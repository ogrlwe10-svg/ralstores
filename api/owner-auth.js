/**
 * api/owner-auth.js — Vercel Serverless Function
 *
 * POST /api/owner-auth  → vérifie email + password, retourne JWT
 * DELETE /api/owner-auth → déconnexion (clear cookie)
 *
 * Les credentials NE SONT PAS dans le code — ils viennent des
 * variables d'environnement Vercel (Settings > Environment Variables).
 * Personne ne peut les voir, même en clonant le repo GitHub.
 */

const crypto = require('crypto');

// ─── Helpers JWT maison (pas de dépendance externe) ─────────────────────────

function b64url(str) {
    return Buffer.from(str).toString('base64url');
}

function signJWT(payload, secret) {
    const header  = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const body    = b64url(JSON.stringify(payload));
    const data    = header + '.' + body;
    const sig     = crypto.createHmac('sha256', secret).update(data).digest('base64url');
    return data + '.' + sig;
}

function verifyJWT(token, secret) {
    try {
        const [header, body, sig] = token.split('.');
        if (!header || !body || !sig) return null;
        const expected = crypto.createHmac('sha256', secret).update(header + '.' + body).digest('base64url');
        // Comparaison en temps constant — anti timing-attack
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
        const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
        return payload;
    } catch {
        return null;
    }
}

// ─── Rate limiting en mémoire (simple, suffit pour usage solo) ───────────────

const attempts = new Map(); // IP → { count, firstAt }
const MAX_ATTEMPTS    = 5;
const WINDOW_MS       = 15 * 60 * 1000; // 15 min
const LOCKOUT_MS      = 15 * 60 * 1000;

function checkRateLimit(ip) {
    const now = Date.now();
    const entry = attempts.get(ip) || { count: 0, firstAt: now, lockedUntil: 0 };

    if (entry.lockedUntil && now < entry.lockedUntil) {
        const remainSec = Math.ceil((entry.lockedUntil - now) / 1000);
        return { blocked: true, remainSec };
    }

    // Reset window si expiré
    if (now - entry.firstAt > WINDOW_MS) {
        attempts.set(ip, { count: 1, firstAt: now, lockedUntil: 0 });
        return { blocked: false };
    }

    entry.count++;
    if (entry.count >= MAX_ATTEMPTS) {
        entry.lockedUntil = now + LOCKOUT_MS;
        attempts.set(ip, entry);
        return { blocked: true, remainSec: Math.ceil(LOCKOUT_MS / 1000) };
    }

    attempts.set(ip, entry);
    return { blocked: false, remaining: MAX_ATTEMPTS - entry.count };
}

function resetRateLimit(ip) {
    attempts.delete(ip);
}

// ─── Handler principal ───────────────────────────────────────────────────────

module.exports = async function handler(req, res) {
    // CORS — autorise uniquement ton domaine
    const origin = req.headers.origin || '';
    const allowed = [
        'https://ralstores.vercel.app',
        'http://localhost:3000',
        'http://127.0.0.1:5500',   // Live Server VS Code
        'null',                     // file:// local
    ];
    if (allowed.includes(origin) || origin === '') {
        res.setHeader('Access-Control-Allow-Origin', origin || '*');
    }
    res.setHeader('Access-Control-Allow-Methods', 'POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') return res.status(200).end();

    // ── Récupérer variables d'environnement (jamais dans le code) ────────────
    const OWNER_EMAILS    = (process.env.OWNER_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
    const OWNER_PASSWORDS = (process.env.OWNER_PASSWORDS || '').split(',').map(p => p.trim()).filter(Boolean);
    const JWT_SECRET      = process.env.JWT_SECRET;

    if (!JWT_SECRET || OWNER_EMAILS.length === 0) {
        console.error('[owner-auth] Variables env manquantes');
        return res.status(500).json({ error: 'Configuration serveur incorrecte' });
    }

    // ── GET IP ────────────────────────────────────────────────────────────────
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.headers['x-real-ip']
        || req.socket?.remoteAddress
        || 'unknown';

    // ── POST — Connexion ──────────────────────────────────────────────────────
    if (req.method === 'POST') {
        // Anti timing-attack : délai minimum constant
        const start = Date.now();
        const minDelay = 400;

        const rl = checkRateLimit(ip);
        if (rl.blocked) {
            await delay(minDelay - (Date.now() - start));
            return res.status(429).json({
                error: `Trop de tentatives. Réessayez dans ${Math.ceil(rl.remainSec / 60)} min.`
            });
        }

        const { email, password } = req.body || {};

        if (!email || !password) {
            await delay(minDelay - (Date.now() - start));
            return res.status(400).json({ error: 'Email et mot de passe requis' });
        }

        const emailNorm = String(email).trim().toLowerCase();

        // Trouver le credential correspondant
        const idx = OWNER_EMAILS.indexOf(emailNorm);
        const validEmail = idx !== -1;
        const validPassword = validEmail && OWNER_PASSWORDS[idx] === String(password).trim();

        // Toujours attendre le délai minimum (même si credentials invalides)
        await delay(Math.max(0, minDelay - (Date.now() - start)));

        if (!validEmail || !validPassword) {
            console.warn(`[owner-auth] Échec login: ${emailNorm} depuis ${ip} — tentatives: ${rl.remaining}`);
            return res.status(401).json({
                error: 'Email ou mot de passe incorrect',
                remaining: rl.remaining || 0,
            });
        }

        // ✅ Succès — réinitialiser le rate limit
        resetRateLimit(ip);

        const now = Math.floor(Date.now() / 1000);
        const token = signJWT({
            email: emailNorm,
            role:  'OWNER',
            iat:   now,
            exp:   now + 3600, // 1h
        }, JWT_SECRET);

        console.info(`[owner-auth] Connexion réussie: ${emailNorm} depuis ${ip}`);

        // Cookie httpOnly — inaccessible depuis JS (protection XSS)
        res.setHeader('Set-Cookie', [
            `ral_owner=${token}; HttpOnly; Secure; SameSite=Strict; Path=/api/; Max-Age=3600`,
        ]);

        return res.status(200).json({
            ok:    true,
            email: emailNorm,
            role:  'OWNER',
            exp:   (now + 3600) * 1000,
        });
    }

    // ── DELETE — Déconnexion ──────────────────────────────────────────────────
    if (req.method === 'DELETE') {
        res.setHeader('Set-Cookie', 'ral_owner=; HttpOnly; Secure; SameSite=Strict; Path=/api/; Max-Age=0');
        return res.status(200).json({ ok: true });
    }

    // ── Vérification token (GET) ──────────────────────────────────────────────
    if (req.method === 'GET') {
        const cookie = req.headers.cookie || '';
        const match  = cookie.match(/ral_owner=([^;]+)/);
        if (!match) return res.status(401).json({ error: 'Non authentifié' });

        const payload = verifyJWT(match[1], JWT_SECRET);
        if (!payload) return res.status(401).json({ error: 'Token invalide ou expiré' });

        return res.status(200).json({ ok: true, email: payload.email, role: payload.role });
    }

    return res.status(405).json({ error: 'Méthode non autorisée' });
};

function delay(ms) {
    return new Promise(r => setTimeout(r, Math.max(0, ms)));
}
