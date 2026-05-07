// ============================================================
// api/paypal-client-id.js
// Renvoie le Client ID PayPal depuis les variables d'environnement.
// Ne jamais mettre la clé directement dans index.html !
// ============================================================

export default async function handler(req, res) {
  const clientId = process.env.PAYPAL_CLIENT_ID;

  if (!clientId) {
    return res.status(500).json({ error: 'PAYPAL_CLIENT_ID non configuré dans les variables Vercel.' });
  }

  return res.status(200).json({ clientId });
}
