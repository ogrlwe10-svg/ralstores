// ============================================================
// api/capture-order.js
// ✅ SÉCURISÉ : la capture est faite côté serveur avec le secret.
// La clé PAYPAL_CLIENT_SECRET n'est jamais envoyée au navigateur.
// ============================================================

async function getPayPalToken() {
  const clientId     = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
  const base         = process.env.PAYPAL_ENV === 'production'
    ? 'https://api-m.paypal.com'
    : 'https://api-m.sandbox.paypal.com';

  const resp = await fetch(`${base}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
    },
    body: 'grant_type=client_credentials'
  });

  const data = await resp.json();
  if (!data.access_token) throw new Error('Impossible d\'obtenir le token PayPal');
  return { token: data.access_token, base };
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).end('Method Not Allowed');
  }

  try {
    const { orderID } = req.body || {};

    if (!orderID) {
      return res.status(400).json({ error: 'orderID manquant.' });
    }

    const { token, base } = await getPayPalToken();

    const captureResp = await fetch(`${base}/v2/checkout/orders/${orderID}/capture`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });

    const result = await captureResp.json();

    if (result.status === 'COMPLETED') {
      console.log('✅ Paiement confirmé:', orderID, result.payer?.email_address);
      return res.status(200).json({ status: 'COMPLETED', orderID });
    }

    console.warn('⚠️ Statut inattendu:', result.status, orderID);
    return res.status(400).json({ error: `Statut PayPal: ${result.status}` });

  } catch (err) {
    console.error('capture-order error:', err);
    return res.status(500).json({ error: 'Erreur serveur interne.' });
  }
}
