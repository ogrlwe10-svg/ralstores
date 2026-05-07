// ============================================================
// api/create-order.js
// ✅ SÉCURISÉ : les prix sont lus depuis le serveur, jamais du client.
// Un attaquant qui modifie PRODUCTS[x].price = 0.01 dans DevTools
// ne pourra PAS contourner cette validation.
// ============================================================

// ⚠️ COPIE EXACTE de tes produits côté serveur (source de vérité)
const PRODUCTS = [
  { id: 1,  name: 'Disney+',                   price: 3    },
  { id: 2,  name: 'Paramount+',                price: 2    },
  { id: 3,  name: 'Netflix Lifetime',          price: 3    },
  { id: 4,  name: 'Prime Video Lifetime',      price: 2    },
  { id: 5,  name: 'HBO Max Lifetime',          price: 2    },
  { id: 6,  name: 'UFC Lifetime',              price: 2    },
  { id: 7,  name: 'DAZN Lifetime',             price: 2    },
  { id: 8,  name: 'AMC+ Lifetime',             price: 2    },
  { id: 9,  name: 'OnePlay Lifetime',          price: 2    },
  { id: 10, name: 'Spotify Lifetime',          price: 6    },
  { id: 11, name: 'Spotify Key Lifetime',      price: 6    },
  { id: 12, name: 'Crunchyroll MEGA FAN',      price: 5    },
  { id: 13, name: 'Duolingo Lifetime',         price: 4    },
  { id: 14, name: 'NBA Lifetime',              price: 4    },
  { id: 15, name: 'TikTok 1K Followers',       price: 6    },
  { id: 16, name: 'TikTok 10K Followers',      price: 25   },
  { id: 17, name: 'TikTok 20K Followers',      price: 35   },
  { id: 18, name: 'Instagram 1K Followers',    price: 5    },
  { id: 19, name: 'Instagram 5K Followers',    price: 10   },
  { id: 20, name: 'YouTube Lifetime',          price: 3    },
  { id: 21, name: 'Twitch 100 Followers',      price: 4    },
  { id: 22, name: 'Twitch 500 Followers',      price: 10   },
  { id: 23, name: 'Twitch 2000 Followers',     price: 20   },
  { id: 24, name: 'Twitch 5000 Followers',     price: 30   },
  { id: 25, name: 'Twitch 10000 Followers',    price: 50   },
  { id: 26, name: 'ChatGPT Accounts',          price: 5    },
  { id: 27, name: 'Gemini Pro Accounts',       price: 5    },
  { id: 28, name: 'Movistar+ Lifetime',        price: 5    },
  { id: 29, name: 'CapCut Pro Lifetime',       price: 4    },
  { id: 30, name: 'Filmora Lifetime',          price: 4    },
  { id: 31, name: 'NordVPN Lifetime',          price: 5    },
  { id: 32, name: 'HotSpot Shield VPN 1 Year', price: 4    },
  { id: 33, name: 'TunnelBear',                price: 4    },
  { id: 34, name: 'IPVanish 1 Year',           price: 4    },
  { id: 35, name: 'PureVPN',                   price: 4    },
  { id: 36, name: 'Mullvad Lifetime',          price: 5    },
];

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
    const { items, email } = req.body || {};

    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Panier vide ou invalide.' });
    }

    // ✅ Calcul du total côté serveur à partir des vrais prix
    let total = 0;
    const itemDetails = [];

    for (const cartItem of items) {
      const product = PRODUCTS.find(p => p.id === cartItem.id);
      if (!product) {
        return res.status(400).json({ error: `Produit #${cartItem.id} inconnu.` });
      }
      const qty = Math.max(1, parseInt(cartItem.quantity) || 1);
      total += product.price * qty;
      itemDetails.push(`${product.name} x${qty}`);
    }

    total = Math.round(total * 100) / 100;

    const { token, base } = await getPayPalToken();

    const orderResp = await fetch(`${base}/v2/checkout/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [{
          description: `Commande RΔL - ${itemDetails.join(', ')}`,
          custom_id: email || '',
          amount: {
            currency_code: 'EUR',
            value: total.toFixed(2)
          }
        }]
      })
    });

    const order = await orderResp.json();

    if (!order.id) {
      console.error('PayPal order error:', order);
      return res.status(500).json({ error: 'Erreur création commande PayPal.' });
    }

    return res.status(200).json({ orderID: order.id, total: total.toFixed(2) });

  } catch (err) {
    console.error('create-order error:', err);
    return res.status(500).json({ error: 'Erreur serveur interne.' });
  }
}
