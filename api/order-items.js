export default async function handler(req, res) {
  console.log('headers:', req.headers);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Normalize body: parse if string and content-type is JSON
  let body = req.body;
  if (typeof body === 'string' && req.headers['content-type']?.includes('application/json')) {
    try {
      body = JSON.parse(body);
    } catch (e) {
      console.error('Invalid JSON body', e);
      return res.status(400).json({ error: 'Invalid JSON body' });
    }
  }

  console.log('body after parse:', body);

  // Validate orderId
  const orderId = body?.orderId;
  if (!orderId) {
    return res.status(400).json({ error: 'Missing orderId' });
  }

  // Example success response
  return res.status(200).json({ ok: true, orderId });
}
