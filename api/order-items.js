import fetch from 'node-fetch';
import aws4 from 'aws4';

export default async function handler(req, res) {
  // Fix: parse body if Vercel passed it as a string
  if (
    req.headers['content-type']?.includes('application/json') &&
    typeof req.body === 'string'
  ) {
    try {
      req.body = JSON.parse(req.body);
    } catch (e) {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }
  }

  const { orderId } = req.body;

  if (!orderId) {
    return res.status(400).json({ error: 'Missing orderId' });
  }

  // ... rest of your code stays the same
}
