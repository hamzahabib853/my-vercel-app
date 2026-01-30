import fetch from 'node-fetch';
import aws4 from 'aws4';

export default async function handler(req, res) {
  // Allow only POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

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

  // Step 1: Get LWA access token
  const lwaRes = await fetch('https://api.amazon.com/auth/o2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: process.env.LWA_REFRESH_TOKEN,
      client_id: process.env.LWA_CLIENT_ID,
      client_secret: process.env.LWA_CLIENT_SECRET,
    }),
  });

  const lwaJson = await lwaRes.json();
  const access_token = lwaJson.access_token;

  if (!access_token) {
    return res.status(401).json({ error: 'Failed to get LWA token', details: lwaJson });
  }

  // Step 2: Assume AWS role (EU region)
  const stsRes = await fetch(`https://sts.${process.env.REGION}.amazonaws.com/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      Action: 'AssumeRole',
      RoleArn: process.env.AWS_ROLE_ARN,
      RoleSessionName: 'spapi-session',
      ExternalId: process.env.EXTERNAL_ID, // REQUIRED
      Version: '2011-06-15',
    }),
  });

  const xml = await stsRes.text();

  const accessKeyId = xml.match(/<AccessKeyId>(.+?)<\/AccessKeyId>/)?.[1];
  const secretAccessKey = xml.match(/<SecretAccessKey>(.+?)<\/SecretAccessKey>/)?.[1];
  const sessionToken = xml.match(/<SessionToken>(.+?)<\/SessionToken>/)?.[1];

  if (!accessKeyId || !secretAccessKey || !sessionToken) {
    return res.status(403).json({ error: 'Failed to assume role', details: xml });
  }

  // Step 3: Call SP-API getOrderItems
  const region = process.env.REGION;
  const host = `sellingpartnerapi-${region}.amazonaws.com`;
  const path = `/orders/v0/orders/${orderId}/orderItems`;

  const opts = {
    host,
    path,
    service: 'execute-api',
    region,
    method: 'GET',
    headers: {
      'x-amz-access-token': access_token,
    },
  };

  // Sign SP-API request
  aws4.sign(opts, {
    accessKeyId,
    secretAccessKey,
    sessionToken,
  });

  const spapiRes = await fetch(`https://${host}${path}`, {
    method: 'GET',
    headers: opts.headers,
  });

  const data = await spapiRes.json();

  return res.status(200).json(data);
}
