import fetch from 'node-fetch';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import aws4 from 'aws4';

const FETCH_TIMEOUT_MS = 15000;
function timeoutFetch(url, opts = {}, timeout = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  const merged = { ...opts, signal: controller.signal };
  return fetch(url, merged).finally(() => clearTimeout(id));
}
function jsonResponse(res, status, body) {
  return res.status(status).json(body);
}

export default async function handler(req, res) {
  console.log('EXTERNAL_ID present:', !!process.env.EXTERNAL_ID);
  try {
    if (req.method !== 'POST') return jsonResponse(res, 405, { error: 'Method not allowed' });

    // Normalize body
    let body = req.body;
    if (typeof body === 'string' && req.headers['content-type']?.includes('application/json')) {
      try { body = JSON.parse(body); } catch (e) { return jsonResponse(res, 400, { error: 'Invalid JSON body' }); }
    }

    const orderId = body?.orderId;
    if (!orderId) return jsonResponse(res, 400, { error: 'Missing orderId' });

    // Required env
    const requiredEnv = [
      'LWA_REFRESH_TOKEN','LWA_CLIENT_ID','LWA_CLIENT_SECRET',
      'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_ROLE_ARN',
      'EXTERNAL_ID','REGION'
    ];
    for (const k of requiredEnv) if (!process.env[k]) return jsonResponse(res, 500, { error: 'Missing environment variable', missing: k });

    // 1) Get LWA token
    const lwaUrl = 'https://api.amazon.com/auth/o2/token';
    const lwaParams = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: process.env.LWA_REFRESH_TOKEN,
      client_id: process.env.LWA_CLIENT_ID,
      client_secret: process.env.LWA_CLIENT_SECRET
    });

    const lwaResp = await timeoutFetch(lwaUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: lwaParams.toString()
    });

    if (!lwaResp.ok) {
      const text = await lwaResp.text();
      return jsonResponse(res, 401, { error: 'Failed to get LWA token', status: lwaResp.status, details: text });
    }
    const { access_token } = await lwaResp.json();
    if (!access_token) return jsonResponse(res, 401, { error: 'LWA token missing', details: await lwaResp.text() });

    // 2) Assume role using AWS SDK (signed)
    const stsClient = new STSClient({
      region: process.env.REGION,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    });

    let assumeResp;
    try {
      assumeResp = await stsClient.send(new AssumeRoleCommand({
        RoleArn: process.env.AWS_ROLE_ARN,
        RoleSessionName: 'spapi-session',
        ExternalId: process.env.EXTERNAL_ID,
        DurationSeconds: 3600
      }));
    } catch (err) {
      return jsonResponse(res, 403, { error: 'Failed to assume role', details: err.message || String(err) });
    }

    const creds = assumeResp?.Credentials;
    if (!creds || !creds.AccessKeyId || !creds.SecretAccessKey || !creds.SessionToken) {
      return jsonResponse(res, 403, { error: 'AssumeRole did not return credentials', details: assumeResp });
    }

    // 3) Call SP-API getOrderItems and sign with aws4 using temporary creds
    const region = process.env.REGION;
    const host = `sellingpartnerapi-${region}.amazonaws.com`;
    const path = `/orders/v0/orders/${encodeURIComponent(orderId)}/orderItems`;

    const opts = {
      host,
      path,
      service: 'execute-api',
      region,
      method: 'GET',
      headers: {
        'x-amz-access-token': access_token,
        'Accept': 'application/json'
      }
    };

    aws4.sign(opts, {
      accessKeyId: creds.AccessKeyId,
      secretAccessKey: creds.SecretAccessKey,
      sessionToken: creds.SessionToken
    });
    // normalize region and trim whitespace
const region = (process.env.REGION || '').trim();
if (!region) return jsonResponse(res, 500, { error: 'Missing REGION env' });

const host = `sellingpartnerapi-${region}.amazonaws.com`;
const spapiUrl = `https://${host}${path}`;

console.log('DEBUG SP-API attempt', { spapiUrl, host });

// Optional DNS lookup for clearer error messages (requires Node 18+ runtime)
import dns from 'dns/promises';
try {
  const addr = await dns.lookup(host);
  console.log('DEBUG DNS lookup success', addr);
} catch (dnsErr) {
  console.error('DEBUG DNS lookup failed', dnsErr.message);
  return jsonResponse(res, 502, { error: 'DNS lookup failed', details: dnsErr.message, host });
}
    const spapiUrl = `https://${host}${path}`;
    const spapiResp = await timeoutFetch(spapiUrl, { method: 'GET', headers: opts.headers }, FETCH_TIMEOUT_MS);
    const spapiText = await spapiResp.text();

    if (!spapiResp.ok) {
      let details = spapiText;
      try { details = JSON.parse(spapiText); } catch (e) { /* keep text */ }
      return jsonResponse(res, spapiResp.status, { error: 'SP-API error', details });
    }

    let data;
    try { data = JSON.parse(spapiText); } catch (e) { return jsonResponse(res, 502, { error: 'Invalid JSON from SP-API', raw: spapiText }); }

    return jsonResponse(res, 200, data);
  } catch (err) {
    const message = err?.message || String(err);
    return jsonResponse(res, 500, { error: 'Internal server error', details: message });
  }
}
