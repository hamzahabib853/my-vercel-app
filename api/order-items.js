import fetch from 'node-fetch';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import aws4 from 'aws4';

const FETCH_TIMEOUT_MS = 15000;
const MAX_FETCH_RETRIES = 3;
const RETRY_BASE_MS = 300;

function timeoutFetch(url, opts = {}, timeout = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  const merged = { ...opts, signal: controller.signal };
  return fetch(url, merged).finally(() => clearTimeout(id));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetries(url, opts = {}, retries = MAX_FETCH_RETRIES) {
  let attempt = 0;
  while (true) {
    try {
      const resp = await timeoutFetch(url, opts);
      return resp;
    } catch (err) {
      attempt += 1;
      const isLast = attempt > retries;
      const code = err && err.code ? err.code : null;
      console.warn('Fetch attempt failed', { url, attempt, code, message: err?.message });
      if (isLast) throw err;
      // Exponential backoff with jitter
      const backoff = Math.round(RETRY_BASE_MS * Math.pow(2, attempt - 1) * (0.8 + Math.random() * 0.4));
      await sleep(backoff);
    }
  }
}

function jsonResponse(res, status, body) {
  return res.status(status).json(body);
}

export default async function handler(req, res) {
  console.log('FUNCTION START', { time: new Date().toISOString() });
  console.log('ENV CHECK', {
    EXTERNAL_ID: !!process.env.EXTERNAL_ID,
    REGION: !!process.env.REGION,
    AWS_ACCESS_KEY_ID: !!process.env.AWS_ACCESS_KEY_ID
  });

  try {
    if (req.method !== 'POST') {
      return jsonResponse(res, 405, { error: 'Method not allowed' });
    }

    // Normalize body
    let body = req.body;
    if (typeof body === 'string' && req.headers['content-type']?.includes('application/json')) {
      try {
        body = JSON.parse(body);
      } catch (e) {
        return jsonResponse(res, 400, { error: 'Invalid JSON body' });
      }
    }

    const orderId = body?.orderId;
    if (!orderId) return jsonResponse(res, 400, { error: 'Missing orderId' });

    // Required env
    const requiredEnv = [
      'LWA_REFRESH_TOKEN', 'LWA_CLIENT_ID', 'LWA_CLIENT_SECRET',
      'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_ROLE_ARN',
      'EXTERNAL_ID', 'REGION'
    ];
    for (const k of requiredEnv) {
      if (!process.env[k]) return jsonResponse(res, 500, { error: 'Missing environment variable', missing: k });
    }

    // Normalize region once and trim whitespace
    const region = (process.env.REGION || '').trim();
    if (!region) return jsonResponse(res, 500, { error: 'Missing REGION env' });

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

    const lwaJson = await lwaResp.json();
    const access_token = lwaJson?.access_token;
    if (!access_token) return jsonResponse(res, 401, { error: 'LWA token missing', details: lwaJson });

    // 2) Assume role using AWS SDK (signed)
    const stsClient = new STSClient({
      region,
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
      console.error('AssumeRole error', err && err.stack ? err.stack : String(err));
      return jsonResponse(res, 403, { error: 'Failed to assume role', details: err.message || String(err) });
    }

    const creds = assumeResp?.Credentials;
    if (!creds || !creds.AccessKeyId || !creds.SecretAccessKey || !creds.SessionToken) {
      return jsonResponse(res, 403, { error: 'AssumeRole did not return credentials', details: assumeResp });
    }


// Temporary connectivity test - add before calling SP-API
try {
  const testResp = await timeoutFetch('https://example.com', { method: 'GET' }, 5000);
  console.log('CONNECTIVITY TEST ok', { status: testResp.status });
} catch (e) {
  console.error('CONNECTIVITY TEST failed', { code: e?.code, message: e?.message });
  return jsonResponse(res, 502, { error: 'Outbound connectivity test failed', details: e?.message, code: e?.code });
}



    
    // 3) Call SP-API getOrderItems and sign with aws4 using temporary creds
    const host = `sellingpartnerapi-${region}.amazonaws.com`;
    const path = `/orders/v0/orders/${encodeURIComponent(orderId)}/orderItems`;
    const spapiUrl = `https://${host}${path}`;

    console.log('SP-API request', { spapiUrl, host });

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

    const fetchHeaders = opts.headers || {};
    let spapiResp;
    try {
      spapiResp = await fetchWithRetries(spapiUrl, { method: 'GET', headers: fetchHeaders });
    } catch (err) {
      console.error('SP-API fetch failed after retries', err && err.stack ? err.stack : String(err));
      return jsonResponse(res, 502, { error: 'SP-API fetch failed', details: err?.message || String(err) });
    }

    const spapiText = await spapiResp.text();

    if (!spapiResp.ok) {
      let details = spapiText;
      try { details = JSON.parse(spapiText); } catch (e) { /* keep text */ }
      return jsonResponse(res, spapiResp.status, { error: 'SP-API error', details });
    }

    let data;
    try {
      data = JSON.parse(spapiText);
    } catch (e) {
      return jsonResponse(res, 502, { error: 'Invalid JSON from SP-API', raw: spapiText });
    }

    return jsonResponse(res, 200, data);
  } catch (err) {
    console.error('UNCAUGHT ERROR', err && err.stack ? err.stack : String(err));
    const message = err?.message || String(err);
    return jsonResponse(res, 500, { error: 'Internal server error', details: message });
  }
}
