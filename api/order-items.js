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
    if (!orderId) {
      return jsonResponse(res, 400, { error: 'Missing orderId' });
    }

    // Required environment variables
    const requiredEnv = [
      'LWA_REFRESH_TOKEN',
      'LWA_CLIENT_ID',
      'LWA_CLIENT_SECRET',
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'AWS_ROLE_ARN',
      'EXTERNAL_ID',
      'REGION'
    ];
    for (const key of requiredEnv) {
      if (!process.env[key]) {
        return jsonResponse(res, 500, { error: 'Missing environment variable', missing: key });
      }
    }

    // 1) Get LWA access token
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
    const access_token = lwaJson.access_token;
    if (!access_token) {
      return jsonResponse(res, 401, { error: 'LWA token missing in response', details: lwaJson });
    }

    // 2) Assume role using AWS SDK v3 (signed)
    const stsClient = new STSClient({
      region: process.env.REGION,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    });

    const assumeCmd = new AssumeRoleCommand({
      RoleArn: process.env.AWS_ROLE_ARN,
      RoleSessionName: 'spapi-session',
      ExternalId: process.env.EXTERNAL_ID,
      DurationSeconds: 3600
    });

    let assumeResp;
    try {
      assumeResp = await stsClient.send(assumeCmd);
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

    // Sign request with temporary credentials
    aws4.sign(opts, {
      accessKeyId: creds.AccessKeyId,
      secretAccessKey: creds.SecretAccessKey,
      sessionToken: creds.SessionToken
    });

    const spapiUrl = `https://${host}${path}`;
    const spapiResp = await timeoutFetch(spapiUrl, {
      method: 'GET',
      headers: opts.headers
    }, FETCH_TIMEOUT_MS);

    const spapiText = await spapiResp.text();
    if (!spapiResp.ok) {
      // Try to parse JSON if possible, otherwise return text
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
    // Catch-all
    const message = err?.message || String(err);
    return jsonResponse(res, 500, { error: 'Internal server error', details: message });
  }
}
