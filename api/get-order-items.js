// api/get-order-items.js

import crypto from 'crypto';
import https from 'https';

export default async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Only POST allowed' });
    }

    const { orderId } = req.body;
    if (!orderId) {
      return res.status(400).json({ error: 'orderId is required in body' });
    }

    const {
      LWA_CLIENT_ID,
      LWA_CLIENT_SECRET,
      LWA_REFRESH_TOKEN,
      AWS_ACCESS_KEY_ID,
      AWS_SECRET_ACCESS_KEY,
      AWS_ROLE_ARN,
      REGION,
      MARKETPLACE_ID,
    } = process.env;

    // 1) Get LWA access token
    const lwaToken = await getLwaAccessToken({
      clientId: LWA_CLIENT_ID,
      clientSecret: LWA_CLIENT_SECRET,
      refreshToken: LWA_REFRESH_TOKEN,
    });

    // 2) Assume role to get temporary AWS credentials
    const tempCreds = await assumeRole({
      accessKeyId: AWS_ACCESS_KEY_ID,
      secretAccessKey: AWS_SECRET_ACCESS_KEY,
      roleArn: AWS_ROLE_ARN,
      region: REGION,
    });

    // 3) Call SP-API getOrderItems
    const spResponse = await callSpApiGetOrderItems({
      orderId,
      region: REGION,
      accessToken: lwaToken,
      tempCreds,
    });

    // 4) Extract personalization details (if present)
    const items = spResponse?.payload?.OrderItems || spResponse?.OrderItems || [];
    const simplified = items.map((item) => {
      const customizedInfo =
        item?.ProductInfo?.CustomizedInfo?.CustomizationDetails || [];
      return {
        asin: item.ASIN,
        sellerSku: item.SellerSKU,
        title: item.Title,
        quantityOrdered: item.QuantityOrdered,
        customization: customizedInfo.map((c) => ({
          type: c.Type,
          name: c.Name,
          value: c.Value,
        })),
      };
    });

    return res.status(200).json({
      orderId,
      marketplaceId: MARKETPLACE_ID,
      items: simplified,
      raw: spResponse, // keep for debugging; remove later if you want
    });
  } catch (err) {
    console.error('Error in handler:', err);
    return res.status(500).json({ error: err.message || 'Unknown error' });
  }
}

// ---------- Helpers ----------

async function getLwaAccessToken({ clientId, clientSecret, refreshToken }) {
  const data = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: clientId,
    client_secret: clientSecret,
  }).toString();

  const options = {
    method: 'POST',
    hostname: 'api.amazon.com',
    path: '/auth/o2/token',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(data),
    },
  };

  const body = await httpRequest(options, data);
  const parsed = JSON.parse(body);
  if (!parsed.access_token) {
    throw new Error('Failed to get LWA access token');
  }
  return parsed.access_token;
}

async function assumeRole({ accessKeyId, secretAccessKey, roleArn, region }) {
  const host = 'sts.amazonaws.com';
  const now = new Date();
  const amzDate = toAmzDate(now);
  const dateStamp = amzDate.slice(0, 8);

  const params = new URLSearchParams({
    Action: 'AssumeRole',
    RoleArn: roleArn,
    RoleSessionName: 'spapi-session',
    Version: '2011-06-15',
  }).toString();

  const method = 'POST';
  const service = 'sts';
  const canonicalUri = '/';
  const canonicalQuerystring = '';
  const canonicalHeaders =
    `content-type:application/x-www-form-urlencoded; charset=utf-8\n` +
    `host:${host}\n` +
    `x-amz-date:${amzDate}\n`;
  const signedHeaders = 'content-type;host;x-amz-date';
  const payloadHash = sha256(params);
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    '',
    signedHeaders,
    payloadHash,
  ].join('\n');

  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    sha256(canonicalRequest),
  ].join('\n');

  const signingKey = getSignatureKey(secretAccessKey, dateStamp, region, service);
  const signature = hmac(signingKey, stringToSign, 'hex');

  const authorizationHeader =
    `${algorithm} Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const options = {
    method,
    hostname: host,
    path: '/',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
      'X-Amz-Date': amzDate,
      Authorization: authorizationHeader,
    },
  };

  const body = await httpRequest(options, params);
  const parsed = parseXml(body);

  const creds =
    parsed?.AssumeRoleResponse?.AssumeRoleResult?.Credentials ||
    parsed?.AssumeRoleResult?.Credentials;

  if (!creds) {
    throw new Error('Failed to assume role');
  }

  return {
    accessKeyId: creds.AccessKeyId,
    secretAccessKey: creds.SecretAccessKey,
    sessionToken: creds.SessionToken,
  };
}

async function callSpApiGetOrderItems({ orderId, region, accessToken, tempCreds }) {
  const host = `sellingpartnerapi-eu.amazon.com`;
  const path = `/orders/v0/orders/${encodeURIComponent(orderId)}/orderItems`;
  const method = 'GET';
  const service = 'execute-api';
  const now = new Date();
  const amzDate = toAmzDate(now);
  const dateStamp = amzDate.slice(0, 8);

  const canonicalQuerystring = '';
  const canonicalHeaders =
    `host:${host}\n` +
    `x-amz-date:${amzDate}\n` +
    `x-amz-security-token:${tempCreds.sessionToken}\n` +
    `x-amz-access-token:${accessToken}\n`;
  const signedHeaders = 'host;x-amz-access-token;x-amz-date;x-amz-security-token';
  const payloadHash = sha256('');
  const canonicalRequest = [
    method,
    path,
    canonicalQuerystring,
    canonicalHeaders,
    '',
    signedHeaders,
    payloadHash,
  ].join('\n');

  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    sha256(canonicalRequest),
  ].join('\n');

  const signingKey = getSignatureKey(
    tempCreds.secretAccessKey,
    dateStamp,
    region,
    service
  );
  const signature = hmac(signingKey, stringToSign, 'hex');

  const authorizationHeader =
    `${algorithm} Credential=${tempCreds.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const options = {
    method,
    hostname: host,
    path,
    headers: {
      'x-amz-date': amzDate,
      'x-amz-security-token': tempCreds.sessionToken,
      'x-amz-access-token': accessToken,
      Authorization: authorizationHeader,
    },
  };

  const body = await httpRequest(options);
  return JSON.parse(body);
}

// ---------- Low-level helpers ----------

function httpRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(data);
        } else {
          reject(
            new Error(
              `HTTP ${res.statusCode}: ${data || 'No body'}`
            )
          );
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function sha256(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

function hmac(key, str, encoding) {
  return crypto.createHmac('sha256', key).update(str, 'utf8').digest(encoding);
}

function toAmzDate(date) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

// Very minimal XML parser for STS response (not robust, but enough here)
function parseXml(xml) {
  const get = (tag, src) => {
    const m = src.match(new RegExp(`<${tag}>([^<]+)</${tag}>`));
    return m ? m[1] : null;
  };

  const creds = {
    AccessKeyId: get('AccessKeyId', xml),
    SecretAccessKey: get('SecretAccessKey', xml),
    SessionToken: get('SessionToken', xml),
  };

  if (!creds.AccessKeyId) return {};

  return {
    AssumeRoleResponse: {
      AssumeRoleResult: {
        Credentials: creds,
      },
    },
  };
}
