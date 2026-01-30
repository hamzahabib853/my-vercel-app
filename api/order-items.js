import aws4 from 'aws4';

// ... earlier code and LWA token retrieval

// Prepare STS request
const stsParams = new URLSearchParams({
  Action: 'AssumeRole',
  RoleArn: process.env.AWS_ROLE_ARN,
  RoleSessionName: 'spapi-session',
  ExternalId: process.env.EXTERNAL_ID,
  Version: '2011-06-15'
}).toString();

const stsOpts = {
  host: 'sts.eu-west-1.amazonaws.com',
  path: '/',
  service: 'sts',
  region: 'eu-west-1',
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: stsParams
};

// Sign using long-term credentials in env
aws4.sign(stsOpts, {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  sessionToken: process.env.AWS_SESSION_TOKEN // optional
});

const stsRes = await fetch(`https://sts.eu-west-1.amazonaws.com/`, {
  method: 'POST',
  headers: stsOpts.headers,
  body: stsOpts.body
});
const xml = await stsRes.text();
// parse xml as before...
