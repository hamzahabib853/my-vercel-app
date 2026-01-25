import crypto from "crypto";
import fetch from "node-fetch";

export default async function handler(req, res) {
  try {
    const orderId = req.query.orderId;
    if (!orderId) {
      return res.status(400).json({ error: "Missing orderId" });
    }

    // Load environment variables
    const {
      LWA_CLIENT_ID,
      LWA_CLIENT_SECRET,
      LWA_REFRESH_TOKEN,
      AWS_ACCESS_KEY,
      AWS_SECRET_KEY,
      AWS_REGION
    } = process.env;

    // Step 1: Get LWA Access Token
    const lwaResponse = await fetch("https://api.amazon.com/auth/o2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: LWA_REFRESH_TOKEN,
        client_id: LWA_CLIENT_ID,
        client_secret: LWA_CLIENT_SECRET
      })
    });

    const lwaData = await lwaResponse.json();
    const accessToken = lwaData.access_token;

    // Step 2: Prepare SP-API request
    const host = "sellingpartnerapi-eu.amazon.com";
    const path = `/orders/v0/orders/${orderId}/orderItems`;
    const url = `https://${host}${path}`;

    const method = "GET";
    const service = "execute-api";
    const algorithm = "AWS4-HMAC-SHA256";
    const now = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
    const date = now.slice(0, 8);

    const canonicalHeaders = `host:${host}\nx-amz-access-token:${accessToken}\n`;
    const signedHeaders = "host;x-amz-access-token";
    const payloadHash = crypto.createHash("sha256").update("").digest("hex");

    const canonicalRequest = [
      method,
      path,
      "",
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join("\n");

    const credentialScope = `${date}/${AWS_REGION}/${service}/aws4_request`;
    const stringToSign = [
      algorithm,
      now,
      credentialScope,
      crypto.createHash("sha256").update(canonicalRequest).digest("hex")
    ].join("\n");

    // Step 3: Create signature
    const kDate = crypto.createHmac("sha256", "AWS4" + AWS_SECRET_KEY).update(date).digest();
    const kRegion = crypto.createHmac("sha256", kDate).update(AWS_REGION).digest();
    const kService = crypto.createHmac("sha256", kRegion).update(service).digest();
    const kSigning = crypto.createHmac("sha256", kService).update("aws4_request").digest();
    const signature = crypto.createHmac("sha256", kSigning).update(stringToSign).digest("hex");

    const authorizationHeader =
      `${algorithm} Credential=${AWS_ACCESS_KEY}/${credentialScope}, ` +
      `SignedHeaders=${signedHeaders}, Signature=${signature}`;

    // Step 4: Call SP-API
    const response = await fetch(url, {
      method,
      headers: {
        "x-amz-access-token": accessToken,
        Authorization: authorizationHeader,
        Host: host
      }
    });

    const data = await response.json();
    return res.status(200).json(data);

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
