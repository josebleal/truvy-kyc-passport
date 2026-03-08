const assert = require("assert");
const { app, publicKey } = require("./server");
const jwt = require("jsonwebtoken");
const http = require("http");

let server;
let BASE_URL;

// ─── Test Runner Setup ─────────────────────────────────────────────────────────
async function setup() {
  server = http.createServer(app);
  await new Promise((res) => server.listen(0, res));
  const port = server.address().port;
  BASE_URL = `http://localhost:${port}`;
}

async function teardown() {
  await new Promise((res) => server.close(res));
}

// ─── HTTP Helper ───────────────────────────────────────────────────────────────
async function request(method, path, body) {
  const url = `${BASE_URL}${path}`;
  const options = {
    method,
    headers: { "Content-Type": "application/json" },
  };

  return new Promise((resolve, reject) => {
    const req = require("http").request(url, options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        resolve({ status: res.statusCode, body: JSON.parse(data) });
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ─── Tests ─────────────────────────────────────────────────────────────────────
const tests = [];
let passed = 0;
let failed = 0;

function test(name, fn) {
  tests.push({ name, fn });
}

// Test 1 — Health check
test("API is running and healthy", async () => {
  const res = await request("GET", "/health");
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.status, "ok");
});

// Test 2 — Credential issuance returns a valid JWT
test("POST /issue returns a valid signed JWT credential", async () => {
  const res = await request("POST", "/issue", {
    name: "Maria Silva",
    country: "Brazil",
    documentType: "passport",
  });

  assert.strictEqual(res.status, 200);
  assert.ok(res.body.token, "token should be present");
  assert.ok(res.body.sessionId, "sessionId should be present");
  assert.ok(res.body.qrBase64, "QR code should be present");
  assert.ok(res.body.token.startsWith("eyJ"), "token should be a JWT");

  // Verify the JWT is actually valid
  const decoded = jwt.verify(res.body.token, publicKey, {
    algorithms: ["RS256"],
  });
  assert.strictEqual(decoded.name, "Maria Silva");
  assert.strictEqual(decoded.sanctionsCheck, "PASSED");
});

// Test 3 — Valid JWT is accepted by /verify
test("POST /verify accepts a valid credential and returns only safe claims", async () => {
  // Issue first
  const issueRes = await request("POST", "/issue", {
    name: "Carlos Mendes",
    country: "Brazil",
  });
  const { token, sessionId } = issueRes.body;

  // Now verify
  const verifyRes = await request("POST", "/verify", { token, sessionId });

  assert.strictEqual(verifyRes.status, 200);
  assert.strictEqual(verifyRes.body.valid, true);

  // Confirm sensitive fields are NOT in the response
  const claims = verifyRes.body.claims;
  assert.ok(!claims.passportNumber, "passportNumber must NOT be transmitted");
  assert.ok(!claims.dateOfBirth, "dateOfBirth must NOT be transmitted");
  assert.ok(!claims.homeAddress, "homeAddress must NOT be transmitted");

  // Confirm withheld list is present
  assert.ok(
    verifyRes.body.withheld.includes("passportNumber"),
    "withheld list should include passportNumber"
  );
});

// Test 4 — ⭐ THE KEY PROOF: Tampered JWT is REJECTED
test("POST /verify rejects a tampered credential (cryptography is real)", async () => {
  // Issue a real credential
  const issueRes = await request("POST", "/issue", {
    name: "Hacker",
    country: "Nowhere",
  });
  const realToken = issueRes.body.token;

  // Tamper: change a character in the middle of the token
  const parts = realToken.split(".");
  const tamperedPayload = parts[1].slice(0, -3) + "XYZ"; // corrupt the payload
  const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

  const verifyRes = await request("POST", "/verify", {
    token: tamperedToken,
  });

  assert.strictEqual(verifyRes.status, 401);
  assert.strictEqual(verifyRes.body.valid, false);
  assert.strictEqual(verifyRes.body.error, "invalid signature");
});

// Test 5 — Session status polling works
test("GET /status returns pending then verified after /verify", async () => {
  // Issue credential
  const issueRes = await request("POST", "/issue", {
    name: "Ana Costa",
    country: "Brazil",
  });
  const { token, sessionId } = issueRes.body;

  // Should be pending before verify
  const pendingRes = await request("GET", `/status/${sessionId}`);
  assert.strictEqual(pendingRes.body.status, "pending");
  assert.strictEqual(pendingRes.body.claims, null);

  // Verify the credential
  await request("POST", "/verify", { token, sessionId });

  // Should be verified now
  const verifiedRes = await request("GET", `/status/${sessionId}`);
  assert.strictEqual(verifiedRes.body.status, "verified");
  assert.ok(verifiedRes.body.claims, "claims should be present after verify");
});

// Test 6 — AI score returns structured JSON (demo mode, no image)
test("POST /ai-score returns structured risk JSON", async () => {
  const res = await request("POST", "/ai-score", {});

  assert.strictEqual(res.status, 200);
  assert.ok(typeof res.body.riskScore === "number", "riskScore should be a number");
  assert.ok(["LOW", "MEDIUM", "HIGH"].includes(res.body.riskLevel), "riskLevel should be valid");
  assert.ok(["APPROVE", "REVIEW", "REJECT"].includes(res.body.recommendation), "recommendation should be valid");
});

// ─── Run All Tests ─────────────────────────────────────────────────────────────
async function run() {
  await setup();
  console.log("\n🧪  KYC Passport — Technical Validation Tests\n");

  for (const { name, fn } of tests) {
    try {
      await fn();
      console.log(`  ✓  ${name}`);
      passed++;
    } catch (err) {
      console.log(`  ✗  ${name}`);
      console.log(`     → ${err.message}`);
      failed++;
    }
  }

  await teardown();

  console.log(`\n  ${passed + failed} tests: ${passed} passing, ${failed} failing\n`);

  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error("Test runner error:", err);
  process.exit(1);
});
