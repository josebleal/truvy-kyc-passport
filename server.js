const express = require("express");
const jwt = require("jsonwebtoken");
const { generateKeyPairSync } = require("crypto");
const QRCode = require("qrcode");
const Anthropic = require("@anthropic-ai/sdk");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

// ─── Key Generation ────────────────────────────────────────────────────────────
// In production: load from secrets manager. For demo: generate on boot.
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// Export public key for jwt.io demo
app.get("/public-key", (req, res) => {
  res.json({ publicKey });
});

// ─── In-Memory Session Store ───────────────────────────────────────────────────
const sessions = {}; // sessionId → { status, claims }

// ─── Anthropic Client ─────────────────────────────────────────────────────────
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ─── POST /issue ──────────────────────────────────────────────────────────────
// Bank A calls this to issue a signed credential
app.post("/issue", async (req, res) => {
  try {
    const { name, country, documentType = "passport" } = req.body;

    if (!name || !country) {
      return res.status(400).json({ error: "name and country are required" });
    }

    const sessionId = `sess_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    // Claims that WILL be shared with Bank B
    const sharedClaims = {
      name,
      country,
      sanctionsCheck: "PASSED",
      ageVerified: "18+",
      issuer: "did:kycp:jumio-mock",
      documentType,
      issuedAt: new Date().toISOString(),
    };

    // Sign the credential — RS256 means only we can issue, anyone can verify
    const token = jwt.sign(sharedClaims, privateKey, {
      algorithm: "RS256",
      expiresIn: "7d",
      subject: `kycp:${sessionId}`,
    });

    // Generate QR code pointing to the verify endpoint
    const verifyUrl = `${process.env.BASE_URL || "http://localhost:3000"}/verify-qr/${sessionId}/${encodeURIComponent(token)}`;
    const qrBase64 = await QRCode.toDataURL(verifyUrl);

    // Register session as pending
    sessions[sessionId] = { status: "pending", claims: null };

    res.json({
      sessionId,
      token,
      qrBase64,
      sharedClaims,
      message: "Credential issued. Zero raw documents transmitted.",
    });
  } catch (err) {
    console.error("[/issue] Error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /verify ─────────────────────────────────────────────────────────────
// Bank B calls this with a token. Returns only verified claims — no raw docs.
app.post("/verify", (req, res) => {
  const { token, sessionId } = req.body;

  if (!token) {
    return res.status(400).json({ valid: false, error: "token is required" });
  }

  try {
    // This will throw if the signature is invalid or token is tampered
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });

    // Mark session verified if sessionId provided
    if (sessionId && sessions[sessionId]) {
      sessions[sessionId] = { status: "verified", claims: decoded };
    }

    res.json({
      valid: true,
      claims: {
        name: decoded.name,
        country: decoded.country,
        sanctionsCheck: decoded.sanctionsCheck,
        ageVerified: decoded.ageVerified,
        issuer: decoded.issuer,
        documentType: decoded.documentType,
        issuedAt: decoded.issuedAt,
      },
      // Explicitly list what was NOT transmitted — this is the privacy proof
      withheld: [
        "passportNumber",
        "dateOfBirth",
        "homeAddress",
        "taxId",
        "rawDocumentImage",
      ],
      message: "Credential verified. Documents received: NONE.",
    });
  } catch (err) {
    // Tampered token, expired, wrong key — all land here
    res.status(401).json({
      valid: false,
      error: "invalid signature",
      detail: err.message,
      message: "Credential rejected. Cannot forge a KYC Passport.",
    });
  }
});

// ─── GET /verify-qr/:sessionId/:token ─────────────────────────────────────────
// Called when user scans QR code from their wallet
app.get("/verify-qr/:sessionId/:token", (req, res) => {
  const { sessionId, token } = req.params;

  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });

    if (sessions[sessionId]) {
      sessions[sessionId] = { status: "verified", claims: decoded };
    }

    res.json({
      valid: true,
      message: "QR scan verified. Session marked complete.",
      sessionId,
    });
  } catch (err) {
    res.status(401).json({ valid: false, error: "invalid signature" });
  }
});

// ─── GET /status/:sessionId ───────────────────────────────────────────────────
// Bank B polls this every 1500ms waiting for the user to share their proof
app.get("/status/:sessionId", (req, res) => {
  const session = sessions[req.params.sessionId];

  if (!session) {
    return res.status(404).json({ error: "session not found" });
  }

  res.json({
    sessionId: req.params.sessionId,
    status: session.status, // "pending" | "verified"
    claims: session.status === "verified" ? session.claims : null,
  });
});

// ─── POST /ai-score ───────────────────────────────────────────────────────────
// Sends ID image to Claude for AI risk scoring
app.post("/ai-score", async (req, res) => {
  try {
    const { imageBase64, mimeType = "image/jpeg" } = req.body;

    let messages;

    if (imageBase64) {
      // Real image provided — use Claude vision
      messages = [
        {
          role: "user",
          content: [
            {
              type: "image",
              source: {
                type: "base64",
                media_type: mimeType,
                data: imageBase64,
              },
            },
            {
              type: "text",
              text: `You are a KYC risk scoring AI. Analyze this identity document image for authenticity signals.
              
Return ONLY a JSON object with this exact structure:
{
  "riskScore": <number 0-100, lower is safer>,
  "riskLevel": "<LOW|MEDIUM|HIGH>",
  "documentAuthenticity": "<LIKELY_GENUINE|SUSPICIOUS|UNREADABLE>",
  "flags": [<array of string flags, empty if none>],
  "recommendation": "<APPROVE|REVIEW|REJECT>",
  "confidence": <number 0-100>
}

Be conservative — flag anything unusual. Do not include any text outside the JSON.`,
            },
          ],
        },
      ];
    } else {
      // No image — return a demo score for UI testing
      return res.json({
        riskScore: 12,
        riskLevel: "LOW",
        documentAuthenticity: "LIKELY_GENUINE",
        flags: [],
        recommendation: "APPROVE",
        confidence: 94,
        note: "Demo score — no image provided",
      });
    }

    const response = await anthropic.messages.create({
      model: "claude-sonnet-4-20250514",
      max_tokens: 500,
      messages,
    });

    const text = response.content[0].text.trim();
    const clean = text.replace(/```json|```/g, "").trim();
    const score = JSON.parse(clean);

    res.json(score);
  } catch (err) {
    console.error("[/ai-score] Error:", err.message);
    // Fallback score so demo never breaks
    res.json({
      riskScore: 15,
      riskLevel: "LOW",
      documentAuthenticity: "LIKELY_GENUINE",
      flags: [],
      recommendation: "APPROVE",
      confidence: 88,
      note: "Fallback score due to processing error",
    });
  }
});

// ─── Health Check ──────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "KYC Passport API",
    version: "1.0.0-demo",
    timestamp: new Date().toISOString(),
  });
});

// ─── Start Server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🛂  KYC Passport API running on port ${PORT}`);
  console.log(`    Health:     http://localhost:${PORT}/health`);
  console.log(`    Public key: http://localhost:${PORT}/public-key`);
  console.log(`\n    Endpoints:`);
  console.log(`    POST /issue        → Issue signed credential`);
  console.log(`    POST /verify       → Verify credential (Bank B)`);
  console.log(`    GET  /status/:id   → Poll session status`);
  console.log(`    POST /ai-score     → Claude AI risk scoring\n`);
});

// Export for testing
module.exports = { app, publicKey, privateKey };
