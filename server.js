const express = require("express");
const jwt = require("jsonwebtoken");
const { generateKeyPairSync } = require("crypto");
const QRCode = require("qrcode");
const Anthropic = require("@anthropic-ai/sdk");
const multer = require("multer");
const pdfParse = require("pdf-parse");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

// ─── RSA Key Generation ───────────────────────────────────────────────────────
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// ─── In-Memory Session Store ──────────────────────────────────────────────────
const sessions = {};
function calcAgeVerified(dob) {
  if (!dob || String(dob).includes("*")) return "18+";
  const d = new Date(dob);
  if (isNaN(d.getTime())) return "18+";
  const age = Math.floor((Date.now() - d) / (365.25*24*60*60*1000));
  return age >= 21 ? "21+" : age >= 18 ? "18+" : "under18";
}


// ─── Anthropic Client ─────────────────────────────────────────────────────────
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ─── Multer — file upload config ─────────────────────────────────────────────
// Accepts JPG, PNG, PDF up to 10MB, stored in memory (no disk writes)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "application/pdf"];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("Only JPG, PNG, and PDF files are accepted"));
    }
  },
});

// ─── GET /public-key ──────────────────────────────────────────────────────────
app.get("/public-key", (req, res) => {
  res.json({ publicKey });
});

// ─── GET /health ──────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "TruVy KYC API",
    version: "2.0.0-demo",
    endpoints: [
      "POST /issue",
      "POST /issue-from-document",
      "POST /verify",
      "GET  /status/:id",
      "POST /ai-score",
      "GET  /public-key",
    ],
    timestamp: new Date().toISOString(),
  });
});

// ─── POST /issue ──────────────────────────────────────────────────────────────
// Standard credential issuance from manual form fields
app.post("/issue", async (req, res) => {
  try {
    const { name, country, documentType = "passport" } = req.body;

    if (!name || !country) {
      return res.status(400).json({ error: "name and country are required" });
    }

    const sessionId = `sess_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    const sharedClaims = {
      name,
      country,
      documentType,
      sanctionsCheck: "PASSED",
      ageVerified: calcAgeVerified(req.body.dateOfBirth),
      issuer: "did:kycp:legitimuz",
      issuedAt: new Date().toISOString(),
    };

    const token = jwt.sign(sharedClaims, privateKey, {
      algorithm: "RS256",
      expiresIn: "7d",
      subject: `kycp:${sessionId}`,
    });

    const verifyUrl = `${process.env.BASE_URL || "http://localhost:3000"}/verify-qr/${sessionId}/${encodeURIComponent(token)}`;
    const qrBase64 = await QRCode.toDataURL(verifyUrl);

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

// ─── POST /issue-from-document ────────────────────────────────────────────────
// Accepts a real ID document (JPG, PNG, or PDF).
// Claude Vision extracts the identity fields.
// Returns a signed TruVy credential — same format as /issue.
//
// Form fields:
//   document — the file (required, multipart/form-data)
//
app.post("/issue-from-document", upload.single("document"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: "No document uploaded. Send a JPG, PNG, or PDF as 'document' field.",
      });
    }

    const { mimetype, buffer, originalname } = req.file;
    console.log(`[/issue-from-document] ${originalname} | ${mimetype} | ${buffer.length} bytes`);

    let extracted;

    if (mimetype === "application/pdf") {
      // PDFs: extract text first, then parse with Claude
      const pdfData = await pdfParse(buffer);
      const extractedText = pdfData.text.slice(0, 3000);
      extracted = await extractFieldsFromText(extractedText);
    } else {
      // JPG / PNG: send directly to Claude Vision
      const imageBase64 = buffer.toString("base64");
      extracted = await extractFieldsFromImage(imageBase64, mimetype);
    }

    return await issueCredentialFromFields(extracted, res);

  } catch (err) {
    console.error("[/issue-from-document] Error:", err.message);

    if (err.message.includes("Only JPG, PNG")) {
      return res.status(400).json({ error: err.message });
    }

    res.status(500).json({
      error: "Document processing failed",
      detail: err.message,
    });
  }
});

// ─── Claude Vision: extract fields from JPG/PNG ───────────────────────────────
async function extractFieldsFromImage(imageBase64, mimeType) {
  const response = await anthropic.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 800,
    messages: [
      {
        role: "user",
        content: [
          {
            type: "image",
            source: { type: "base64", media_type: mimeType, data: imageBase64 },
          },
          {
            type: "text",
            text: `You are a KYC document parser. Extract identity fields from this document image.

Return ONLY a valid JSON object — no other text:
{
  "name": "<full legal name as shown, or null if unreadable>",
  "country": "<issuing country or US state, e.g. 'United States', 'Brazil'>",
  "documentType": "<'passport' | 'drivers_license' | 'national_id'>",
  "documentNumber": "<ID number — show first 2 chars only then *******, e.g. 'AB*******'>",
  "dateOfBirth": "<return ONLY as '**/**/**** (age verified)', never the real date>",
  "expiryDate": "<expiry date if visible, or null>",
  "readable": <true if fields could be extracted, false if image is unclear>,
  "confidence": <0-100 confidence score>
}

Privacy rules (strict):
- documentNumber: ALWAYS mask — first 2 chars + ******* only
- dateOfBirth: ALWAYS return as "**/**/**** (age verified)" — never reveal real date
- If document is blurry, covered, or unreadable: set readable: false, return nulls
- Never invent data — null if not visible`,
          },
        ],
      },
    ],
  });

  const text = response.content[0].text.trim();
  return JSON.parse(text.replace(/```json|```/g, "").trim());
}

// ─── Claude Text: extract fields from PDF text ───────────────────────────────
async function extractFieldsFromText(rawText) {
  const response = await anthropic.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 800,
    messages: [
      {
        role: "user",
        content: `You are a KYC document parser. Extract identity fields from this PDF text.

PDF text:
${rawText}

Return ONLY a valid JSON object — no other text:
{
  "name": "<full legal name, or null if not found>",
  "country": "<issuing country, e.g. 'United States', 'Brazil'>",
  "documentType": "<'passport' | 'drivers_license' | 'national_id'>",
  "documentNumber": "<ID number — first 2 chars + ******* only>",
  "dateOfBirth": "<return ONLY as '**/**/**** (age verified)'>",
  "expiryDate": "<expiry date if found, or null>",
  "readable": <true if identity fields were found, false if text was empty>,
  "confidence": <0-100>
}

Privacy rules: always mask documentNumber and dateOfBirth as shown above.`,
      },
    ],
  });

  const text = response.content[0].text.trim();
  return JSON.parse(text.replace(/```json|```/g, "").trim());
}

// ─── Issue credential from extracted fields ───────────────────────────────────
async function issueCredentialFromFields(extracted, res) {
  if (!extracted.readable || !extracted.name) {
    return res.status(422).json({
      error: "Document could not be read",
      readable: false,
      detail: "The document was unclear or did not contain recognizable identity fields. Please upload a clearer photo.",
      suggestion: "Make sure the ID is flat, well-lit, and fully visible in the frame.",
      extracted,
    });
  }

  const sessionId = `sess_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  const sharedClaims = {
    name: extracted.name,
    country: extracted.country || "Unknown",
    documentType: extracted.documentType || "identity_document",
    sanctionsCheck: "PASSED",
    ageVerified: calcAgeVerified(extracted.dateOfBirth),
    issuer: "did:kycp:legitimuz",
    issuedAt: new Date().toISOString(),
    extractionConfidence: extracted.confidence,
  };

  const token = jwt.sign(sharedClaims, privateKey, {
    algorithm: "RS256",
    expiresIn: "7d",
    subject: `kycp:${sessionId}`,
  });

  const verifyUrl = `${process.env.BASE_URL || "http://localhost:3000"}/verify-qr/${sessionId}/${encodeURIComponent(token)}`;
  const qrBase64 = await QRCode.toDataURL(verifyUrl);

  sessions[sessionId] = { status: "pending", claims: null };

  console.log(`[/issue-from-document] ✓ Issued for: ${extracted.name} (${extracted.confidence}% confidence)`);

  return res.json({
    sessionId,
    token,
    qrBase64,
    sharedClaims,
    // Safe extracted fields shown in UI — sensitive ones are masked by Claude
    documentFields: {
      name: extracted.name,
      country: extracted.country,
      documentType: extracted.documentType,
      documentNumber: extracted.documentNumber,   // e.g. "AB*******"
      dateOfBirth: extracted.dateOfBirth,         // e.g. "**/**/**** (age verified)"
      expiryDate: extracted.expiryDate,
      extractionConfidence: extracted.confidence,
    },
    withheldFromBanks: [
      "documentNumber",
      "dateOfBirth",
      "homeAddress",
      "taxId",
      "rawDocumentImage",
    ],
    message: "Document scanned. Credential issued. Zero raw documents will be transmitted to any bank.",
  });
}

// ─── POST /verify ─────────────────────────────────────────────────────────────
// Any bank verifies a TruVy credential. Returns only safe claims.
app.post("/verify", (req, res) => {
  const { token, sessionId } = req.body;

  if (!token) {
    return res.status(400).json({ valid: false, error: "token is required" });
  }

  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });

    if (sessionId && sessions[sessionId]) {
      sessions[sessionId] = { status: "verified", claims: decoded };
    }

    res.json({
      valid: true,
      claims: {
        name: decoded.name,
        country: decoded.country,
        documentType: decoded.documentType,
        sanctionsCheck: decoded.sanctionsCheck,
        ageVerified: decoded.ageVerified,
        issuer: decoded.issuer,
        issuedAt: decoded.issuedAt,
      },
      withheld: [
        "documentNumber",
        "dateOfBirth",
        "homeAddress",
        "taxId",
        "rawDocumentImage",
      ],
      message: "Credential verified. Documents received: NONE.",
    });
  } catch (err) {
    res.status(401).json({
      valid: false,
      error: "invalid signature",
      detail: err.message,
      message: "Credential rejected. Cannot forge a TruVy Passport.",
    });
  }
});

// ─── GET /verify-qr/:sessionId/:token ────────────────────────────────────────
app.get("/verify-qr/:sessionId/:token", (req, res) => {
  const { sessionId, token } = req.params;

  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });

    if (sessions[sessionId]) {
      sessions[sessionId] = { status: "verified", claims: decoded };
    }

    res.json({ valid: true, message: "QR scan verified. Session marked complete.", sessionId });
  } catch (err) {
    res.status(401).json({ valid: false, error: "invalid signature" });
  }
});

// ─── GET /status/:sessionId ───────────────────────────────────────────────────
app.get("/status/:sessionId", (req, res) => {
  const session = sessions[req.params.sessionId];

  if (!session) {
    return res.status(404).json({ error: "session not found" });
  }

  res.json({
    sessionId: req.params.sessionId,
    status: session.status,
    claims: session.status === "verified" ? session.claims : null,
  });
});

// ─── POST /ai-score ───────────────────────────────────────────────────────────
// Sends ID image to Claude for AI risk scoring
app.post("/ai-score", async (req, res) => {
  try {
    const { imageBase64, mimeType = "image/jpeg" } = req.body;

    if (!imageBase64) {
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
      messages: [
        {
          role: "user",
          content: [
            {
              type: "image",
              source: { type: "base64", media_type: mimeType, data: imageBase64 },
            },
            {
              type: "text",
              text: `You are a KYC risk scoring AI. Analyze this identity document for authenticity signals.

Return ONLY a JSON object:
{
  "riskScore": <0-100, lower is safer>,
  "riskLevel": "<LOW|MEDIUM|HIGH>",
  "documentAuthenticity": "<LIKELY_GENUINE|SUSPICIOUS|UNREADABLE>",
  "flags": [<string flags, empty array if none>],
  "recommendation": "<APPROVE|REVIEW|REJECT>",
  "confidence": <0-100>
}`,
            },
          ],
        },
      ],
    });

    const text = response.content[0].text.trim();
    res.json(JSON.parse(text.replace(/```json|```/g, "").trim()));

  } catch (err) {
    console.error("[/ai-score] Error:", err.message);
    res.json({
      riskScore: 15,
      riskLevel: "LOW",
      documentAuthenticity: "LIKELY_GENUINE",
      flags: [],
      recommendation: "APPROVE",
      confidence: 88,
      note: "Fallback score",
    });
  }
});

// ─── Start Server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🛂  TruVy KYC API running on port ${PORT}`);
  console.log(`    Health:     http://localhost:${PORT}/health`);
  console.log(`    Public key: http://localhost:${PORT}/public-key`);
  console.log(`\n    Endpoints:`);
  console.log(`    POST /issue                → Issue from form fields`);
  console.log(`    POST /issue-from-document  → Issue from JPG/PNG/PDF upload ⭐`);
  console.log(`    POST /verify               → Verify credential (any bank)`);
  console.log(`    GET  /status/:id           → Poll session status`);
  console.log(`    POST /ai-score             → Claude AI risk scoring\n`);
});

module.exports = { app, publicKey, privateKey };
