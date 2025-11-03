// @ts-nocheck
const express = require("express");
const multer = require("multer");
const CryptoJS = require("crypto-js");
const fs = require("fs");
const path = require("path");
const Web3 = require("web3").default;
const QRCode = require('qrcode');
const { networkInterfaces } = require('os');
const contract = require("./build/contracts/CertificateStorage.json");

const app = express();
const port = 3000;

// Middleware
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ==========================
// 🌐 Get Server IP Address
// ==========================
function getServerIP() {
  const nets = networkInterfaces();
  
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return 'localhost';
}

const serverIP = getServerIP();

// ==========================
// 📦 Multer setup
// ==========================
const upload = multer({ dest: "uploads/" });

// ==========================
// 🔗 Web3 + Smart Contract
// ==========================
const web3 = new Web3("http://127.0.0.1:7545");
const networkId = Object.keys(contract.networks)[0];

if (!networkId) {
  throw new Error("❌ Contract not deployed on Ganache. Run: truffle migrate --reset");
}

const contractAddress = contract.networks[networkId].address;
const certificateContract = new web3.eth.Contract(contract.abi, contractAddress);

// Create qrcodes directory if it doesn't exist
const qrCodesDir = path.join(__dirname, 'qrcodes');
if (!fs.existsSync(qrCodesDir)) {
  fs.mkdirSync(qrCodesDir);
}

// Simple user storage (in production, use a database)
const users = [
  { username: "issuer", password: "issuer123", role: "issuer" },
  { username: "employer", password: "employer123", role: "employer" }
];

// Session storage (in production, use proper sessions)
let sessions = {};

// ==========================
// 🏠 Routes
// ==========================

// Serve HOME page (main page with just title)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});

// Serve LOGIN page (when clicking login button)
app.get("/login-page", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// ==========================
// 🔍 Public Verifier Route (No authentication required)
// ==========================
app.get("/verifier", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "verifier-dashboard.html"));
});

// Login endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    const sessionId = Math.random().toString(36).substring(7);
    sessions[sessionId] = { username: user.username, role: user.role };
    
    res.json({
      status: "success",
      message: "Login successful",
      role: user.role,
      sessionId: sessionId
    });
  } else {
    res.status(401).json({
      status: "error",
      error: "Invalid username or password"
    });
  }
});

// Dashboard based on role
app.get("/dashboard", (req, res) => {
  const sessionId = req.query.sessionId;
  const session = sessions[sessionId];
  
  if (!session) {
    return res.redirect("/");
  }
  
  if (session.role === "issuer") {
    res.sendFile(path.join(__dirname, "public", "issuer-dashboard.html"));
  } else {
    res.sendFile(path.join(__dirname, "public", "verifier-dashboard.html"));
  }
});

// Logout
app.post("/logout", (req, res) => {
  const { sessionId } = req.body;
  delete sessions[sessionId];
  res.json({ status: "success", message: "Logged out successfully" });
});

// ==========================
// 📤 Upload Certificate with additional data + QR Code Generation
// ==========================
app.post("/upload", upload.single("certificate"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ status: "error", error: "No file uploaded." });
    }

    // Validate all required fields
    const requiredFields = ['department', 'name', 'academicYear', 'regNo', 'joinDate', 'endDate', 'marks'];
    for (let field of requiredFields) {
      if (!req.body[field]) {
        return res.status(400).json({ status: "error", error:`Missing required field: ${field} `});
      }
    }

    const fileData = fs.readFileSync(req.file.path);
    const fileHash = CryptoJS.SHA256(CryptoJS.lib.WordArray.create(fileData)).toString();

    console.log("📌 File Hash (upload):", fileHash);

    // Get account dynamically for each upload
    const accounts = await web3.eth.getAccounts();
    const account = accounts[0];

    await certificateContract.methods
      .storeCertificate(fileHash)
      .send({ from: account, gas: 500000 });

    // Store additional certificate data (in production, use database)
    const certificateData = {
      hash: fileHash,
      department: req.body.department,
      name: req.body.name,
      academicYear: req.body.academicYear,
      regNo: req.body.regNo,
      joinDate: req.body.joinDate,
      endDate: req.body.endDate,
      marks: req.body.marks,
      timestamp: new Date().toISOString()
    };

    // Save certificate data to file (in production, use database)
    const certificatesFile = path.join(__dirname, 'certificates.json');
    let certificates = [];
    if (fs.existsSync(certificatesFile)) {
      certificates = JSON.parse(fs.readFileSync(certificatesFile));
    }
    certificates.push(certificateData);
    fs.writeFileSync(certificatesFile, JSON.stringify(certificates, null, 2));

    // Generate QR Code - Use IP address for mobile compatibility
    const qrCodeText = `http://${serverIP}:${port}/verify-hash/${fileHash}`;

    const qrCodeFileName = `qr_${fileHash.substring(0, 16)}.png;`
    const qrCodePath = path.join(qrCodesDir, qrCodeFileName);

    try {
      // Generate QR code with the direct verification URL
      await QRCode.toFile(qrCodePath, qrCodeText, {
        color: {
          dark: '#000000',
          light: '#FFFFFF'
        },
        width: 300,
        margin: 2
      });
      console.log("✅ QR Code generated");
    } catch (qrError) {
      console.error("❌ QR Code generation failed:", qrError);
    }

    res.json({
      status: "success",
      message: "✅ Certificate stored successfully on blockchain",
      hash: fileHash,
      data: certificateData,
      qrCodeUrl: `/qrcodes/${qrCodeFileName}`
    });
  } catch (error) {
    console.error("❌ Upload error:", error);
    res.status(500).json({
      status: "error",
      error: "Error uploading certificate.",
    });
  }
});

// ==========================
// 🌐 Public Verification Page (for QR Code scanning)
// ==========================
app.get("/verify-hash/:hash", async (req, res) => {
  try {
    const fileHash = req.params.hash;
    console.log("📌 Verifying hash from QR:", fileHash);

    // Verify the certificate
    let verificationResult;
    try {
      verificationResult = await verifyCertificateHashForPage(fileHash);
    } catch (error) {
      verificationResult = {
        status: "failed",
        message: "❌ Certificate not found or invalid"
      };
    }

    // Serve HTML page with verification results
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Certificate Verification - Blockchain Verifier</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
          font-family: Arial, sans-serif; 
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          min-height: 100vh; 
          display: flex; 
          justify-content: center; 
          align-items: center; 
          padding: 20px;
        }
        .container {
          background: white;
          padding: 40px;
          border-radius: 20px;
          box-shadow: 0 15px 35px rgba(0,0,0,0.1);
          max-width: 500px;
          width: 100%;
          text-align: center;
        }
        .status-success { 
          color: #28a745; 
          font-size: 2rem; 
          margin-bottom: 20px;
        }
        .status-failed { 
          color: #dc3545; 
          font-size: 2rem; 
          margin-bottom: 20px;
        }
        .details {
          background: #f8f9fa;
          padding: 20px;
          border-radius: 10px;
          margin-top: 20px;
          text-align: left;
        }
        .detail-row {
          display: flex;
          justify-content: space-between;
          margin-bottom: 10px;
          padding-bottom: 10px;
          border-bottom: 1px solid #dee2e6;
        }
        .detail-label {
          font-weight: bold;
          color: #6c757d;
        }
        .hash {
          font-family: monospace;
          background: #e9ecef;
          padding: 10px;
          border-radius: 5px;
          word-break: break-all;
          margin: 10px 0;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Blockchain Certificate Verification</h1>
        <div class="${verificationResult.status === 'success' ? 'status-success' : 'status-failed'}">
          ${verificationResult.status === 'success' ? '✅ VALID CERTIFICATE' : '❌ INVALID CERTIFICATE'}
        </div>
        <p>${verificationResult.message}</p>
        
        ${verificationResult.status === 'success' ? `
          <div class="details">
            <h3>Certificate Details</h3>
            <div class="detail-row">
              <span class="detail-label">Name:</span>
              <span>${verificationResult.certificateData.name}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Department:</span>
              <span>${verificationResult.certificateData.department}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Registration No:</span>
              <span>${verificationResult.certificateData.regNo}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Academic Year:</span>
              <span>${verificationResult.certificateData.academicYear}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Marks:</span>
              <span>${verificationResult.certificateData.marks}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Issued By:</span>
              <span>${verificationResult.issuer}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Issue Date:</span>
              <span>${verificationResult.timestamp}</span>
            </div>
            <div class="hash">
              <strong>Certificate Hash:</strong><br>
              ${verificationResult.hash}
            </div>
          </div>
        ` : ''}
        
        <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #dee2e6;">
          <p style="color: #6c757d; font-size: 0.9rem;">
            Verified on Blockchain • ${new Date().toLocaleString()}
          </p>
        </div>
      </div>
    </body>
    </html>
    `;

    res.send(html);

  } catch (error) {
    console.error("❌ Verify hash page error:", error);
    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head><title>Error</title></head>
      <body style="font-family: Arial; text-align: center; padding: 50px;">
        <h1 style="color: #dc3545;">❌ Verification Error</h1>
        <p>Unable to verify certificate. Please try again.</p>
      </body>
      </html>
    `);
  }
});

// ==========================
// 🔍 Verify Certificate by File Upload
// ==========================
app.post("/verify", upload.single("certificate"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ status: "error", error: "No file uploaded." });
    }

    const fileData = fs.readFileSync(req.file.path);
    const fileHash = CryptoJS.SHA256(CryptoJS.lib.WordArray.create(fileData)).toString();

    console.log("📌 File Hash (verify):", fileHash);

    return await verifyCertificateHash(fileHash, res);
  } catch (error) {
    console.error("❌ Verify error:", error);
    res.status(500).json({
      status: "error",
      error: "Unexpected error during verification. Please try again.",
    });
  }
});

// ==========================
// 🔍 Verify Certificate by Hash (POST endpoint)
// ==========================
app.post("/verify-hash", async (req, res) => {
  try {
    const { hash } = req.body;
    if (!hash) {
      return res.status(400).json({ status: "error", error: "No hash provided." });
    }

    console.log("📌 Verifying hash:", hash);
    return await verifyCertificateHash(hash, res);
  } catch (error) {
    console.error("❌ Verify hash error:", error);
    res.status(500).json({
      status: "error",
      error: "Unexpected error during verification. Please try again.",
    });
  }
});

// ==========================
// 🎯 Common Certificate Verification Function
// ==========================
async function verifyCertificateHash(fileHash, res) {
  try {
    let cert;
    try {
      cert = await certificateContract.methods.verifyCertificate(fileHash).call();
    } catch (err) {
      console.log("❌ Blockchain revert: Certificate not found.");
      return res.json({
        status: "failed",
        message: "❌ Certificate not found or invalid",
      });
    }

    const issuer = cert[0];
    const timestamp = cert[1];

    if (!issuer || issuer === "0x0000000000000000000000000000000000000000") {
      return res.json({
        status: "failed",
        message: "❌ Certificate not found or invalid",
      });
    }

    // Get additional certificate data
    const certificatesFile = path.join(__dirname, 'certificates.json');
    let certificateData = null;
    if (fs.existsSync(certificatesFile)) {
      const certificates = JSON.parse(fs.readFileSync(certificatesFile));
      certificateData = certificates.find(c => c.hash === fileHash);
    }

    const timestampNum = Number(timestamp);

    return res.json({
      status: "success",
      message: "✅ Certificate verified successfully!",
      hash: fileHash,
      issuer: issuer,
      timestamp: new Date(timestampNum * 1000).toLocaleString(),
      certificateData: certificateData
    });
  } catch (error) {
    console.error("❌ Verify certificate error:", error);

    if (
      error.message.includes("Certificate not found") ||
      error.message.includes("revert")
    ) {
      return res.json({
        status: "failed",
        message: "❌ Certificate not found or invalid",
      });
    }

    return res.status(500).json({
      status: "error",
      error: "Unexpected error during verification. Please try again.",
    });
  }
}

// ==========================
// 🎯 Common Certificate Verification Function for Web Page
// ==========================
async function verifyCertificateHashForPage(fileHash) {
  try {
    let cert;
    try {
      cert = await certificateContract.methods.verifyCertificate(fileHash).call();
    } catch (err) {
      console.log("❌ Blockchain revert: Certificate not found.");
      return {
        status: "failed",
        message: "❌ Certificate not found or invalid"
      };
    }

    const issuer = cert[0];
    const timestamp = cert[1];

    if (!issuer || issuer === "0x0000000000000000000000000000000000000000") {
      return {
        status: "failed",
        message: "❌ Certificate not found or invalid"
      };
    }

    // Get additional certificate data
    const certificatesFile = path.join(__dirname, 'certificates.json');
    let certificateData = null;
    if (fs.existsSync(certificatesFile)) {
      const certificates = JSON.parse(fs.readFileSync(certificatesFile));
      certificateData = certificates.find(c => c.hash === fileHash);
    }

    const timestampNum = Number(timestamp);

    return {
      status: "success",
      message: "✅ Certificate verified successfully! This certificate is authentic and stored on the blockchain.",
      hash: fileHash,
      issuer: issuer,
      timestamp: new Date(timestampNum * 1000).toLocaleString(),
      certificateData: certificateData
    };
  } catch (error) {
    console.error("❌ Verify certificate error:", error);
    return {
      status: "failed",
      message: "❌ Certificate verification failed"
    };
  }
}

// ==========================
// 📁 Serve QR Code files
// ==========================
app.use('/qrcodes', express.static(qrCodesDir));

// ==========================
// 🚀 Start server
// ==========================
app.listen(port, async () => {
  try {
    const accounts = await web3.eth.getAccounts();
    const account = accounts[0];
    
    console.log(`🚀 Server running on http://localhost:${port}`);
    console.log(`✅ Using account: ${account}`);
    console.log(`✅ Contract Address: ${contractAddress}`);
  } catch (error) {
    console.log(`🚀 Server running on http://localhost:${port}`);
    console.log(`❌ Failed to get account information: ${error.message}`);
    console.log(`✅ Contract Address: ${contractAddress}`);
  }
});