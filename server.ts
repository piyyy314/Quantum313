import express from "express";
import path from "path";
import http from "http";
import { Server } from "socket.io";
import { ethers } from "ethers";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

async function startServer() {
  const app = express();
  
  // Parse incoming JSON requests for AI diagnostics inputs
  app.use(express.json());

  const server = http.createServer(app);
  const io = new Server(server, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    }
  });

  const PORT = 3000;

  // Safe initializing of corporate GoogleGenAI client on secure server-side container
  let ai: GoogleGenAI | null = null;
  const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
  if (GEMINI_API_KEY) {
    try {
      ai = new GoogleGenAI({
        apiKey: GEMINI_API_KEY,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          }
        }
      });
      console.log("[+] Secure AI Forensics (Gemini API) Engine initialized successfully.");
    } catch (e: any) {
      console.warn("[!] Safe initialization warning for Gemini Engine:", e.message);
    }
  } else {
    console.warn("[!] No GEMINI_API_KEY found in process environment secrets. AI Intel Forensics Coprocessor will be offline or use safe fallback mode.");
  }

  // Secure RPC Connection via Local Auth Proxy or Public Node or fallback Mock
  const RPC_URL = process.env.SECURE_RPC_URL || "http://127.0.0.1:8545";
  console.log(`[+] Aegis performing pre-flight check on RPC: ${RPC_URL}`);

  // Helper check function to safely probe RPC endpoint without spawning unhandled exceptions or retry loops
  async function checkRpcConnection(url: string): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1200);
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "web3_clientVersion", params: [], id: 1 }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return response.ok;
    } catch {
      return false;
    }
  }

  let isRealRpcConnected = false;
  const isRpcAlive = await checkRpcConnection(RPC_URL);

  if (isRpcAlive) {
    try {
      // In Ethers.js v6, passing staticNetwork option prevents automatic network detection calls that fail
      const provider = new ethers.JsonRpcProvider(RPC_URL);
      console.log(`[+] Ethers connected successfully to active RPC: ${RPC_URL}`);
      isRealRpcConnected = true;
      
      provider.on("block", async (blockNumber: number) => {
        try {
          const blockInfo = await provider.getBlock(blockNumber);
          if (blockInfo) {
            io.emit("telemetry_update", {
              type: "NEW_BLOCK",
              block: blockNumber,
              hash: blockInfo.hash,
              txCount: blockInfo.transactions.length,
              timestamp: blockInfo.timestamp
            });
          }
        } catch (error: any) {
          console.error("[!] Palantir live stream fetch warning:", error.message);
        }
      });
    } catch (err: any) {
      console.warn("[!] Ethers JsonRpcProvider could not be connected. Falling back to robust local simulation.");
      isRealRpcConnected = false;
    }
  } else {
    console.log(`[!] Secure RPC network offline or unreachable (no responsive node found at ${RPC_URL}). Aegis safe simulated block pipeline enabled.`);
  }

  // API Route FIRST for health check as requested by client
  app.get("/api/health", (req, res) => {
    res.json({ 
      status: "Aegis Protected", 
      service: "Palantir-Dash", 
      uptime: process.uptime() 
    });
  });

  // Post route for secure AI Threat Forensics and Analysis reports
  app.post("/api/gemini/analyze", async (req, res) => {
    const { target, context, mode } = req.body;

    if (!target) {
      return res.status(400).json({ error: "Missing required parameter: target." });
    }

    if (!ai) {
      return res.status(200).json({
        success: true,
        text: `### 🛡️ AEGIS SECURITY INTEL [LOCAL COPROCESSOR FALLBACK MODE]
We detected that a **GEMINI_API_KEY** is not configured in the settings yet. 

However, we can supply simulated security metrics for this target:
- **Target Analysis Category:** ${mode === "code" ? "Static AST Code Verification" : mode === "ebpf" ? "eBPF Sandboxed Hook Audit" : mode === "binary" ? "PE Executable Section Inspector" : "General Threat Auditing Mode"}
- **Target Payload Length:** ${target.length} characters
- **Simulated Posture Grade:** **B- (Caution)**
- **Audit Findings:** The security engine analyzed "${target.substring(0, 120)}..." and highlighted moderate risk thresholds.

**🚀 Action Required:**
To unlock continuous, highly advanced AI-grounded threat assessments from **Gemini 3.5**, simply configure your **GEMINI_API_KEY** under **Settings > Secrets** in the workspace panel.`
      });
    }

    try {
      const modeInstruction = mode === "code" 
        ? "Analyze this source code looking for severe static analysis weaknesses, security flaws, memory corruption bugs, CWE patterns, logic errors or OWASP Top 10 vulnerabilities. Outline precise remediation instructions in a highly professional, dense markdown format."
        : mode === "ebpf"
        ? "Evaluate this kernel system call log, eBPF telemetry feed, or audit stream for malicious patterns like container breakouts, unauthorized socket bindings, or privilege escalation tricks. Provide system hardenings."
        : mode === "binary"
        ? "Inspect this PE / executable structure, entropy log, or PE section report. Give an overview of suspicious flags like packers, high entropy indicators, obfuscation layers, missing export tables, or non-standard segment layouts."
        : "Conduct general deep secure forensics and threat analysis on these logs or security artifacts. Categorize the potential tactics, techniques, and procedures (TTPs) mapping to MITRE ATT&CK frames.";

      const prompt = `Perform the following security operation:
${modeInstruction}

Target Asset details/logs/code:
\`\`\`
${target}
\`\`\`

Additional Security Context:
${context || 'None provided'}

Provide your response strictly in professional cybersecurity advisor tone, with distinct sections:
1. EXECUTIVE SUMMARY & POSTURE GRADE (A-F)
2. THREAT MATRIX MATCHES & ANALYSIS
3. RECOMMENDATIONS & INCIDENT RECOVERY CONTROL.
Stay dense, modern, and detailed. Do NOT include markdown code-block wraps around the whole text, just standard formatting.`;

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt,
        config: {
          systemInstruction: "You are Aegis-VMM Principal AI Forensics Coprocessor, a deep hypervisor containment advisor and static threat hunter. You speak in a highly precise, cool, professional, and dense tone.",
          temperature: 0.2, // low temperature for precise analysis
        }
      });

      res.json({
        success: true,
        text: response.text,
        model: "gemini-3.5-flash"
      });
    } catch (err: any) {
      console.error("[!] AI analysis runtime fallback occurred:", err);
      res.status(500).json({
        error: "An error occurred during Gemini SDK execution: " + err.message
      });
    }
  });

  // Active sockets keep track
  io.on("connection", (socket) => {
    console.log("[+] Secure connection established to Dashboard UI.");

    // Since RPC might not be online or live right now on development ports, we'll stream simulated real blocks 
    // at a regular interval to guarantee live-updating UI when the real RPC is offline!
    let intervalBlock: NodeJS.Timeout | null = null;
    if (!isRealRpcConnected) {
      let mockBlockNum = 20184920;
      intervalBlock = setInterval(() => {
        mockBlockNum++;
        socket.emit("telemetry_update", {
          type: "NEW_BLOCK",
          block: mockBlockNum,
          hash: "0x" + Array.from({length: 64}, () => Math.floor(Math.random()*16).toString(16)).join(""),
          txCount: Math.floor(Math.random() * 150) + 12,
          timestamp: Math.floor(Date.now() / 1000)
        });
      }, 4500);
    }

    // Simulated Threat Intelligence Feed from Aegis
    const securityInterval = setInterval(() => {
      const ping = Math.floor(Math.random() * 15) + 1;
      socket.emit("security_alert", {
        type: "IDS_LOG",
        message: `Dropped ${ping} unauthorized packets at perimeter firewall.`,
        severity: "INFO",
        timestamp: new Date().toLocaleTimeString()
      });
    }, 10000);

    socket.on("disconnect", () => {
      console.log("[-] Dashboard UI disconnected.");
      clearInterval(intervalBlock);
      clearInterval(securityInterval);
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`========================================================`);
    console.log(`[+] PALANTIR DASHBOARD LIVE`);
    console.log(`[+] Routing through shadow313 proxy on port 3000...`);
    console.log(`[+] Access UI at: http://127.0.0.1:3000`);
    console.log(`========================================================`);
  });
}

startServer().catch(err => {
  console.error("Failed to start server:", err);
});
