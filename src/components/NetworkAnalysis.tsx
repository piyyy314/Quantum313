import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Network, Key, Shield, AlertTriangle, FileText, 
  Terminal, Search, Radio, Compass, RefreshCw, 
  Trash2, Play, CheckCircle, Download, FileJson, Cpu
} from 'lucide-react';

interface NetworkAnalysisProps {
  triggerToast: (msg: string) => void;
}

export default function NetworkAnalysis({ triggerToast }: NetworkAnalysisProps) {
  const [activeTab, setActiveTab] = useState<'network' | 'pwd' | 'social' | 'sandbox' | 'forensics' | 'reports' | 'jamming' | 'ids' | 'compliance'>('network');

  // 3. Network Analysis states
  const [hostIp, setHostIp] = useState('ground-controller.aegis.local');
  const [scanOutput, setScanOutput] = useState<string[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  // 5. Password Cracking states
  const [targetHash, setTargetHash] = useState('b8a9d12e84c2f1ea09de312f2ea');
  const [crackOutput, setCrackOutput] = useState<string[]>([]);
  const [isCracking, setIsCracking] = useState(false);

  // 6. Social Eng. states
  const [templateType, setTemplateType] = useState('cisa_alert');
  const [senderField, setSenderField] = useState('cisa-response@satellite-cisa.gov');
  const [campaignOutput, setCampaignOutput] = useState<string[]>([]);
  const [isSimulatingCampaign, setIsSimulatingCampaign] = useState(false);

  // 7. Malware Sandbox states
  const [sandboxFile, setSandboxFile] = useState('svchost_patched.exe');
  const [sandboxOutput, setSandboxOutput] = useState<string[]>([]);
  const [isSandboxRunning, setIsSandboxRunning] = useState(false);

  // 8. Incident Response / Forensics states
  const [caseId, setCaseId] = useState('CASE-2026-09A');
  const [forensicsLog, setForensicsLog] = useState<string[]>([
    "[*] Case file established: CASE-2026-09A.",
    "[*] Target host: Satellite Terminal Uplink Ground Controller.",
    "[*] ALERT: eBPF policy change detected on 'openat /etc/shadow' (intercepted -> allowed).",
    "[*] Immediate 15-min IR playbook active. Run remediation steps below."
  ]);
  const [isAnalyzingForensics, setIsAnalyzingForensics] = useState(false);
  const [suidBitCleared, setSuidBitCleared] = useState(false);
  const [ebpfRuleRestored, setEbpfRuleRestored] = useState(false);
  const [upxDeleted, setUpxDeleted] = useState(false);
  const [bindReceiptData, setBindReceiptData] = useState<any | null>(null);

  // 9. Automated Reports Engine states
  const [selectedReportType, setSelectedReportType] = useState('pci_dss');
  const [compiledReport, setCompiledReport] = useState<string>('');
  const [isCompilingReport, setIsCompilingReport] = useState(false);

  // 10. RF Jamming states
  const [jammingFreq, setJammingFreq] = useState('14.25');
  const [jammingOutput, setJammingOutput] = useState<string[]>([]);
  const [isJamming, setIsJamming] = useState(false);

  // 11. IDS Rules states
  const [idsTriggerCount, setIdsTriggerCount] = useState(0);
  const [idsRules, setIdsRules] = useState<string>(
    `# Suricata / Snort Ruleset for VSAT Defense\n` +
    `alert tcp any any -> $HOME_NET 8080 (msg:"Suspicious unauthenticated TCP terminal request"; content:"setuid"; sid:1000001; rev:1;)\n` +
    `alert udp any any -> $HOME_NET 161 (msg:"Vulnerable SNMPv1 command query"; content:"public"; sid:1000002; rev:1;)`
  );

  // 12. NSA Compliance / Hardening
  const [hardeningScore, setHardeningScore] = useState(82);

  // Executing 3. Network Analysis Scan
  const handleNetworkScan = () => {
    setIsScanning(true);
    setScanOutput([`[*] Initializing scanning engine targeting: ${hostIp}...`, `[>] Mapping routing tables & UDP gateway parameters...`]);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step === 1) {
        setScanOutput(prev => [...prev, `[+] Port 22/tcp (SSH) - OPEN (OpenSSH 8.9p1)`]);
      } else if (step === 2) {
        setScanOutput(prev => [...prev, `[+] Port 161/udp (SNMP) - OPEN (Vulnerable SNMPv1 Enabled!)`]);
      } else if (step === 3) {
        setScanOutput(prev => [...prev, `[+] Port 8080/tcp (HTTP) - OPEN (Unauthenticated Satellite Dashboard)`]);
      } else if (step === 4) {
        clearInterval(interval);
        setIsScanning(false);
        setScanOutput(prev => [...prev, `[✓] SCAN COMPLETE. SNMPv1 plain credentials pose critical threat vulnerability.`]);
        triggerToast('🔍 Network scan complete! Ground segment topology fully mapped.');
      }
    }, 800);
  };

  // Executing 5. Password Cracking
  const handlePasswordCracking = () => {
    setIsCracking(true);
    setCrackOutput([`[*] Launching parallel multi-threaded GPU brute force kernels over SHA256 targets...`, `[>] Target hash: ${targetHash}`]);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step === 1) {
        setCrackOutput(prev => [...prev, `[>] Sweeping standard dictionary arrays (0 / 10,000 matches)`]);
      } else if (step === 2) {
        setCrackOutput(prev => [...prev, `[>] Exhausting space permutations... matching offset failure.`]);
      } else if (step === 3) {
        clearInterval(interval);
        setIsCracking(false);
        setCrackOutput(prev => [...prev, `[✓] KEY CRACKED: "Aegis_Orbit_Admin_2026!"`, `[*] Crack time: 2.4 seconds`]);
        triggerToast('🔑 Key recovered successfully!');
      }
    }, 1000);
  };

  // Executing 6. Social Eng. Simulation
  const handleSocialSim = () => {
    setIsSimulatingCampaign(true);
    setCampaignOutput([`[*] Formatting campaign payload template: ${templateType}...`, `[*] Sender alias: ${senderField}`]);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step === 1) {
        setCampaignOutput(prev => [...prev, `[>] Formatting digital signature header blocks...`]);
      } else if (step === 2) {
        setCampaignOutput(prev => [...prev, `[>] Dispatching simulated target email list...`]);
      } else if (step === 3) {
        clearInterval(interval);
        setIsSimulatingCampaign(false);
        setCampaignOutput(prev => [...prev, `[✓] CAMPAIGN FINALISED. Over 42% clickthrough simulated, proving lack of credential-entry guardrails.`]);
        triggerToast('🎣 Phishing simulation finished!');
      }
    }, 800);
  };

  // Executing 7. Malware Sandbox
  const handleMalwareSandbox = () => {
    setIsSandboxRunning(true);
    setSandboxOutput([`[*] Spinning up sandboxed virtual container...`, `[*] Injecting threat analyzer hooks into: ${sandboxFile}`]);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step === 1) {
        setSandboxOutput(prev => [...prev, `[>] Monitoring kernel system calls (eBPF Telemetry Hook Enabled)`]);
      } else if (step === 2) {
        setSandboxOutput(prev => [...prev, `[⚠️] WARNING: Executable attempted unaligned thread injection (VirtualAlloc)`]);
      } else if (step === 3) {
        setSandboxOutput(prev => [...prev, `[⚠️] WARNING: Attempted to fetch remote payloads from unvetted HTTP endpoint`]);
      } else if (step === 4) {
        clearInterval(interval);
        setIsSandboxRunning(false);
        setSandboxOutput(prev => [...prev, `[✓] SANDBOX EXECUTION HALTED. Threat index: 8.8/10 (Ransomware Backdoor)`]);
        triggerToast('☣️ Sandbox threat behavior analyzed!');
      }
    }, 900);
  };

  // Executing 8. Incident Forensics & Remediation Actions
  const handleCheckSuidBash = () => {
    setForensicsLog(prev => [
      ...prev,
      `[1/8] Inspecting /bin/bash permissions...`,
      `[!] FOUND: -rwsr-xr-x 1 root root (SUID BIT SET!)`,
      `[>] Executing 'chmod u-s /bin/bash' immediately...`,
      `[✓] SUCCESS: SUID bit stripped from /bin/bash (-rwxr-xr-x).`
    ]);
    setSuidBitCleared(true);
    triggerToast('🛡️ SUID bit removed from /bin/bash successfully!');
  };

  const handleAuditEbpfPolicy = () => {
    setForensicsLog(prev => [
      ...prev,
      `[2/8] Auditing eBPF policy modification log...`,
      `[!] EVENT: openat /etc/shadow rule decision changed: intercepted -> allowed`,
      `[!] CHANGED_BY: UNKNOWN — INVESTIGATE`,
      `[!] FIRST_ALLOWED_TS: 2026-08-08T04:01:50Z`,
      `[!] SESSIONS_BLOCKED_BEFORE_CHANGE: 15`
    ]);
    triggerToast('🔍 eBPF policy modification log analyzed.');
  };

  const handleVerifyShadowExfil = () => {
    setForensicsLog(prev => [
      ...prev,
      `[3/8] Checking /etc/shadow access & exfiltration status...`,
      `[!] FOUND: Process 'cat' (PID 9990) issued openat /etc/shadow at 2026-08-08T04:01:52Z.`,
      `[!] STATUS: Read succeeded (allowed due to modified eBPF rule). Hashes exposed.`,
      `[⚠️] ALERT: /etc/shadow hash exfiltration detected via outbound TCP stream.`
    ]);
    triggerToast('⚠️ /etc/shadow exfiltration confirmed.');
  };

  const handleTracePPID725 = () => {
    setForensicsLog(prev => [
      ...prev,
      `[4/8] Tracing PPID 725 (parent of cat PID 9990)...`,
      `[>] Querying kernel process tree: PID 9990 (cat) -> PPID 725`,
      `[!] PPID 725 Identified: /usr/libexec/space_telemetryd (Backdoored L-band daemon)`,
      `[!] SPAWNED_BY: /bin/sh -c 'cat /etc/shadow > /tmp/.exfil'`
    ]);
    triggerToast('🎯 PPID 725 process tree mapped to backdoored telemetry daemon.');
  };

  const handleRestoreShadowRule = () => {
    setForensicsLog(prev => [
      ...prev,
      `[5/8] Restoring eBPF 'openat /etc/shadow' intercept rule...`,
      `[>] Injecting kernel kprobe filter rule ID: ebpf-shadow-block-01`,
      `[✓] SUCCESS: 'openat /etc/shadow' decision set to INTERCEPTED.`
    ]);
    setEbpfRuleRestored(true);
    triggerToast('🛡️ eBPF openat /etc/shadow rule restored to INTERCEPTED!');
  };

  const handle313BindReceipt = () => {
    const payload = {
      event: "EBPF_POLICY_CHANGE",
      rule: "openat /etc/shadow",
      old_decision: "intercepted",
      new_decision: "allowed",
      changed_by: "UNKNOWN — INVESTIGATE",
      first_allowed_ts: "2026-08-08T04:01:50Z",
      sessions_blocked_before_change: 15,
      receipt_id: "313-BIND-8f921a00e42d",
      cryptographic_hash: "sha256:7a920b12c842e911a3df049e218274191c0b31e9f82d1c7a2b90c1f4e",
      timestamp_bound: new Date().toISOString()
    };
    setBindReceiptData(payload);
    setForensicsLog(prev => [
      ...prev,
      `[6/8] Executing bind_receipt() for 313-BIND cryptographic timestamp...`,
      `[✓] 313-BIND RECEIPT BOUND: sha256:7a920b12c842e911a3df04...`,
      `[✓] Unforgeable cryptographic receipt stored in audit ledger.`
    ]);
    triggerToast('🔐 313-BIND cryptographic receipt successfully generated & bound!');
  };

  const handleDeleteUpxBinary = () => {
    setForensicsLog(prev => [
      ...prev,
      `[8/8] Scanning disk for UPX-packed binaries...`,
      `[!] FOUND: /tmp/.upx_payload_packed (UPX 3.96 packed ELF 64-bit)`,
      `[>] Executing shred -u /tmp/.upx_payload_packed...`,
      `[✓] SUCCESS: UPX-packed malware binary permanently removed from disk.`
    ]);
    setUpxDeleted(true);
    triggerToast('🧹 UPX-packed binary shredded and deleted from disk!');
  };

  const handleIncidentForensics = () => {
    setIsAnalyzingForensics(true);
    setForensicsLog([`[*] Case file established: ${caseId}.`, `[*] Running full 8-step eBPF & Incident Response correlation...`]);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step === 1) {
        setForensicsLog(prev => [...prev, `[>] [15-MIN ACTION] Checked /bin/bash: SUID bit detected.`]);
      } else if (step === 2) {
        setForensicsLog(prev => [...prev, `[>] [15-MIN ACTION] Checked eBPF log: 'openat /etc/shadow' allowed at 2026-08-08T04:01:50Z.`]);
      } else if (step === 3) {
        setForensicsLog(prev => [...prev, `[>] [15-MIN ACTION] Verified cat (PID 9990) read /etc/shadow under PPID 725.`]);
      } else if (step === 4) {
        clearInterval(interval);
        setIsAnalyzingForensics(false);
        setForensicsLog(prev => [...prev, `[✓] INCIDENT ANALYSIS COMPLETE. Use action buttons below to execute remediation steps & 313-BIND receipt.`]);
        triggerToast('📋 Case forensics correlation complete!');
      }
    }, 800);
  };

  // Executing 9. Automated Reports
  const handleAutomatedReport = () => {
    setIsCompilingReport(true);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step === 2) {
        clearInterval(interval);
        setIsCompilingReport(false);
        const reportText = 
          `================================================================================\n` +
          `Aegis Intelligence Automated Cyber-Range Report\n` +
          `Report Standard: ${selectedReportType.toUpperCase()}\n` +
          `Compiled Timestamp UTC: 2026-07-17T23:22:59Z\n` +
          `Generated For: baalbek.313@gmail.com\n` +
          `================================================================================\n\n` +
          `1. INCIDENT CORRELATION STATISTICS\n` +
          `- Active Telemetry Audit Jitter: 11 ms\n` +
          `- Satellite Doppler Offset: +4.1 Hz\n` +
          `- Identified Vulnerabilities: Plaintext SNMPv1 enabled, Unauthenticated Port 8080.\n\n` +
          `2. SECURITY REMEDIATION REQUIREMENTS\n` +
          `- [MANDATORY] Enforce HTTPS/TLS and block Port 80 dynamic redirects.\n` +
          `- [MANDATORY] Restructure credentials from vulnerable SNMPv1 to SNMPv3 cryptographic signing.\n` +
          `- [MANDATORY] Implement Suricata/Snort alert rulesets to block unvetted setuid(0) triggers.\n\n` +
          `3. DISPOSITION\n` +
          `Target satisfies 100% NSA Ground-Station Security Hardening Standards upon applying toggled controls.`;
        setCompiledReport(reportText);
        triggerToast('📋 Automated report successfully generated!');
      }
    }, 800);
  };

  // Executing 10. RF Jamming Simulation
  const handleRFJamming = () => {
    setIsJamming(true);
    setJammingOutput([`[*] Injecting high-power white Gaussian noise loop...`, `[*] Target uplink frequency: ${jammingFreq} GHz`]);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step === 1) {
        setJammingOutput(prev => [...prev, `[>] Transmitting intermodulation carriers into L-band receiver...`]);
      } else if (step === 2) {
        setJammingOutput(prev => [...prev, `[⚠️] Carrier SNR collapsing to < 6.2 dB (LOCK LOST)`]);
      } else if (step === 3) {
        clearInterval(interval);
        setIsJamming(false);
        setJammingOutput(prev => [...prev, `[✓] RF Spectrum fully congested. Target satellite communication transponder completely disconnected.`]);
        triggerToast('📡 High-power Jamming active! Communication loop severed.');
      }
    }, 900);
  };

  return (
    <div className="space-y-6">
      {/* Element Nav Row */}
      <div className="bg-slate-950/40 border border-white/5 p-2 rounded flex flex-wrap gap-1.5">
        <button
          onClick={() => setActiveTab('network')}
          className={`px-3 py-1.5 rounded font-mono text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer ${
            activeTab === 'network' ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/20' : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          🌐 3. Network Analysis
        </button>

        <button
          onClick={() => setActiveTab('pwd')}
          className={`px-3 py-1.5 rounded font-mono text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer ${
            activeTab === 'pwd' ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/20' : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          🔑 5. Password Cracker
        </button>

        <button
          onClick={() => setActiveTab('social')}
          className={`px-3 py-1.5 rounded font-mono text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer ${
            activeTab === 'social' ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/20' : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          🎣 6. Social Eng. Sim
        </button>

        <button
          onClick={() => setActiveTab('sandbox')}
          className={`px-3 py-1.5 rounded font-mono text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer ${
            activeTab === 'sandbox' ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/20' : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          ☣️ 7. Malware Sandbox
        </button>

        <button
          onClick={() => setActiveTab('forensics')}
          className={`px-3 py-1.5 rounded font-mono text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer ${
            activeTab === 'forensics' ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/20' : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          📋 8. Incident Forensics
        </button>

        <button
          onClick={() => setActiveTab('reports')}
          className={`px-3 py-1.5 rounded font-mono text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer ${
            activeTab === 'reports' ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/20' : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          📥 9. Reports Engine
        </button>

        <button
          onClick={() => setActiveTab('jamming')}
          className={`px-3 py-1.5 rounded font-mono text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer ${
            activeTab === 'jamming' ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/20' : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          📡 10. RF Jamming
        </button>

        <button
          onClick={() => setActiveTab('ids')}
          className={`px-3 py-1.5 rounded font-mono text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer ${
            activeTab === 'ids' ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/20' : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          🛡️ 11. IDS Rules
        </button>

        <button
          onClick={() => setActiveTab('compliance')}
          className={`px-3 py-1.5 rounded font-mono text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer ${
            activeTab === 'compliance' ? 'bg-[#00f0ff]/15 text-[#00f0ff] border border-[#00f0ff]/20' : 'text-zinc-500 hover:text-zinc-300'
          }`}
        >
          🔒 NSA Compliance
        </button>
      </div>

      {/* Tab Contents */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          transition={{ duration: 0.15 }}
          className="bg-[#08080B] border border-white/5 rounded p-5 space-y-4"
        >
          {/* 3. Network Analysis */}
          {activeTab === 'network' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-xs text-white uppercase tracking-wider font-mono font-semibold">
                  🌐 Network Analysis & Ground Segment Scanner
                </h3>
                <p className="text-[10px] text-white/40 font-mono">
                  Map local networking pathways, active transponder gateways, and vulnerable service protocols.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 pt-2">
                <div className="md:col-span-4 space-y-3 font-mono text-xs">
                  <div className="bg-black/30 border border-white/5 p-4 rounded space-y-2">
                    <label className="text-[9px] text-white/30 uppercase block font-bold">Target IP / Gateway</label>
                    <input
                      type="text"
                      value={hostIp}
                      onChange={(e) => setHostIp(e.target.value)}
                      className="w-full bg-[#0C0C10] border border-white/5 p-2 rounded text-zinc-200 focus:outline-none focus:border-[#00f0ff]"
                    />
                    
                    <button
                      onClick={handleNetworkScan}
                      disabled={isScanning}
                      className="w-full mt-2.5 py-2 bg-[#00f0ff] text-black font-bold uppercase rounded hover:bg-[#00f0ff]/80 transition-all cursor-pointer flex items-center justify-center gap-1.5 text-[10px]"
                    >
                      {isScanning ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />} Run Gateway Scan
                    </button>
                  </div>
                </div>

                <div className="md:col-span-8 bg-black/40 border border-white/5 p-4 rounded h-64 overflow-y-auto font-mono text-[11px] text-cyan-400 space-y-1">
                  {scanOutput.length === 0 ? (
                    <span className="text-white/20 italic">Initialize Gateway scanning parameters above to begin.</span>
                  ) : (
                    scanOutput.map((l, i) => <div key={i}>{l}</div>)
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 5. Password Cracker */}
          {activeTab === 'pwd' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-xs text-white uppercase tracking-wider font-mono font-semibold">
                  🔑 Password Cracking & Recovery Tool
                </h3>
                <p className="text-[10px] text-white/40 font-mono">
                  Simulate GPU cracking dictionary sweeps over un-parameterized terminal database secrets.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 pt-2">
                <div className="md:col-span-4 space-y-3 font-mono text-xs">
                  <div className="bg-black/30 border border-white/5 p-4 rounded space-y-2">
                    <label className="text-[9px] text-white/30 uppercase block font-bold">SHA-256 target hash</label>
                    <input
                      type="text"
                      value={targetHash}
                      onChange={(e) => setTargetHash(e.target.value)}
                      className="w-full bg-[#0C0C10] border border-white/5 p-2 rounded text-zinc-200 focus:outline-none focus:border-[#00f0ff]"
                    />
                    
                    <button
                      onClick={handlePasswordCracking}
                      disabled={isCracking}
                      className="w-full mt-2.5 py-2 bg-[#00f0ff] text-black font-bold uppercase rounded hover:bg-[#00f0ff]/80 transition-all cursor-pointer flex items-center justify-center gap-1.5 text-[10px]"
                    >
                      {isCracking ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />} Recover Key
                    </button>
                  </div>
                </div>

                <div className="md:col-span-8 bg-black/40 border border-white/5 p-4 rounded h-64 overflow-y-auto font-mono text-[11px] text-cyan-400 space-y-1">
                  {crackOutput.length === 0 ? (
                    <span className="text-white/20 italic">Load target cryptographic hashes above to run dictionary permutation sweeps.</span>
                  ) : (
                    crackOutput.map((l, i) => <div key={i}>{l}</div>)
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 6. Social Engineering */}
          {activeTab === 'social' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-xs text-white uppercase tracking-wider font-mono font-semibold">
                  🎣 Social Engineering Campaign Simulator
                </h3>
                <p className="text-[10px] text-white/40 font-mono">
                  Simulate un-parameterized client credential-entry scenarios to test human compliance factors.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 pt-2">
                <div className="md:col-span-4 space-y-3 font-mono text-xs">
                  <div className="bg-black/30 border border-white/5 p-4 rounded space-y-3">
                    <div>
                      <label className="text-[9px] text-white/30 uppercase block font-bold mb-1">Campaign Template</label>
                      <select
                        value={templateType}
                        onChange={(e) => setTemplateType(e.target.value)}
                        className="w-full bg-[#0C0C10] border border-white/5 p-2 rounded text-zinc-300 focus:outline-none"
                      >
                        <option value="cisa_alert">CISA Satellite Urgency Alert</option>
                        <option value="firmware_update">Firmware Block Patch Required</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-[9px] text-white/30 uppercase block font-bold mb-1">Sender Mask ID</label>
                      <input
                        type="text"
                        value={senderField}
                        onChange={(e) => setSenderField(e.target.value)}
                        className="w-full bg-[#0C0C10] border border-white/5 p-2 rounded text-zinc-300 focus:outline-none"
                      />
                    </div>
                    
                    <button
                      onClick={handleSocialSim}
                      disabled={isSimulatingCampaign}
                      className="w-full py-2 bg-[#00f0ff] text-black font-bold uppercase rounded hover:bg-[#00f0ff]/80 transition-all cursor-pointer flex items-center justify-center gap-1.5 text-[10px]"
                    >
                      {isSimulatingCampaign ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />} Launch Phishing Sim
                    </button>
                  </div>
                </div>

                <div className="md:col-span-8 bg-black/40 border border-white/5 p-4 rounded h-64 overflow-y-auto font-mono text-[11px] text-cyan-400 space-y-1">
                  {campaignOutput.length === 0 ? (
                    <span className="text-white/20 italic">Select template blocks above to execute simulated vector loops.</span>
                  ) : (
                    campaignOutput.map((l, i) => <div key={i}>{l}</div>)
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 7. Malware Sandbox */}
          {activeTab === 'sandbox' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-xs text-white uppercase tracking-wider font-mono font-semibold">
                  ☣️ Malware Sandbox & Code Execution Monitor
                </h3>
                <p className="text-[10px] text-white/40 font-mono">
                  Safely test anomalous firmware code in closed sandboxed environments with active syscall diagnostics.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 pt-2">
                <div className="md:col-span-4 space-y-3 font-mono text-xs">
                  <div className="bg-black/30 border border-white/5 p-4 rounded space-y-2">
                    <label className="text-[9px] text-white/30 uppercase block font-bold">Target File Name</label>
                    <input
                      type="text"
                      value={sandboxFile}
                      onChange={(e) => setSandboxFile(e.target.value)}
                      className="w-full bg-[#0C0C10] border border-white/5 p-2 rounded text-zinc-200 focus:outline-none focus:border-[#00f0ff]"
                    />
                    
                    <button
                      onClick={handleMalwareSandbox}
                      disabled={isSandboxRunning}
                      className="w-full mt-2.5 py-2 bg-[#00f0ff] text-black font-bold uppercase rounded hover:bg-[#00f0ff]/80 transition-all cursor-pointer flex items-center justify-center gap-1.5 text-[10px]"
                    >
                      {isSandboxRunning ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />} Execute in Sandbox
                    </button>
                  </div>
                </div>

                <div className="md:col-span-8 bg-black/40 border border-white/5 p-4 rounded h-64 overflow-y-auto font-mono text-[11px] text-cyan-400 space-y-1">
                  {sandboxOutput.length === 0 ? (
                    <span className="text-white/20 italic">Submit suspicious binary targets above to safely trigger behavioral scanning.</span>
                  ) : (
                    sandboxOutput.map((l, i) => <div key={i}>{l}</div>)
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 8. Incident Forensics & 313-BIND Policy Remediation */}
          {activeTab === 'forensics' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-xs text-white uppercase tracking-wider font-mono font-semibold flex items-center gap-2">
                  📋 Incident Response, Forensics & 313-BIND Cryptographic Policy Ledger
                </h3>
                <p className="text-[10px] text-white/40 font-mono">
                  Execute 15-minute immediate containment, trace process tree exfiltrations, restore kernel eBPF rules, and bind unforgeable 313-BIND cryptographic timestamps.
                </p>
              </div>

              {/* 15-Min & 1-Hour Interactive Action Buttons */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                {/* 15-min Immediate Actions Panel */}
                <div className="bg-rose-950/20 border border-rose-500/30 p-3.5 rounded space-y-2.5">
                  <div className="flex justify-between items-center border-b border-rose-500/20 pb-1.5">
                    <span className="text-[10px] font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1">
                      <AlertTriangle size={12} /> Immediate 15-Min Actions
                    </span>
                    <span className="text-[9px] text-white/40 uppercase">High Priority</span>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={handleCheckSuidBash}
                      className={`p-2 rounded border text-[10px] uppercase font-bold transition-all cursor-pointer flex items-center justify-center gap-1 ${
                        suidBitCleared 
                          ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300' 
                          : 'bg-rose-900/40 border-rose-500/50 text-rose-200 hover:bg-rose-800/60'
                      }`}
                    >
                      {suidBitCleared ? '✓ SUID Stripped' : '1. chmod u-s /bin/bash'}
                    </button>

                    <button
                      onClick={handleAuditEbpfPolicy}
                      className="p-2 rounded bg-black/40 border border-white/10 hover:border-[#00f0ff] text-zinc-300 hover:text-[#00f0ff] text-[10px] uppercase font-bold transition-all cursor-pointer"
                    >
                      2. eBPF Policy Log
                    </button>

                    <button
                      onClick={handleVerifyShadowExfil}
                      className="p-2 rounded bg-black/40 border border-white/10 hover:border-[#00f0ff] text-zinc-300 hover:text-[#00f0ff] text-[10px] uppercase font-bold transition-all cursor-pointer"
                    >
                      3. /etc/shadow Exfil
                    </button>

                    <button
                      onClick={handleTracePPID725}
                      className="p-2 rounded bg-black/40 border border-white/10 hover:border-[#00f0ff] text-zinc-300 hover:text-[#00f0ff] text-[10px] uppercase font-bold transition-all cursor-pointer"
                    >
                      4. Verify PPID 725
                    </button>
                  </div>
                </div>

                {/* 1-Hour Hardening & Cryptographic Binding Panel */}
                <div className="bg-cyan-950/20 border border-cyan-500/30 p-3.5 rounded space-y-2.5">
                  <div className="flex justify-between items-center border-b border-cyan-500/20 pb-1.5">
                    <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1">
                      <Shield size={12} /> 1-Hour Hardening & 313-BIND
                    </span>
                    <span className="text-[9px] text-white/40 uppercase">Remediation</span>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={handleRestoreShadowRule}
                      className={`p-2 rounded border text-[10px] uppercase font-bold transition-all cursor-pointer flex items-center justify-center gap-1 ${
                        ebpfRuleRestored 
                          ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300' 
                          : 'bg-black/40 border-white/10 hover:border-[#00f0ff] text-zinc-300 hover:text-[#00f0ff]'
                      }`}
                    >
                      {ebpfRuleRestored ? '✓ eBPF Rule Restored' : '5. Restore /etc/shadow Rule'}
                    </button>

                    <button
                      onClick={handle313BindReceipt}
                      className={`p-2 rounded border text-[10px] uppercase font-bold transition-all cursor-pointer flex items-center justify-center gap-1 ${
                        bindReceiptData 
                          ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300' 
                          : 'bg-[#00f0ff]/20 border border-[#00f0ff]/50 text-[#00f0ff] hover:bg-[#00f0ff]/30'
                      }`}
                    >
                      {bindReceiptData ? '✓ 313-BIND Bound' : '6. 313-BIND Receipt'}
                    </button>

                    <button
                      onClick={handleDeleteUpxBinary}
                      className={`p-2 rounded border text-[10px] uppercase font-bold transition-all cursor-pointer flex items-center justify-center gap-1 ${
                        upxDeleted 
                          ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300' 
                          : 'bg-black/40 border-white/10 hover:border-rose-400 text-zinc-300 hover:text-rose-300'
                      }`}
                    >
                      {upxDeleted ? '✓ UPX Binary Deleted' : '8. Delete UPX Binary'}
                    </button>

                    <button
                      onClick={handleIncidentForensics}
                      disabled={isAnalyzingForensics}
                      className="p-2 rounded bg-black/40 border border-white/10 hover:border-[#00f0ff] text-zinc-300 hover:text-[#00f0ff] text-[10px] uppercase font-bold transition-all cursor-pointer flex items-center justify-center gap-1"
                    >
                      {isAnalyzingForensics ? <RefreshCw size={11} className="animate-spin" /> : <Play size={11} />} Auto-Correlate
                    </button>
                  </div>
                </div>
              </div>

              {/* 313-BIND Cryptographic Receipt Box */}
              {bindReceiptData && (
                <div className="bg-[#0C0C10] border border-[#00f0ff]/40 p-4 rounded space-y-2 font-mono text-xs">
                  <div className="flex justify-between items-center text-[10px] text-[#00f0ff] font-bold border-b border-[#00f0ff]/20 pb-1">
                    <span>🔐 313-BIND CRYPTOGRAPHIC POLICY RECEIPT</span>
                    <span className="text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/30">UNFORGEABLE TIMESTAMP BOUND</span>
                  </div>
                  <pre className="text-[10px] text-zinc-300 bg-black/60 p-3 rounded border border-white/5 overflow-x-auto leading-relaxed">
{JSON.stringify(bindReceiptData, null, 2)}
                  </pre>
                </div>
              )}

              {/* Live Forensics Output Terminal */}
              <div className="bg-black/40 border border-white/5 p-4 rounded h-64 overflow-y-auto font-mono text-[11px] text-cyan-400 space-y-1">
                {forensicsLog.map((l, i) => <div key={i}>{l}</div>)}
              </div>
            </div>
          )}

          {/* 9. Automated Reports Engine */}
          {activeTab === 'reports' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-xs text-white uppercase tracking-wider font-mono font-semibold">
                  📥 Automated Cyber-Range Reports Engine
                </h3>
                <p className="text-[10px] text-white/40 font-mono">
                  Instantly compile ground station compliance audits, technical telemetry metrics, and vulnerability logs.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 pt-2">
                <div className="md:col-span-4 space-y-3 font-mono text-xs">
                  <div className="bg-black/30 border border-white/5 p-4 rounded space-y-3">
                    <div>
                      <label className="text-[9px] text-white/30 uppercase block font-bold mb-1">Audit Template</label>
                      <select
                        value={selectedReportType}
                        onChange={(e) => setSelectedReportType(e.target.value)}
                        className="w-full bg-[#0C0C10] border border-white/5 p-2 rounded text-zinc-300 focus:outline-none"
                      >
                        <option value="pci_dss">PCI-DSS compliance</option>
                        <option value="nist_800">NIST SP 800-53 Ground Segment</option>
                        <option value="mitre_attck">MITRE ATT&CK Matrix Space</option>
                      </select>
                    </div>
                    
                    <button
                      onClick={handleAutomatedReport}
                      disabled={isCompilingReport}
                      className="w-full py-2 bg-[#00f0ff] text-black font-bold uppercase rounded hover:bg-[#00f0ff]/80 transition-all cursor-pointer flex items-center justify-center gap-1.5 text-[10px]"
                    >
                      {isCompilingReport ? <RefreshCw size={12} className="animate-spin" /> : <FileText size={12} />} Compile PDF/JSON Report
                    </button>
                  </div>
                </div>

                <div className="md:col-span-8 bg-black/40 border border-white/5 p-4 rounded h-64 overflow-y-auto font-mono text-[11px] text-cyan-400 whitespace-pre">
                  {isCompilingReport ? (
                    <div className="text-white/20 italic animate-pulse">Running document collation parameters... compiling reports.</div>
                  ) : compiledReport ? (
                    compiledReport
                  ) : (
                    <span className="text-white/20 italic">Select report standard templates above to compile.</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 10. RF Jamming */}
          {activeTab === 'jamming' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-xs text-white uppercase tracking-wider font-mono font-semibold">
                  📡 10. RF Jamming & Spectrum Jammer
                </h3>
                <p className="text-[10px] text-white/40 font-mono">
                  Transmit broad-spectrum noise profiles into satellite telemetry loops to model environmental interference.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 pt-2">
                <div className="md:col-span-4 space-y-3 font-mono text-xs">
                  <div className="bg-black/30 border border-white/5 p-4 rounded space-y-2">
                    <label className="text-[9px] text-white/30 uppercase block font-bold">Jamming Target Freq (GHz)</label>
                    <input
                      type="text"
                      value={jammingFreq}
                      onChange={(e) => setJammingFreq(e.target.value)}
                      className="w-full bg-[#0C0C10] border border-white/5 p-2 rounded text-zinc-200 focus:outline-none focus:border-[#00f0ff]"
                    />
                    
                    <button
                      onClick={handleRFJamming}
                      disabled={isJamming}
                      className="w-full mt-2.5 py-2 bg-rose-500 hover:bg-rose-600 text-white font-bold uppercase rounded transition-all cursor-pointer flex items-center justify-center gap-1.5 text-[10px]"
                    >
                      {isJamming ? <RefreshCw size={12} className="animate-spin" /> : <Play size={12} />} Inject Jamming Carrier
                    </button>
                  </div>
                </div>

                <div className="md:col-span-8 bg-black/40 border border-white/5 p-4 rounded h-64 overflow-y-auto font-mono text-[11px] text-cyan-400 space-y-1">
                  {jammingOutput.length === 0 ? (
                    <span className="text-white/20 italic">Provide L-band tracking frequency targets to initiate jamming.</span>
                  ) : (
                    jammingOutput.map((l, i) => <div key={i}>{l}</div>)
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 11. IDS Rules */}
          {activeTab === 'ids' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-xs text-white uppercase tracking-wider font-mono font-semibold">
                  🛡️ 11. IDS Rules & Correlation Engine
                </h3>
                <p className="text-[10px] text-white/40 font-mono">
                  Modify Snort/Suricata rules to block malicious system calls, SNMP probes, or out-of-bounds TFTP patches.
                </p>
              </div>

              <div className="space-y-3 pt-2 font-mono text-xs">
                <div className="bg-black/30 border border-white/5 p-4 rounded space-y-2">
                  <label className="text-[9px] text-white/30 uppercase block font-bold">Suricata ruleset configuration</label>
                  <textarea
                    value={idsRules}
                    onChange={(e) => setIdsRules(e.target.value)}
                    rows={4}
                    className="w-full bg-[#0C0C10] border border-white/5 p-2.5 rounded text-zinc-300 font-mono text-[11px] focus:outline-none focus:border-[#00f0ff] resize-none"
                  />
                  
                  <button
                    onClick={() => {
                      triggerToast('🛡️ Suricata IDS rules updated successfully.');
                    }}
                    className="px-4 py-2 bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 border border-[#00f0ff]/30 text-[#00f0ff] font-bold uppercase rounded transition-all cursor-pointer text-[10px]"
                  >
                    Apply Rules to Ground Receiver
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* 12. NSA Compliance */}
          {activeTab === 'compliance' && (
            <div className="space-y-4">
              <div className="space-y-1">
                <h3 className="text-xs text-white uppercase tracking-wider font-mono font-semibold">
                  🔒 NSA Ground-Station Security Compliance & Hardening Check
                </h3>
                <p className="text-[10px] text-white/40 font-mono">
                  Verifies configuration bounds matching real-world space telemetry transport frameworks.
                </p>
              </div>

              <div className="bg-black/30 border border-white/5 p-4 rounded space-y-4 font-mono text-xs">
                <div className="flex justify-between items-center pb-2 border-b border-white/5">
                  <span className="text-[10px] text-white/40 uppercase font-bold">Audit Param</span>
                  <span className="text-[10px] text-white/40 uppercase font-bold">Fidelity State</span>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-zinc-400">NSA-HARDENING-01 (SNMPv3 Access Controls)</span>
                    <span className="text-emerald-400 font-bold">COMPLIANT (100%)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-400">NSA-HARDENING-02 (Secure HTTPS Enforcer Loop)</span>
                    <span className="text-emerald-400 font-bold">COMPLIANT (100%)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-400">NSA-HARDENING-03 (VLAN Segmentation Gateway)</span>
                    <span className="text-emerald-400 font-bold">COMPLIANT (100%)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-zinc-400">NSA-HARDENING-04 (Firmware Block Signature Checks)</span>
                    <span className="text-emerald-400 font-bold">COMPLIANT (100%)</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-white/5 flex justify-between items-center">
                  <span className="text-[10px] text-[#00f0ff] font-bold">TOTAL SUITE COMPLIANCE:</span>
                  <span className="text-emerald-400 font-bold text-sm">100% SECURE</span>
                </div>
              </div>
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
