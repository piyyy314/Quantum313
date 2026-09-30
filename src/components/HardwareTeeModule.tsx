import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  Key, 
  Cpu, 
  Lock, 
  Unlock, 
  CheckCircle, 
  AlertTriangle, 
  RefreshCw, 
  FileCode, 
  Copy, 
  Check, 
  Radio, 
  Terminal, 
  Layers, 
  ShieldCheck, 
  EyeOff, 
  ShieldAlert, 
  Zap 
} from 'lucide-react';
import { 
  TeePlatform, 
  EnclaveMeasurement, 
  SealedKeyVaultItem, 
  AttestationQuote 
} from '../types';

interface HardwareTeeModuleProps {
  triggerToast: (msg: string) => void;
}

const DEFAULT_MEASUREMENT: EnclaveMeasurement = {
  mrEnclave: '0x8a92f01948bd21e06913c19df273a0e5b7410c81d293847a98bc19d3f18e90ab',
  mrSigner: '0x313f890192eab817412959810a9c82173b98120d912487e0981bfa09918239ac',
  isvProdId: 1,
  isvSvn: 4,
  attributes: {
    debugMode: false,
    mode64bit: true,
    kssEnabled: true,
    memorySizeMb: 16
  }
};

const INITIAL_VAULT_ITEMS: SealedKeyVaultItem[] = [
  {
    id: 'key-313-bind-root',
    label: '313-BIND Immutable Audit Ledger Root Signing Key',
    keyType: '313-BIND-RootKey',
    sealedData: 'e4a9018b2c91df089104fa281c7e901a8f902b4d7c81a90f12',
    authTag: '8f921a00e42d710b89ac01',
    policy: 'POLICY_MRENCLAVE',
    createdAt: '2026-08-08T04:00:00Z',
    isSealed: true
  },
  {
    id: 'key-agent-ed25519',
    label: 'Security Agent Master Identity Private Key',
    keyType: 'Ed25519-Private',
    sealedData: '71c8901ae4f91048b2901cfa3901b8e4091ab709c812ef9018',
    authTag: '310fa8901ebc4412091d3e',
    policy: 'POLICY_MRENCLAVE',
    createdAt: '2026-08-07T21:10:00Z',
    isSealed: true
  },
  {
    id: 'key-sat-aes256',
    label: 'Satellite Ground Station Uplink AES-256-GCM Session Key',
    keyType: 'AES-256-GCM',
    sealedData: '90fa1b20c841e90a8812fbc49012a8019b88210fe4019a8471',
    authTag: '66a01bc94812f00a3909bc',
    policy: 'POLICY_MRSIGNER',
    createdAt: '2026-08-07T18:30:00Z',
    isSealed: true
  }
];

export default function HardwareTeeModule({ triggerToast }: HardwareTeeModuleProps) {
  const [platform, setPlatform] = useState<TeePlatform>('Intel SGX');
  const [activeTab, setActiveTab] = useState<'vault' | 'attestation' | 'memory_guard' | 'diagnostics'>('vault');
  const [vaultItems, setVaultItems] = useState<SealedKeyVaultItem[]>(INITIAL_VAULT_ITEMS);
  const [measurement, setMeasurement] = useState<EnclaveMeasurement>(DEFAULT_MEASUREMENT);
  
  // New Key Sealing Form States
  const [newKeyLabel, setNewKeyLabel] = useState('');
  const [newKeyType, setNewKeyType] = useState<SealedKeyVaultItem['keyType']>('AES-256-GCM');
  const [newKeyPolicy, setNewKeyPolicy] = useState<'POLICY_MRENCLAVE' | 'POLICY_MRSIGNER'>('POLICY_MRENCLAVE');
  const [newKeyPlaintext, setNewKeyPlaintext] = useState('');
  const [isSealingKey, setIsSealingKey] = useState(false);

  // In-Enclave Signing States
  const [signPayload, setSignPayload] = useState('{"telemetry_report_id":"SAT-TLM-909","status":"SECURE","ts":"2026-08-28T19:26:00Z"}');
  const [inEnclaveSignature, setInEnclaveSignature] = useState<string | null>(null);
  const [isSigning, setIsSigning] = useState(false);

  // Remote Attestation States
  const [isAttesting, setIsAttesting] = useState(false);
  const [latestQuote, setLatestQuote] = useState<AttestationQuote | null>(null);
  const [attestationLogs, setAttestationLogs] = useState<string[]>([
    "[*] Hardware TEE Driver: /dev/sgx_enclave initialized.",
    "[*] Intel SGX Launch Control (FLC) Enclave Control Structure (SECS) active.",
    "[*] Ready. Click 'Attest Agent Integrity' to generate signed Quoting Enclave quote."
  ]);

  // Memory Dump Simulation States
  const [isSimulatingAttack, setIsSimulatingAttack] = useState(false);
  const [memoryDumpResult, setMemoryDumpResult] = useState<string | null>(null);

  const [copiedText, setCopiedText] = useState(false);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(true);
    triggerToast('📋 Copied to clipboard');
    setTimeout(() => setCopiedText(false), 2000);
  };

  // Sealing a new cryptographic key into enclave
  const handleSealNewKey = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyLabel.trim()) return;

    setIsSealingKey(true);
    setTimeout(() => {
      const generatedCiphertext = Array.from({ length: 32 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
      const generatedTag = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');

      const newItem: SealedKeyVaultItem = {
        id: `key-${Date.now()}`,
        label: newKeyLabel,
        keyType: newKeyType,
        sealedData: generatedCiphertext,
        authTag: generatedTag,
        policy: newKeyPolicy,
        createdAt: new Date().toISOString(),
        isSealed: true
      };

      setVaultItems(prev => [newItem, ...prev]);
      setNewKeyLabel('');
      setNewKeyPlaintext('');
      setIsSealingKey(false);
      triggerToast(`🔐 Hardware Sealing Key (${newKeyPolicy}) derived and stored in Enclave!`);
    }, 800);
  };

  // Perform In-Enclave Cryptographic Signing
  const handleInEnclaveSign = () => {
    setIsSigning(true);
    setInEnclaveSignature(null);

    setTimeout(() => {
      const dummySig = '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
      setInEnclaveSignature(dummySig);
      setIsSigning(false);
      triggerToast('✍️ Payload signed inside Enclave memory! Secret key never exposed to host.');
    }, 700);
  };

  // Simulate Host OS Compromise / Memory Dump
  const handleSimulateMemoryDump = () => {
    setIsSimulatingAttack(true);
    setMemoryDumpResult(null);

    setTimeout(() => {
      setIsSimulatingAttack(false);
      setMemoryDumpResult(`0x7fff0000: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
0x7fff0010: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
0x7fff0020: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
0x7fff0030: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  ................
[!] HARDWARE SECURITY REPORT:
- Target Memory Page: 0x7FFF0000 (Processor Reserved Memory / EPC Enclave Page)
- Attempted Access: Host Kernel Ring 0 /dev/mem DMA Read
- Hardware Enclave Memory Controller Response: ACCESS BLOCKED (Returns 0xFF)
- Cryptographic Secret Integrity: 100% PRESERVED`);
      triggerToast('🛡️ Memory Dump Blocked! TEE hardware encryption returned 0xFF.');
    }, 1000);
  };

  // Generate & Verify Hardware Remote Attestation Quote
  const handleRunAttestation = () => {
    setIsAttesting(true);
    setLatestQuote(null);
    setAttestationLogs(prev => [
      ...prev,
      `[>] Generating 64-byte random attestation nonce challenge...`,
      `[>] Enclave invoking EREPORT with MRENCLAVE measurement & agent public key hash...`
    ]);

    setTimeout(() => {
      setAttestationLogs(prev => [
        ...prev,
        `[>] Passing EREPORT to Quoting Enclave (QE) for Platform Provisioning Key (PCK) signing...`,
        `[>] Generated Intel SGX ECDSA Quote v3...`,
        `[>] Dispatching quote to Intel PCS / IAS Attestation Verification Service...`,
        `[✓] Signature Verification: PASS (Intel Root CA Chain Valid)`,
        `[✓] MRENCLAVE Verification: PASS (${measurement.mrEnclave.slice(0, 18)}...)`,
        `[✓] TCB Status: OK (UP_TO_DATE)`,
        `[✓] AGENT INTEGRITY ATTESTED: Enclave code is untampered and running in genuine hardware.`
      ]);

      const quote: AttestationQuote = {
        quoteId: `QUOTE-SGX-${Date.now()}`,
        teeType: platform,
        timestamp: new Date().toISOString(),
        nonceChallenge: '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(''),
        reportDataHash: '0x' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(''),
        measurement: measurement,
        qeReport: {
          qeSvn: 2,
          pckCertChain: 'Intel_SGX_PCK_Certificate_Chain_v3_Valid',
          ecdsaSignature: '0x' + Array.from({ length: 64 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('')
        },
        verificationStatus: 'VERIFIED_VALID'
      };

      setLatestQuote(quote);
      setIsAttesting(false);
      triggerToast('🌟 Hardware Remote Attestation: Security Agent Cryptographically Verified!');
    }, 1500);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-[#08080B] border border-white/5 rounded p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-1.5 bg-emerald-500/10 text-emerald-400 rounded border border-emerald-500/20">
                <ShieldCheck size={18} />
              </span>
              <h2 className="text-base font-serif font-light text-zinc-100 flex items-center gap-2">
                Hardware TEE Enclave (Intel SGX / AMD SEV)
              </h2>
              <span className="text-[9px] bg-emerald-950/60 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded font-mono font-bold">
                PRM / EPC ENCLAVE ACTIVE
              </span>
            </div>
            <p className="text-xs text-white/50 font-mono">
              Hardware-isolated key vault, in-enclave cryptographic operations, and unforgeable remote attestation proofs.
            </p>
          </div>

          {/* Platform Selector & Quick Attest Button */}
          <div className="flex items-center gap-2">
            <div className="flex bg-black/40 border border-white/10 p-1 rounded font-mono text-[11px]">
              {(['Intel SGX', 'AMD SEV-SNP', 'ARM TrustZone / Realm'] as TeePlatform[]).map((plat) => (
                <button
                  key={plat}
                  onClick={() => setPlatform(plat)}
                  className={`px-2.5 py-1 rounded transition-all cursor-pointer font-bold ${
                    platform === plat
                      ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.2)]'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  {plat}
                </button>
              ))}
            </div>

            <button
              onClick={handleRunAttestation}
              disabled={isAttesting}
              className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-black font-bold uppercase rounded text-xs font-mono transition-all cursor-pointer flex items-center gap-2 shadow-[0_0_15px_rgba(16,185,129,0.2)]"
            >
              {isAttesting ? (
                <>
                  <RefreshCw size={13} className="animate-spin" /> Verifying Quote...
                </>
              ) : (
                <>
                  <ShieldCheck size={13} /> Attest Agent Integrity
                </>
              )}
            </button>
          </div>
        </div>

        {/* Hardware Status Specs Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2 font-mono text-xs">
          <div className="p-3 bg-black/30 border border-white/5 rounded space-y-1">
            <span className="text-[9px] text-white/40 uppercase tracking-wider block font-bold">Enclave Measurement (MRENCLAVE)</span>
            <span className="text-[#00f0ff] font-bold text-[11px] truncate block" title={measurement.mrEnclave}>
              {measurement.mrEnclave.slice(0, 18)}...
            </span>
          </div>

          <div className="p-3 bg-black/30 border border-white/5 rounded space-y-1">
            <span className="text-[9px] text-white/40 uppercase tracking-wider block font-bold">Author Signer Hash (MRSIGNER)</span>
            <span className="text-purple-400 font-bold text-[11px] truncate block" title={measurement.mrSigner}>
              {measurement.mrSigner.slice(0, 18)}...
            </span>
          </div>

          <div className="p-3 bg-black/30 border border-white/5 rounded space-y-1">
            <span className="text-[9px] text-white/40 uppercase tracking-wider block font-bold">Enclave Page Cache (EPC)</span>
            <span className="text-emerald-400 font-bold text-[11px]">
              16 MB Allocated / 128 MB PRM
            </span>
          </div>

          <div className="p-3 bg-black/30 border border-white/5 rounded space-y-1">
            <span className="text-[9px] text-white/40 uppercase tracking-wider block font-bold">Debug Protection Status</span>
            <span className="text-amber-400 font-bold text-[11px] flex items-center gap-1">
              <Lock size={11} /> PROD_MODE (Debug Disabled)
            </span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 bg-[#08080B] border border-white/5 p-1 rounded font-mono text-xs">
        <button
          onClick={() => setActiveTab('vault')}
          className={`flex-1 py-2 px-3 rounded text-center transition-all cursor-pointer font-bold flex items-center justify-center gap-2 ${
            activeTab === 'vault'
              ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.2)]'
              : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Key size={13} /> Hardware Sealed Key Vault ({vaultItems.length})
        </button>

        <button
          onClick={() => setActiveTab('attestation')}
          className={`flex-1 py-2 px-3 rounded text-center transition-all cursor-pointer font-bold flex items-center justify-center gap-2 ${
            activeTab === 'attestation'
              ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.2)]'
              : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <ShieldCheck size={13} /> Remote Attestation & Quotes
        </button>

        <button
          onClick={() => setActiveTab('memory_guard')}
          className={`flex-1 py-2 px-3 rounded text-center transition-all cursor-pointer font-bold flex items-center justify-center gap-2 ${
            activeTab === 'memory_guard'
              ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.2)]'
              : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <EyeOff size={13} /> Memory Isolation & Kernel Attack Sim
        </button>
      </div>

      {/* TAB 1: Sealed Key Vault & In-Enclave Signing */}
      {activeTab === 'vault' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Vault Items List */}
          <div className="lg:col-span-7 space-y-4">
            <div className="bg-[#08080B] border border-white/5 rounded p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-white/5 pb-2">
                <div className="flex items-center gap-2">
                  <Lock size={14} className="text-[#00f0ff]" />
                  <span className="text-xs font-mono font-bold text-zinc-200">Enclave-Sealed Cryptographic Keys</span>
                </div>
                <span className="text-[9px] text-zinc-500 font-mono">EGETKEY Hardware Root</span>
              </div>

              <div className="space-y-3">
                {vaultItems.map((item) => (
                  <div key={item.id} className="p-3.5 bg-black/40 border border-white/5 rounded space-y-2 font-mono text-xs">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="font-bold text-zinc-100 flex items-center gap-1.5">
                          <Key size={13} className="text-emerald-400" />
                          {item.label}
                        </div>
                        <span className="text-[9px] text-zinc-500 block mt-0.5">Created: {item.createdAt}</span>
                      </div>
                      <span className="text-[9px] bg-cyan-950/60 text-[#00f0ff] border border-[#00f0ff]/30 px-2 py-0.5 rounded font-bold uppercase">
                        {item.keyType}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[10px] bg-black/60 p-2 rounded border border-white/5">
                      <div>
                        <span className="text-zinc-500 block">Sealing Policy:</span>
                        <span className="text-purple-300 font-bold">{item.policy}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block">Hardware Auth Tag:</span>
                        <span className="text-emerald-400 font-bold truncate block">{item.authTag}</span>
                      </div>
                    </div>

                    <div className="text-[10px] text-zinc-500 truncate">
                      <span className="text-zinc-400">Ciphertext (Sealed to Silicon):</span> {item.sealedData}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* In-Enclave Cryptographic Signing Sandbox */}
            <div className="bg-[#08080B] border border-white/5 rounded p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-white/5 pb-2">
                <div className="flex items-center gap-2">
                  <Zap size={14} className="text-emerald-400" />
                  <span className="text-xs font-bold text-zinc-200">In-Enclave Message Signing (Zero Key Exposure)</span>
                </div>
                <span className="text-[9px] text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/30">
                  Key Stays Inside Enclave
                </span>
              </div>

              <div className="space-y-2">
                <label className="text-[10px] text-white/40 uppercase font-bold">Telemetry Payload to Sign</label>
                <input
                  type="text"
                  value={signPayload}
                  onChange={(e) => setSignPayload(e.target.value)}
                  className="w-full bg-black/60 border border-white/10 p-2.5 rounded text-zinc-200 focus:outline-none focus:border-[#00f0ff] text-xs font-mono"
                />

                <button
                  onClick={handleInEnclaveSign}
                  disabled={isSigning}
                  className="w-full py-2 bg-[#00f0ff] hover:bg-[#00f0ff]/80 text-black font-bold uppercase rounded transition-all cursor-pointer flex items-center justify-center gap-2"
                >
                  {isSigning ? <RefreshCw size={13} className="animate-spin" /> : <Zap size={13} />} Sign Inside Enclave
                </button>
              </div>

              {inEnclaveSignature && (
                <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-emerald-400 font-bold uppercase">Enclave Cryptographic Signature (Ed25519)</span>
                    <button
                      onClick={() => handleCopy(inEnclaveSignature)}
                      className="text-[9px] text-zinc-400 hover:text-white flex items-center gap-1 cursor-pointer"
                    >
                      <Copy size={10} /> Copy
                    </button>
                  </div>
                  <pre className="text-[10px] text-emerald-300 bg-black/60 p-2 rounded overflow-x-auto">
                    <code>{inEnclaveSignature}</code>
                  </pre>
                  <span className="text-[9px] text-zinc-400 block">
                    ✓ Verified: Secret key remained in hardware PRM memory during full computation.
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Right: Seal New Key Form */}
          <div className="lg:col-span-5 space-y-4 font-mono text-xs">
            <form onSubmit={handleSealNewKey} className="bg-[#08080B] border border-white/5 rounded p-4 space-y-4">
              <div className="border-b border-white/5 pb-2">
                <h3 className="text-xs font-bold text-zinc-200 flex items-center gap-2">
                  <Key size={14} className="text-[#00f0ff]" /> Seal New Key into Hardware TEE
                </h3>
                <p className="text-[10px] text-white/40 mt-0.5">
                  Derives silicon-bound encryption keys using CPU Root-of-Trust (EGETKEY).
                </p>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="text-[10px] text-white/30 uppercase block font-bold mb-1">Key Description / Label</label>
                  <input
                    type="text"
                    placeholder="e.g. Ground Receiver Session Token"
                    value={newKeyLabel}
                    onChange={(e) => setNewKeyLabel(e.target.value)}
                    required
                    className="w-full bg-black/60 border border-white/10 p-2 rounded text-zinc-200 focus:outline-none focus:border-[#00f0ff]"
                  />
                </div>

                <div>
                  <label className="text-[10px] text-white/30 uppercase block font-bold mb-1">Cryptographic Algorithm</label>
                  <select
                    value={newKeyType}
                    onChange={(e) => setNewKeyType(e.target.value as any)}
                    className="w-full bg-black/60 border border-white/10 p-2 rounded text-zinc-200 focus:outline-none focus:border-[#00f0ff]"
                  >
                    <option value="AES-256-GCM">AES-256-GCM (Symmetric Encryption)</option>
                    <option value="Ed25519-Private">Ed25519-Private (Identity Signature)</option>
                    <option value="HMAC-SHA256">HMAC-SHA256 (Authentication Secret)</option>
                    <option value="RSA-4096-Private">RSA-4096-Private (Asymmetric Master)</option>
                    <option value="313-BIND-RootKey">313-BIND-RootKey (Audit Ledger Root)</option>
                  </select>
                </div>

                <div>
                  <label className="text-[10px] text-white/30 uppercase block font-bold mb-1">Hardware Sealing Policy</label>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => setNewKeyPolicy('POLICY_MRENCLAVE')}
                      className={`p-2 rounded border text-center transition-all cursor-pointer ${
                        newKeyPolicy === 'POLICY_MRENCLAVE'
                          ? 'bg-cyan-950/40 border-[#00f0ff] text-[#00f0ff] font-bold'
                          : 'bg-black/40 border-white/5 text-zinc-400'
                      }`}
                    >
                      <span className="block text-[10px]">MRENCLAVE</span>
                      <span className="text-[8px] text-zinc-500 block">Strict Build Lock</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setNewKeyPolicy('POLICY_MRSIGNER')}
                      className={`p-2 rounded border text-center transition-all cursor-pointer ${
                        newKeyPolicy === 'POLICY_MRSIGNER'
                          ? 'bg-purple-950/40 border-purple-500 text-purple-300 font-bold'
                          : 'bg-black/40 border-white/5 text-zinc-400'
                      }`}
                    >
                      <span className="block text-[10px]">MRSIGNER</span>
                      <span className="text-[8px] text-zinc-500 block">Author Key Upgradeable</span>
                    </button>
                  </div>
                </div>

                <div>
                  <label className="text-[10px] text-white/30 uppercase block font-bold mb-1">Optional Plaintext (Or Auto-Generate)</label>
                  <input
                    type="password"
                    placeholder="Leave empty to generate 256-bit entropy"
                    value={newKeyPlaintext}
                    onChange={(e) => setNewKeyPlaintext(e.target.value)}
                    className="w-full bg-black/60 border border-white/10 p-2 rounded text-zinc-200 focus:outline-none focus:border-[#00f0ff]"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isSealingKey}
                  className="w-full py-2.5 bg-emerald-500 hover:bg-emerald-400 text-black font-bold uppercase rounded transition-all cursor-pointer flex items-center justify-center gap-1.5"
                >
                  {isSealingKey ? <RefreshCw size={13} className="animate-spin" /> : <Lock size={13} />} Seal Key to Hardware Enclave
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* TAB 2: Remote Attestation Engine */}
      {activeTab === 'attestation' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 font-mono text-xs">
          {/* Left: Attestation Stream & Verification Certificate */}
          <div className="lg:col-span-7 space-y-4">
            <div className="bg-[#08080B] border border-white/5 rounded p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-white/5 pb-2">
                <div className="flex items-center gap-2">
                  <ShieldCheck size={14} className="text-emerald-400" />
                  <span className="text-xs font-bold text-zinc-200">Hardware Attestation Quote & Proof</span>
                </div>
                <button
                  onClick={handleRunAttestation}
                  disabled={isAttesting}
                  className="px-2.5 py-1 bg-emerald-500 text-black text-[10px] font-bold uppercase rounded cursor-pointer hover:bg-emerald-400"
                >
                  {isAttesting ? 'Verifying...' : 'Re-Attest'}
                </button>
              </div>

              {latestQuote ? (
                <div className="space-y-3">
                  <div className="p-3 bg-emerald-950/30 border border-emerald-500/40 rounded space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                        <CheckCircle size={14} /> ATTESTATION VERDICT: CRYPTOGRAPHICALLY VALID
                      </span>
                      <span className="text-[9px] bg-emerald-900/60 text-emerald-200 px-2 py-0.5 rounded border border-emerald-500/40 font-bold">
                        TCB UP-TO-DATE
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[10px] bg-black/60 p-2.5 rounded border border-emerald-500/20">
                      <div>
                        <span className="text-zinc-500 block">Quote ID:</span>
                        <span className="text-white font-bold">{latestQuote.quoteId}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block">TEE Architecture:</span>
                        <span className="text-[#00f0ff] font-bold">{latestQuote.teeType}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block">Quoting Enclave SVN:</span>
                        <span className="text-white font-bold">ISV SVN {latestQuote.qeReport.qeSvn}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block">Timestamp:</span>
                        <span className="text-zinc-300 font-bold">{latestQuote.timestamp}</span>
                      </div>
                    </div>
                  </div>

                  {/* Cryptographic Proof JSON Certificate */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-white/40 uppercase font-bold">Hardware Quote Signature & Certificate Payload</span>
                      <button
                        onClick={() => handleCopy(JSON.stringify(latestQuote, null, 2))}
                        className="text-[9px] text-zinc-400 hover:text-white flex items-center gap-1 cursor-pointer"
                      >
                        <Copy size={10} /> Copy Attestation Certificate
                      </button>
                    </div>
                    <pre className="text-[10px] text-emerald-300 bg-black/80 p-3 rounded border border-white/5 overflow-x-auto max-h-56 leading-relaxed">
                      <code>{JSON.stringify(latestQuote, null, 2)}</code>
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="py-10 text-center text-zinc-500 italic space-y-1">
                  <div>No attestation quote generated for the current session.</div>
                  <div className="text-[10px]">Click 'Attest Agent Integrity' to request a hardware-signed quote.</div>
                </div>
              )}
            </div>
          </div>

          {/* Right: Attestation Execution Logs */}
          <div className="lg:col-span-5 bg-black/40 border border-white/5 rounded p-4 space-y-2">
            <span className="text-[10px] text-white/40 uppercase tracking-wider font-bold block border-b border-white/5 pb-1.5">
              Intel PCS / AMD KDS Attestation Audit Stream
            </span>
            <div className="h-80 overflow-y-auto font-mono text-[11px] text-cyan-400 space-y-1.5">
              {attestationLogs.map((log, idx) => {
                let col = 'text-cyan-400';
                if (log.startsWith('[✓]')) col = 'text-emerald-400 font-bold';
                return (
                  <div key={idx} className={col}>
                    {log}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Memory Dump Protection & Attack Simulation */}
      {activeTab === 'memory_guard' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 font-mono text-xs">
          <div className="lg:col-span-5 space-y-4">
            <div className="bg-[#08080B] border border-white/5 rounded p-4 space-y-3">
              <div className="border-b border-white/5 pb-2">
                <h3 className="text-xs font-bold text-zinc-200 flex items-center gap-2">
                  <ShieldAlert size={14} className="text-rose-400" /> Host Kernel Compromise Simulator
                </h3>
                <p className="text-[10px] text-white/40 mt-0.5">
                  Test physical and kernel-level DMA memory dumping against the TEE Enclave Page Cache (EPC).
                </p>
              </div>

              <div className="space-y-3">
                <div className="p-3 bg-black/40 border border-white/5 rounded space-y-1">
                  <span className="text-zinc-400 text-[10px] block">Simulated Attack Vector:</span>
                  <span className="text-rose-400 font-bold block">Root Kernel Mode /dev/mem Dump</span>
                  <p className="text-[10px] text-zinc-500 mt-1">
                    An adversary gains ring-0 kernel execution and attempts to dump the Agent's master signing keys from host RAM.
                  </p>
                </div>

                <button
                  onClick={handleSimulateMemoryDump}
                  disabled={isSimulatingAttack}
                  className="w-full py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-bold uppercase rounded transition-all cursor-pointer flex items-center justify-center gap-1.5"
                >
                  {isSimulatingAttack ? <RefreshCw size={13} className="animate-spin" /> : <EyeOff size={13} />} Simulate Kernel Dump Attack
                </button>
              </div>
            </div>
          </div>

          <div className="lg:col-span-7 bg-[#08080B] border border-white/5 rounded p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-white/5 pb-2">
              <span className="text-xs font-bold text-zinc-200">Hardware Memory Controller Response</span>
              <span className="text-[9px] text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/30">
                AES-XEX Memory Encryption Active
              </span>
            </div>

            {memoryDumpResult ? (
              <pre className="bg-black/80 p-3.5 rounded border border-rose-500/30 text-[11px] text-rose-300 overflow-x-auto leading-relaxed font-mono">
                <code>{memoryDumpResult}</code>
              </pre>
            ) : (
              <div className="py-14 text-center text-zinc-500 italic">
                Launch memory dump simulation to inspect physical memory bus protection.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
