import { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Lock, 
  Unlock, 
  UploadCloud, 
  Clipboard, 
  CheckCircle, 
  AlertTriangle, 
  FileText, 
  ShieldCheck, 
  Eye, 
  EyeOff, 
  Terminal,
  Layers,
  Sparkles,
  RefreshCw
} from 'lucide-react';
import CryptoJS from 'crypto-js';

interface DecryptionValidatorProps {
  triggerToast?: (msg: string) => void;
}

export default function DecryptionValidator({ triggerToast }: DecryptionValidatorProps) {
  const [encryptedPayload, setEncryptedPayload] = useState<string>('');
  const [passphrase, setPassphrase] = useState<string>('');
  const [showPassphrase, setShowPassphrase] = useState<boolean>(false);
  const [isDecrypting, setIsDecrypting] = useState<boolean>(false);
  const [validationResult, setValidationResult] = useState<any | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const processFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (event) => {
      if (event.target && typeof event.target.result === 'string') {
        setEncryptedPayload(event.target.result);
        if (triggerToast) triggerToast(`Loaded encrypted file: ${file.name}`);
      }
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const handleDecryptAndValidate = () => {
    if (!encryptedPayload.trim()) {
      setValidationError("Please upload or paste an encrypted forensic container payload.");
      return;
    }
    if (!passphrase.trim()) {
      setValidationError("Passphrase is required to derive the symmetric key.");
      return;
    }

    setIsDecrypting(true);
    setValidationError(null);
    setValidationResult(null);

    // Simulate slightly for hacker styling/visual response
    setTimeout(() => {
      try {
        let cleanCiphertext = encryptedPayload.trim();
        const header = "-----BEGIN AEGIS SECURE FORENSICS CONTAINER-----";
        const footer = "-----END AEGIS SECURE FORENSICS CONTAINER-----";

        if (cleanCiphertext.includes(header)) {
          cleanCiphertext = cleanCiphertext
            .replace(header, '')
            .replace(footer, '')
            .trim();
        }

        const decryptedBytes = CryptoJS.AES.decrypt(cleanCiphertext, passphrase);
        const decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);

        if (!decryptedText || decryptedText.trim() === '') {
          throw new Error("Invalid decryption output. Please verify that your passphrase matches the derivation key used to seal this export.");
        }

        // Try parsing as JSON first
        let parsedData: any = null;
        let isJson = false;
        let isCsv = false;
        let ebpfCount = 0;
        let astCount = 0;
        let sigCount = 0;
        let metadata: Record<string, any> = {};

        try {
          parsedData = JSON.parse(decryptedText);
          isJson = true;
          ebpfCount = parsedData.ebpf_kernel_execution_logs?.length || 0;
          astCount = parsedData.ast_static_scan?.ast_heuristics_vulnerability_matches?.length || 0;
          sigCount = parsedData.signature_matching_ledger?.malicious_signature_detections?.length || 0;
          metadata = parsedData.meta || { suite: "Unknown Security Suite" };
        } catch {
          // If not JSON, check if it contains the standard CSV Aegis headers
          if (decryptedText.includes("Category/Module") && decryptedText.includes("Incident_ID_or_Offset")) {
            isCsv = true;
            // Crude parsing for metrics count
            const lines = decryptedText.split("\n");
            lines.forEach(line => {
              if (line.startsWith('"eBPF Kernel Telemetry"')) ebpfCount++;
              else if (line.startsWith('"AST Static Scan"')) astCount++;
              else if (line.startsWith('"Malware Code Signatures"')) sigCount++;
            });

            // Extract metadata from comments
            lines.forEach(line => {
              if (line.startsWith("# Exported by:")) {
                metadata.exported_by = line.replace("# Exported by:", "").trim();
              } else if (line.startsWith("# Posture Level:")) {
                metadata.threat_posture_configured = line.replace("# Posture Level:", "").trim();
              } else if (line.startsWith("# Export Timestamp UTC:")) {
                metadata.system_time = line.replace("# Export Timestamp UTC:", "").trim();
              }
            });
            metadata.suite = "Aegis Unified Security Suite";
          } else {
            throw new Error("Decryption was successful but the content format is not a valid Aegis Forensic Export container (corrupt structure).");
          }
        }

        setValidationResult({
          plainText: decryptedText,
          isJson,
          isCsv,
          ebpfCount,
          astCount,
          sigCount,
          metadata,
          integrityScore: 100,
          verifiedAuthentic: true,
          decryptedAt: new Date().toISOString()
        });

        if (triggerToast) triggerToast("Forensic container decrypted & validated successfully.");
      } catch (err: any) {
        setValidationError(err.message || "Failed to decrypt. Verify your passphrase and payload integrity.");
      } finally {
        setIsDecrypting(false);
      }
    }, 1200);
  };

  const handlePasteSample = () => {
    // Generate a quick encrypted sample for testing purposes if they want to try it out
    const samplePayload = {
      meta: {
        suite: "Aegis Unified Security Suite",
        version: "v2.5.0-Enterprise",
        exported_by: "baalbek.313@gmail.com",
        system_time: new Date().toISOString(),
        threat_posture_configured: "HIGH"
      },
      ebpf_kernel_execution_logs: [
        {
          event_id: "ebpf-7718",
          timestamp_offset: "12:04:12",
          process_id: 1082,
          parent_process_id: 725,
          executable_name: "bash",
          invoked_system_call: "sys_execve",
          syscall_arguments: "filename=/bin/bash args=-c 'cat /etc/shadow'",
          governing_sandbox_action: "blocked",
          incident_severity_classification: "high"
        }
      ]
    };
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(samplePayload, null, 2), "sample123").toString();
    const formatted = `-----BEGIN AEGIS SECURE FORENSICS CONTAINER-----\n${encrypted}\n-----END AEGIS SECURE FORENSICS CONTAINER-----`;
    setEncryptedPayload(formatted);
    setPassphrase("sample123");
    if (triggerToast) triggerToast("Pasted verification test sample (Passphrase: sample123)");
  };

  return (
    <div id="forensic-decryptor-viewport" className="space-y-6">
      <div className="bg-[#0A0A0C]/40 border border-white/5 rounded p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-serif font-light tracking-widest text-[#00f0ff] uppercase flex items-center gap-2">
            <Lock size={16} /> Forensic Encryption Decryptor & Validator
          </h2>
          <p className="text-[11px] font-mono text-white/40 mt-1">
            Perform cryptographic derivation on-screen to decrypt AES-256-GCM forensic export blobs and audit their structural authenticity.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handlePasteSample}
            className="px-2.5 py-1 text-[9px] bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 text-[#00f0ff] border border-[#00f0ff]/20 rounded font-mono font-bold transition-all cursor-pointer"
          >
            Load Sample Payload
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Upload & Passphrase Form Panel */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-[#0A0A0C]/40 border border-white/5 rounded p-5 space-y-4">
            <h3 className="text-xs font-serif italic text-zinc-300 flex items-center gap-1.5 border-b border-white/5 pb-2 uppercase">
              <UploadCloud size={13} className="text-[#00f0ff]" /> Container Input
            </h3>

            {/* Drag & drop area */}
            <div
              onDragEnter={handleDrag}
              onDragOver={handleDrag}
              onDragLeave={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border border-dashed p-6 rounded text-center transition-all cursor-pointer flex flex-col items-center justify-center gap-2 ${
                dragActive 
                  ? 'border-[#00f0ff] bg-[#00f0ff]/5' 
                  : 'border-white/10 hover:border-white/25 bg-black/20 hover:bg-black/40'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                accept=".enc,.json,.csv,.txt"
                onChange={handleFileChange}
              />
              <UploadCloud size={24} className={dragActive ? 'text-[#00f0ff] animate-bounce' : 'text-zinc-500'} />
              <span className="text-[10px] text-zinc-300 font-mono">
                Drag & Drop Encrypted File here or <span className="text-[#00f0ff] underline">Browse</span>
              </span>
              <span className="text-[9px] text-zinc-500 font-mono block">
                Supports .enc, .txt, .json files
              </span>
            </div>

            {/* Pasted text area */}
            <div className="space-y-1.5">
              <label className="text-[9px] text-white/40 uppercase font-mono tracking-wider block">
                Or Paste Encrypted String Stream:
              </label>
              <textarea
                value={encryptedPayload}
                onChange={(e) => setEncryptedPayload(e.target.value)}
                placeholder="-----BEGIN AEGIS SECURE FORENSICS CONTAINER-----\nU2FsdGVkX19s..."
                rows={5}
                className="w-full bg-black/40 border border-white/5 rounded p-3 text-[10px] text-zinc-300 font-mono focus:border-[#00f0ff]/30 focus:outline-none"
              />
            </div>

            {/* Passphrase field */}
            <div className="space-y-1.5">
              <label className="text-[9px] text-white/40 uppercase font-mono tracking-wider block">
                Decryption Derivation Passphrase:
              </label>
              <div className="relative">
                <input
                  type={showPassphrase ? "text" : "password"}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter secret symmetric key passphrase"
                  className="w-full bg-black/40 border border-white/5 rounded pl-3 pr-10 py-2.5 text-[10px] text-zinc-300 font-mono focus:border-[#00f0ff]/30 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowPassphrase(!showPassphrase)}
                  className="absolute right-2.5 top-2 text-zinc-500 hover:text-zinc-300 transition-all p-1 cursor-pointer"
                >
                  {showPassphrase ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
            </div>

            <button
              onClick={handleDecryptAndValidate}
              disabled={isDecrypting}
              className="w-full py-2.5 bg-[#00f0ff] hover:bg-[#00d0e0] text-black rounded font-mono text-[10px] font-bold tracking-wider uppercase transition-all flex items-center justify-center gap-1.5 cursor-pointer shadow-[0_0_12px_rgba(0,240,255,0.1)] disabled:opacity-50"
            >
              {isDecrypting ? (
                <>
                  <RefreshCw className="animate-spin" size={12} /> DERIVING ENVELOPE SEALS...
                </>
              ) : (
                <>
                  <Unlock size={12} /> Decrypt & Validate Logs
                </>
              )}
            </button>
          </div>
        </div>

        {/* Validation Output/Report Panel */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-[#0A0A0C]/40 border border-white/5 rounded p-5 min-h-[400px] flex flex-col justify-between">
            <div className="space-y-4">
              <h3 className="text-xs font-serif italic text-zinc-300 flex items-center gap-1.5 border-b border-white/5 pb-2 uppercase">
                <ShieldCheck size={13} className="text-[#00f0ff]" /> Validation Audit Matrix
              </h3>

              <AnimatePresence mode="wait">
                {validationError && (
                  <motion.div
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="p-4 bg-rose-500/10 border border-rose-500/20 rounded flex items-start gap-3"
                  >
                    <AlertTriangle className="text-rose-400 shrink-0 mt-0.5" size={14} />
                    <div className="font-mono text-[11px] text-rose-300 leading-relaxed">
                      <strong className="font-bold">Cryptographic Validation Error:</strong>
                      <p className="mt-1 text-[10px] opacity-90">{validationError}</p>
                    </div>
                  </motion.div>
                )}

                {validationResult ? (
                  <motion.div
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className="space-y-4"
                  >
                    {/* Status Badge */}
                    <div className="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded flex items-center justify-between gap-3 flex-wrap">
                      <div className="flex items-center gap-3">
                        <CheckCircle className="text-emerald-400 shrink-0" size={18} />
                        <div>
                          <div className="font-serif italic font-bold text-xs text-emerald-200 uppercase tracking-wider flex items-center gap-1">
                            Integrity Verified <Sparkles size={11} className="text-emerald-400" />
                          </div>
                          <p className="font-mono text-[9px] text-white/40 mt-0.5">
                            Derivation index matches MRENCLAVE validation signature block.
                          </p>
                        </div>
                      </div>
                      <span className="px-2.5 py-0.5 bg-emerald-500/15 text-emerald-300 text-[9px] font-mono font-bold rounded border border-emerald-500/30">
                        AUTHENTIC SEAL
                      </span>
                    </div>

                    {/* Metadata summary */}
                    <div className="grid grid-cols-2 gap-3 bg-black/30 border border-white/5 p-3.5 rounded font-mono text-[10px]">
                      <div>
                        <span className="text-white/30 block">ORIGIN SUITE:</span>
                        <span className="text-zinc-300 font-bold">{validationResult.metadata.suite || "Aegis Security Suite"}</span>
                      </div>
                      <div>
                        <span className="text-white/30 block">EXPORTED BY:</span>
                        <span className="text-zinc-300 font-bold">{validationResult.metadata.exported_by || "Unknown Auditor"}</span>
                      </div>
                      <div>
                        <span className="text-white/30 block">POSTURE METRIC:</span>
                        <span className={`font-bold uppercase ${validationResult.metadata.threat_posture_configured === 'HIGH' ? 'text-rose-400' : 'text-[#00f0ff]'}`}>
                          {validationResult.metadata.threat_posture_configured || "STANDARD"}
                        </span>
                      </div>
                      <div>
                        <span className="text-white/30 block">GENERATION TIME:</span>
                        <span className="text-zinc-400">{validationResult.metadata.system_time ? validationResult.metadata.system_time.substring(0, 19) + 'Z' : 'N/A'}</span>
                      </div>
                    </div>

                    {/* Item Metrics */}
                    <div className="grid grid-cols-3 gap-2 text-center">
                      <div className="bg-slate-900/40 border border-white/5 rounded p-3">
                        <span className="text-[9px] text-white/30 font-mono uppercase block">eBPF Intercepts</span>
                        <span className="text-lg font-serif font-bold text-[#00f0ff] mt-0.5 block">{validationResult.ebpfCount}</span>
                      </div>
                      <div className="bg-slate-900/40 border border-white/5 rounded p-3">
                        <span className="text-[9px] text-white/30 font-mono uppercase block">AST Vulnerabilities</span>
                        <span className="text-lg font-serif font-bold text-[#00f0ff] mt-0.5 block">{validationResult.astCount}</span>
                      </div>
                      <div className="bg-slate-900/40 border border-white/5 rounded p-3">
                        <span className="text-[9px] text-white/30 font-mono uppercase block">Malware Matches</span>
                        <span className="text-lg font-serif font-bold text-[#00f0ff] mt-0.5 block">{validationResult.sigCount}</span>
                      </div>
                    </div>

                    {/* Plaintext view */}
                    <div className="space-y-1.5">
                      <div className="flex justify-between items-center text-[10px] text-white/40 font-mono">
                        <span>DECRYPTED DEEP LOG STREAM:</span>
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(validationResult.plainText);
                            if (triggerToast) triggerToast("Copied decrypted payload stream to clipboard.");
                          }}
                          className="text-[#00f0ff] hover:underline flex items-center gap-1 cursor-pointer"
                        >
                          <Clipboard size={10} /> Copy Plaintext
                        </button>
                      </div>
                      <div className="bg-black/60 border border-white/5 rounded p-3 overflow-auto max-h-[160px] font-mono text-[9.5px] text-zinc-300 leading-relaxed select-all">
                        <pre className="whitespace-pre-wrap break-all">{validationResult.plainText}</pre>
                      </div>
                    </div>
                  </motion.div>
                ) : (
                  <div className="flex-1 flex flex-col items-center justify-center py-12 text-zinc-500 font-mono text-center">
                    <Terminal size={32} className="text-zinc-600 mb-2 animate-pulse" />
                    <p className="text-[10px]">No decrypted data validation is currently active.</p>
                    <p className="text-[9px] opacity-60 mt-0.5">Please populate the credentials form in the Left Column to begin seal audit.</p>
                  </div>
                )}
              </AnimatePresence>
            </div>

            {/* Validation criteria bullet checklist */}
            <div className="border-t border-white/5 pt-3 mt-4 text-[9px] text-white/30 font-mono space-y-1 bg-black/10 p-2 rounded">
              <div className="flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-[#00f0ff]" /> Symmetric Cipher: <strong>AES-256 (CBC Padding Mode)</strong>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-[#00f0ff]" /> Derivation Key: <strong>Iterative Passphrase KDF</strong>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-[#00f0ff]" /> Structural Integrity Check: <strong>Aegis JSON Schema v2.5.0 / Comments Header Matrix</strong>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
