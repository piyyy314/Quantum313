import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ShieldCheck, AlertOctagon, RefreshCw, Key, FileSignature, CheckCircle, Flame, ShieldAlert } from 'lucide-react';
import CryptoJS from 'crypto-js';

interface ThreatIntegrityCheckerProps {
  onIntegrityChange?: (isValid: boolean) => void;
  triggerToast?: (msg: string) => void;
}

export default function ThreatIntegrityChecker({ onIntegrityChange, triggerToast }: ThreatIntegrityCheckerProps) {
  const [currentHash, setCurrentHash] = useState<string>('');
  const [baselineHash, setBaselineHash] = useState<string | null>(null);
  const [isSecure, setIsSecure] = useState<boolean>(true);
  const [dbLength, setDbLength] = useState<number>(0);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);

  // Compute hash of the current localStorage database
  const computeDatabaseHash = () => {
    try {
      const rawData = localStorage.getItem('aegis_threat_archive') || '[]';
      // Compute SHA-256
      const hash = CryptoJS.SHA256(rawData).toString();
      setCurrentHash(hash);
      
      const parsed = JSON.parse(rawData);
      setDbLength(parsed.length);
      return hash;
    } catch (e) {
      const fallbackHash = CryptoJS.SHA256('[]').toString();
      setCurrentHash(fallbackHash);
      setDbLength(0);
      return fallbackHash;
    }
  };

  // Re-run computation on mount & listen to localStorage changes or custom event
  useEffect(() => {
    // Initial compute
    const initialHash = computeDatabaseHash();

    // Check if baseline is sealed
    const sealed = localStorage.getItem('aegis_threat_archive_baseline_hash');
    if (sealed) {
      setBaselineHash(sealed);
      setIsSecure(initialHash === sealed);
      if (onIntegrityChange) onIntegrityChange(initialHash === sealed);
    } else {
      // If no baseline is sealed yet, automatically seal current state on first launch
      localStorage.setItem('aegis_threat_archive_baseline_hash', initialHash);
      setBaselineHash(initialHash);
      setIsSecure(true);
      if (onIntegrityChange) onIntegrityChange(true);
    }

    // Custom event to force recalculation from other components (e.g. ThreatArchive)
    const handleRecalc = () => {
      const freshHash = computeDatabaseHash();
      const currentSealed = localStorage.getItem('aegis_threat_archive_baseline_hash');
      if (currentSealed) {
        setBaselineHash(currentSealed);
        const match = freshHash === currentSealed;
        setIsSecure(match);
        if (onIntegrityChange) onIntegrityChange(match);
      } else {
        localStorage.setItem('aegis_threat_archive_baseline_hash', freshHash);
        setBaselineHash(freshHash);
        setIsSecure(true);
        if (onIntegrityChange) onIntegrityChange(true);
      }
    };

    window.addEventListener('aegis_archive_modified', handleRecalc);
    // Listen to native storage events for offline cross-tab tampering detection
    window.addEventListener('storage', handleRecalc);

    return () => {
      window.removeEventListener('aegis_archive_modified', handleRecalc);
      window.removeEventListener('storage', handleRecalc);
    };
  }, [onIntegrityChange]);

  const handleVerify = () => {
    setIsVerifying(true);
    setTimeout(() => {
      const freshHash = computeDatabaseHash();
      const sealed = localStorage.getItem('aegis_threat_archive_baseline_hash');
      
      if (sealed) {
        const match = freshHash === sealed;
        setIsSecure(match);
        if (onIntegrityChange) onIntegrityChange(match);
        if (triggerToast) {
          if (match) {
            triggerToast("🛡️ Cryptographic handshake verified: Threat Archive matches sealed baseline hash.");
          } else {
            triggerToast("⚠️ INTEGRITY FAILURE: Local storage database drift or unverified offline tampering detected!");
          }
        }
      } else {
        localStorage.setItem('aegis_threat_archive_baseline_hash', freshHash);
        setBaselineHash(freshHash);
        setIsSecure(true);
        if (onIntegrityChange) onIntegrityChange(true);
        if (triggerToast) triggerToast("🔐 Cryptographic baseline hash successfully sealed.");
      }
      setIsVerifying(false);
    }, 600);
  };

  const handleSealBaseline = () => {
    const freshHash = computeDatabaseHash();
    localStorage.setItem('aegis_threat_archive_baseline_hash', freshHash);
    setBaselineHash(freshHash);
    setIsSecure(true);
    if (onIntegrityChange) onIntegrityChange(true);
    if (triggerToast) triggerToast("🔑 Dynamic Threat Baseline Seal updated and saved to local secure cache.");
  };

  // Simulates offline/unauthorized modification of the database bypassing state
  const handleSimulateTampering = () => {
    try {
      const rawData = localStorage.getItem('aegis_threat_archive') || '[]';
      const parsed = JSON.parse(rawData);
      
      // Inject a forged malicious alert directly into the array
      const forgedEntry = {
        id: "forged-inject-313",
        timestamp: new Date().toISOString(),
        category: "ebpf",
        name: " forged_payload_malicious_backdoor_injection_attempt",
        severity: "high",
        details: "MALICIOUS PAYLOAD INJECTED VIA DIRECT LOCALSTORAGE MANIPULATION OUTSIDE THE AEGIS RUNTIME.",
        rawPayload: "syscall=execve command=rm -rf / status=tampered bypass_verification=true",
        status: "Unresolved",
        notes: "TAMPERED DIRECTLY IN LOCAL STORAGE BYPASSING SECURITY CONTROLLERS.",
        assignedOfficer: "unknown_intruder@darknet.io",
        meta: { forged: true }
      };

      const tamperedArray = [forgedEntry, ...parsed];
      localStorage.setItem('aegis_threat_archive', JSON.stringify(tamperedArray));
      
      // Notify components and recalculate
      window.dispatchEvent(new Event('aegis_archive_modified'));
      if (triggerToast) triggerToast("🚨 TAMPER SIMULATION TRIGGERED: Directly altered Local Storage content to trigger cryptographic drift.");
    } catch (e) {
      if (triggerToast) triggerToast("[-] Failed to simulate tampering: " + String(e));
    }
  };

  const handleFixDatabase = () => {
    try {
      const rawData = localStorage.getItem('aegis_threat_archive') || '[]';
      const parsed = JSON.parse(rawData);
      
      // Remove any forged entries
      const cleaned = parsed.filter((t: any) => t.id !== "forged-inject-313" && !t.meta?.forged);
      localStorage.setItem('aegis_threat_archive', JSON.stringify(cleaned));
      
      window.dispatchEvent(new Event('aegis_archive_modified'));
      if (triggerToast) triggerToast("✓ Purged tampered indicators! Database restored to authorized record state.");
    } catch (e) {
      if (triggerToast) triggerToast("[-] Failed to restore: " + String(e));
    }
  };

  // Split SHA-256 hash into 64 elements to draw as visual block matrix
  const renderHashBlocks = () => {
    if (!currentHash) return null;
    
    return currentHash.split('').map((char, index) => {
      // Convert character to 0-15 integer
      const val = parseInt(char, 16);
      
      // Determine styling based on hex digit value
      let bgColor = "bg-zinc-950 border-zinc-900";
      let textColor = "text-zinc-600";
      
      if (!isSecure) {
        // Red hue shift if tampered
        const intensity = Math.round((val / 15) * 100);
        if (val > 11) {
          bgColor = "bg-rose-950/40 border-rose-800/40";
          textColor = "text-rose-400";
        } else if (val > 5) {
          bgColor = "bg-rose-950/20 border-rose-900/20";
          textColor = "text-rose-600";
        }
      } else {
        // Cyan hue shift if secure
        if (val > 11) {
          bgColor = "bg-[#00f0ff]/15 border-[#00f0ff]/30";
          textColor = "text-[#00f0ff] font-bold";
        } else if (val > 5) {
          bgColor = "bg-cyan-950/20 border-cyan-900/30";
          textColor = "text-cyan-400";
        }
      }

      return (
        <div 
          key={index} 
          className={`h-5 w-5 rounded border flex items-center justify-center font-mono text-[9px] select-none uppercase transition-all duration-300 hover:scale-110 ${bgColor} ${textColor}`}
          title={`Byte Index: ${index} | Hex Val: ${char}`}
        >
          {char}
        </div>
      );
    });
  };

  return (
    <div className="bg-[#040406] border border-white/5 rounded-md p-4 space-y-4 font-mono select-none">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-2 border-b border-white/5">
        <div className="flex items-center gap-2">
          <div className={`p-1.5 rounded ${isSecure ? 'bg-[#00f0ff]/10 text-[#00f0ff]' : 'bg-rose-500/10 text-rose-400'}`}>
            <FileSignature size={14} />
          </div>
          <div>
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-zinc-200">
              SHA-256 Offline Database Integrity Auditor
            </h4>
            <p className="text-[9px] text-zinc-500">
              Calculates real-time cryptographically secure hash verification on the local threat ledger state.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleVerify}
            disabled={isVerifying}
            className="px-2.5 py-1 bg-black/40 hover:bg-white/5 border border-white/5 text-zinc-300 hover:text-white rounded text-[9px] font-bold transition-all uppercase flex items-center gap-1 cursor-pointer"
          >
            <RefreshCw size={10} className={isVerifying ? "animate-spin" : ""} />
            Verify
          </button>
          
          <button
            onClick={handleSealBaseline}
            className="px-2.5 py-1 bg-[#00f0ff]/15 hover:bg-[#00f0ff]/25 border border-[#00f0ff]/20 text-[#00f0ff] hover:text-white rounded text-[9px] font-bold transition-all uppercase flex items-center gap-1 cursor-pointer"
            title="Seal current database hash as authorized baseline"
          >
            <Key size={10} />
            Seal Baseline
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Real-time Indicator Panel */}
        <div className="lg:col-span-5 space-y-3.5">
          <div className={`p-3 rounded border flex items-center gap-3.5 ${
            isSecure 
              ? 'bg-emerald-950/10 border-emerald-900/30 text-emerald-400' 
              : 'bg-rose-950/15 border-rose-900/30 text-rose-400'
          }`}>
            <div className="shrink-0">
              {isSecure ? (
                <ShieldCheck size={28} className="text-emerald-400 animate-pulse" />
              ) : (
                <ShieldAlert size={28} className="text-rose-400 animate-bounce" />
              )}
            </div>
            <div className="space-y-0.5">
              <div className="text-[10px] font-bold tracking-wider uppercase">
                {isSecure ? "AUTHENTICATED INTEGRITY SAFE" : "CRITICAL: FINGERPRINT DRIFT DETECTED"}
              </div>
              <p className="text-[8.5px] text-zinc-400 leading-normal font-sans">
                {isSecure 
                  ? `Cryptographic hash matches the authorized offline database seal perfectly. Verified database has ${dbLength} active threat logs.` 
                  : "Database has been altered offline or records have been manipulated! The baseline hash does not match computed data."
                }
              </p>
            </div>
          </div>

          <div className="space-y-1.5 text-[9.5px]">
            <div className="flex items-center justify-between text-zinc-550">
              <span>ACTIVE COMPUTED HASH</span>
              <span className="text-[8px] text-zinc-600 font-bold">SHA-256</span>
            </div>
            <div className="bg-black border border-white/5 p-2 rounded text-zinc-300 font-mono break-all text-[9px] selection:bg-[#00f0ff]/20 select-all">
              {currentHash || "CALCULATING..."}
            </div>
          </div>

          <div className="space-y-1.5 text-[9.5px]">
            <div className="flex items-center justify-between text-zinc-550">
              <span>SEALED BASELINE AUTH HASH</span>
              <span className="text-[8px] text-[#00f0ff] font-bold">CACHED SECURE</span>
            </div>
            <div className="bg-black border border-white/5 p-2 rounded text-zinc-400 font-mono break-all text-[9px] selection:bg-[#00f0ff]/20 select-all">
              {baselineHash || "NO BASELINE SEALED IN REGISTRY"}
            </div>
          </div>

          {/* Tamper controls simulation */}
          <div className="pt-1 flex gap-2">
            {!isSecure ? (
              <button
                onClick={handleFixDatabase}
                className="flex-1 py-1 px-2.5 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 rounded font-bold text-emerald-400 text-[8.5px] transition-all uppercase flex items-center justify-center gap-1 cursor-pointer"
              >
                <CheckCircle size={10} /> Clean Tampered Entries
              </button>
            ) : (
              <button
                onClick={handleSimulateTampering}
                className="flex-1 py-1 px-2.5 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 rounded font-bold text-rose-400 text-[8.5px] transition-all uppercase flex items-center justify-center gap-1 cursor-pointer"
                title="Directly bypass state and write forged logs to localStorage to trigger mismatch warning"
              >
                <Flame size={10} /> Inject Tamper Anomaly
              </button>
            )}
          </div>
        </div>

        {/* 64-hex visualizer fingerprint blocks */}
        <div className="lg:col-span-7 flex flex-col justify-between">
          <div className="space-y-1.5">
            <span className="text-[9px] text-zinc-550 uppercase tracking-wider block">
              Cryptographic Visual DNA Fingerprint (64 hex blocks)
            </span>
            <div className="grid grid-cols-8 sm:grid-cols-16 gap-1 bg-black/60 border border-white/5 p-3 rounded-md min-h-[100px] items-center justify-items-center">
              {renderHashBlocks()}
            </div>
          </div>
          
          <div className="text-[8px] text-zinc-650 leading-relaxed font-sans pt-3 select-none">
            💡 <strong>Aegis Secure Cryptography Note:</strong> A visual fingerprint lets researchers verify database integrity at a single glance without reading long hexadecimal strings. Any slight modification (even one byte) completely scrambles the fingerprint matrix pattern (the Avalanche Effect).
          </div>
        </div>
      </div>
    </div>
  );
}
