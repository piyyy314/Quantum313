import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  X, 
  Download, 
  Copy, 
  Check, 
  FileText, 
  FileJson, 
  FileSpreadsheet, 
  Terminal, 
  ShieldCheck, 
  Lock, 
  Share2 
} from 'lucide-react';
import CryptoJS from 'crypto-js';
import { ArchivedThreat } from '../types';

interface ForensicExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  threats: ArchivedThreat[];
  onToast: (msg: string) => void;
}

type ExportFormat = 'stix' | 'cef' | 'syslog' | 'csv' | 'json' | 'encrypted';

export default function ForensicExportModal({
  isOpen,
  onClose,
  threats,
  onToast
}: ForensicExportModalProps) {
  const [selectedFormat, setSelectedFormat] = useState<ExportFormat>('stix');
  const [encryptionPassphrase, setEncryptionPassphrase] = useState('Aegis-Vault-Pass-2026!');
  const [copied, setCopied] = useState(false);

  // Generate STIX 2.1 Bundle representation
  const stixContent = useMemo(() => {
    const bundleId = `bundle--${CryptoJS.lib.WordArray.random(16).toString()}`;
    const objects = threats.map((t) => {
      const indicatorId = `indicator--${CryptoJS.SHA256(t.id + t.timestamp).toString().substring(0, 32)}`;
      return {
        type: 'indicator',
        spec_version: '2.1',
        id: indicatorId,
        created: t.timestamp,
        modified: t.timestamp,
        name: t.name,
        description: t.details,
        indicator_types: [t.category === 'ebpf' ? 'malicious-activity' : 'anomalous-activity'],
        pattern_type: 'stix',
        pattern: `[file:name = '${t.category === 'ebpf' ? 'kernel_probe' : 'source_ast'}' AND x_aegis:severity = '${t.severity}']`,
        valid_from: t.timestamp,
        confidence: t.severity === 'high' ? 95 : t.severity === 'medium' ? 70 : 40,
        labels: [t.category, t.severity, t.status.toLowerCase().replace(' ', '-')],
        external_references: [
          {
            source_name: 'aegis-vmm-forensics',
            external_id: t.id,
            description: `Aegis Kernel & AST Preserved Log: ${t.status}`
          }
        ],
        custom_properties: {
          x_aegis_assigned_officer: t.assignedOfficer || 'unassigned',
          x_aegis_mitre_tactic: t.mitreTactic || (t.category === 'ebpf' ? 'Privilege Escalation (TA0004)' : 'Defense Evasion (TA0005)'),
          x_aegis_raw_payload: t.rawPayload,
          x_aegis_integrity_hash: CryptoJS.SHA256(t.rawPayload + t.timestamp).toString()
        }
      };
    });

    return JSON.stringify({
      type: 'bundle',
      id: bundleId,
      spec_version: '2.1',
      objects
    }, null, 2);
  }, [threats]);

  // Generate CEF (Common Event Format - ArcSight / SIEM) representation
  const cefContent = useMemo(() => {
    return threats.map(t => {
      const sevNumber = t.severity === 'high' ? 9 : t.severity === 'medium' ? 6 : 3;
      const cleanDetails = t.details.replace(/[\\|]/g, '_');
      const cleanPayload = t.rawPayload.replace(/[\r\n]+/g, ' ').replace(/[\\|]/g, '_');
      return `CEF:0|Aegis-Security|Kernel-VMM|2.5.0|${t.id}|${t.name}|${sevNumber}|src=${t.meta?.ip || '127.0.0.1'} cat=${t.category} cs1=${t.status} cs1Label=TriageStatus msg=${cleanDetails} rawData=${cleanPayload} act=${t.status === 'Remediated' ? 'blocked' : 'alert'}`;
    }).join('\n');
  }, [threats]);

  // Generate Syslog RFC 5424 representation
  const syslogContent = useMemo(() => {
    return threats.map(t => {
      const pri = t.severity === 'high' ? 131 : t.severity === 'medium' ? 134 : 135; // local0.err / local0.notice / local0.info
      const dateStr = new Date(t.timestamp).toISOString();
      return `<${pri}>1 ${dateStr} aegis-vmm-node01 aegis-forensics - [threat@54321 id="${t.id}" cat="${t.category}" sev="${t.severity}" status="${t.status}"] ${t.name} - ${t.details}`;
    }).join('\n');
  }, [threats]);

  // Generate CSV representation with full forensic metadata
  const csvContent = useMemo(() => {
    const headers = ['ID', 'Timestamp', 'Category', 'Severity', 'Name', 'Status', 'AssignedOfficer', 'MITRE_Tactic', 'Details', 'Payload_Hash_SHA256', 'RawPayload'];
    const escapeCsv = (str: string) => `"${(str || '').replace(/"/g, '""')}"`;
    const rows = threats.map(t => {
      const hash = CryptoJS.SHA256(t.rawPayload + t.timestamp).toString();
      const mitre = t.mitreTactic || (t.category === 'ebpf' ? 'TA0004' : 'TA0005');
      return [
        escapeCsv(t.id),
        escapeCsv(t.timestamp),
        escapeCsv(t.category),
        escapeCsv(t.severity),
        escapeCsv(t.name),
        escapeCsv(t.status),
        escapeCsv(t.assignedOfficer || ''),
        escapeCsv(mitre),
        escapeCsv(t.details),
        escapeCsv(hash),
        escapeCsv(t.rawPayload)
      ].join(',');
    });
    return [headers.join(','), ...rows].join('\n');
  }, [threats]);

  // Generate Standard JSON
  const jsonContent = useMemo(() => {
    return JSON.stringify({
      generator: 'Aegis Security Forensics Suite v2.5.0',
      exported_at: new Date().toISOString(),
      record_count: threats.length,
      integrity_merkle_root: CryptoJS.SHA256(threats.map(t => t.id).join(':')).toString(),
      records: threats
    }, null, 2);
  }, [threats]);

  // Generate AES-256 Encrypted Container
  const encryptedContent = useMemo(() => {
    const plain = JSON.stringify({
      export_version: '2.5.0',
      system_time: new Date().toISOString(),
      threats
    });
    const ciphertext = CryptoJS.AES.encrypt(plain, encryptionPassphrase).toString();
    return `-----BEGIN AEGIS SECURE FORENSICS CONTAINER-----\nFORMAT: AES-256-CBC/PBKDF2\nRECORDS: ${threats.length}\nCHECKSUM: ${CryptoJS.SHA256(ciphertext).toString()}\n\n${ciphertext}\n-----END AEGIS SECURE FORENSICS CONTAINER-----`;
  }, [threats, encryptionPassphrase]);

  const activeContent = useMemo(() => {
    switch (selectedFormat) {
      case 'stix': return stixContent;
      case 'cef': return cefContent;
      case 'syslog': return syslogContent;
      case 'csv': return csvContent;
      case 'json': return jsonContent;
      case 'encrypted': return encryptedContent;
    }
  }, [selectedFormat, stixContent, cefContent, syslogContent, csvContent, jsonContent, encryptedContent]);

  const getFileExtension = () => {
    switch (selectedFormat) {
      case 'stix': return 'stix.json';
      case 'cef': return 'cef.log';
      case 'syslog': return 'rfc5424.syslog';
      case 'csv': return 'forensics.csv';
      case 'json': return 'threat_ledger.json';
      case 'encrypted': return 'aegis.vault';
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(activeContent);
    setCopied(true);
    onToast(`Copied ${selectedFormat.toUpperCase()} forensic payload to clipboard`);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleDownload = () => {
    const filename = `aegis_forensics_${selectedFormat}_${Date.now()}.${getFileExtension()}`;
    const blob = new Blob([activeContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    onToast(`Downloaded ${filename}`);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
      <motion.div
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.96 }}
        className="w-full max-w-4xl bg-[#0B0B0E] border border-white/10 rounded-xl shadow-2xl overflow-hidden font-mono flex flex-col max-h-[90vh]"
      >
        {/* Header */}
        <div className="p-4 border-b border-white/10 bg-gradient-to-r from-black to-[#13131a] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30">
              <Share2 size={16} />
            </div>
            <div>
              <div className="text-[9px] text-[#00f0ff] uppercase tracking-widest font-bold">
                FORENSIC EXPORT PIPELINE
              </div>
              <h3 className="text-sm font-semibold text-zinc-100">
                Multi-Format Threat Intelligence Exporter ({threats.length} Records)
              </h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-white p-1.5 rounded hover:bg-white/5 transition-colors cursor-pointer"
          >
            <X size={16} />
          </button>
        </div>

        {/* Format Selector Pills */}
        <div className="p-4 border-b border-white/5 bg-black/40 flex flex-wrap gap-2 items-center">
          <span className="text-[10px] text-zinc-400 font-bold uppercase mr-1">FORMAT:</span>
          
          <button
            type="button"
            onClick={() => setSelectedFormat('stix')}
            className={`px-3 py-1.5 rounded text-[10px] font-bold tracking-wider uppercase transition-all flex items-center gap-1.5 cursor-pointer ${
              selectedFormat === 'stix'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_12px_rgba(0,240,255,0.4)]'
                : 'bg-white/5 text-zinc-300 hover:bg-white/10 border border-white/5'
            }`}
          >
            <FileJson size={12} /> STIX 2.1 (OASIS)
          </button>

          <button
            type="button"
            onClick={() => setSelectedFormat('cef')}
            className={`px-3 py-1.5 rounded text-[10px] font-bold tracking-wider uppercase transition-all flex items-center gap-1.5 cursor-pointer ${
              selectedFormat === 'cef'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_12px_rgba(0,240,255,0.4)]'
                : 'bg-white/5 text-zinc-300 hover:bg-white/10 border border-white/5'
            }`}
          >
            <Terminal size={12} /> CEF (ArcSight)
          </button>

          <button
            type="button"
            onClick={() => setSelectedFormat('syslog')}
            className={`px-3 py-1.5 rounded text-[10px] font-bold tracking-wider uppercase transition-all flex items-center gap-1.5 cursor-pointer ${
              selectedFormat === 'syslog'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_12px_rgba(0,240,255,0.4)]'
                : 'bg-white/5 text-zinc-300 hover:bg-white/10 border border-white/5'
            }`}
          >
            <FileText size={12} /> Syslog RFC 5424
          </button>

          <button
            type="button"
            onClick={() => setSelectedFormat('csv')}
            className={`px-3 py-1.5 rounded text-[10px] font-bold tracking-wider uppercase transition-all flex items-center gap-1.5 cursor-pointer ${
              selectedFormat === 'csv'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_12px_rgba(0,240,255,0.4)]'
                : 'bg-white/5 text-zinc-300 hover:bg-white/10 border border-white/5'
            }`}
          >
            <FileSpreadsheet size={12} /> Forensic CSV
          </button>

          <button
            type="button"
            onClick={() => setSelectedFormat('json')}
            className={`px-3 py-1.5 rounded text-[10px] font-bold tracking-wider uppercase transition-all flex items-center gap-1.5 cursor-pointer ${
              selectedFormat === 'json'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_12px_rgba(0,240,255,0.4)]'
                : 'bg-white/5 text-zinc-300 hover:bg-white/10 border border-white/5'
            }`}
          >
            <FileJson size={12} /> Pure JSON
          </button>

          <button
            type="button"
            onClick={() => setSelectedFormat('encrypted')}
            className={`px-3 py-1.5 rounded text-[10px] font-bold tracking-wider uppercase transition-all flex items-center gap-1.5 cursor-pointer ${
              selectedFormat === 'encrypted'
                ? 'bg-amber-400 text-black shadow-[0_0_12px_rgba(251,191,36,0.4)]'
                : 'bg-white/5 text-zinc-300 hover:bg-white/10 border border-white/5'
            }`}
          >
            <Lock size={12} /> AES-256 Vault (.aegis)
          </button>
        </div>

        {/* Encrypted Vault Options */}
        {selectedFormat === 'encrypted' && (
          <div className="px-4 py-2.5 bg-amber-500/10 border-b border-amber-500/20 flex flex-wrap items-center gap-3">
            <span className="text-[10px] text-amber-300 font-bold uppercase flex items-center gap-1.5">
              <Lock size={12} /> AES-256 Encryption Passphrase:
            </span>
            <input
              type="text"
              value={encryptionPassphrase}
              onChange={(e) => setEncryptionPassphrase(e.target.value)}
              className="bg-black/60 border border-amber-500/40 rounded px-2.5 py-1 text-zinc-200 text-[10px] flex-1 max-w-sm focus:outline-none focus:border-amber-400"
              placeholder="Enter cryptographic passphrase..."
            />
            <span className="text-[9px] text-amber-400/80">PBKDF2 Iterations: 10,000</span>
          </div>
        )}

        {/* Preview Area */}
        <div className="flex-1 p-4 overflow-y-auto bg-black/60 min-h-[300px]">
          <div className="flex items-center justify-between text-[9px] text-zinc-500 mb-2">
            <span>PAYLOAD PREVIEW ({selectedFormat.toUpperCase()})</span>
            <span>{activeContent.length} bytes</span>
          </div>
          <pre className="text-[10px] text-emerald-400/90 font-mono bg-black/80 border border-white/5 p-4 rounded-lg overflow-x-auto max-h-[340px] whitespace-pre-wrap leading-relaxed select-all">
            {activeContent}
          </pre>
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-white/10 bg-black/80 flex items-center justify-between gap-3">
          <div className="text-[10px] text-zinc-400">
            Target: <span className="text-[#00f0ff] font-bold">.{getFileExtension()}</span> | Compatible with Splunk, Elastic, QRadar, Sentinel, MISP
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopy}
              className="px-3.5 py-2 rounded bg-white/5 hover:bg-white/10 text-zinc-200 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all cursor-pointer"
            >
              {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <button
              type="button"
              onClick={handleDownload}
              className="px-4 py-2 rounded bg-[#00f0ff] hover:bg-[#33f3ff] text-black text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(0,240,255,0.3)] cursor-pointer"
            >
              <Download size={13} />
              Download {getFileExtension().toUpperCase()}
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
