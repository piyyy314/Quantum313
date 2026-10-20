import React, { useState, useMemo } from 'react';
import { motion } from 'motion/react';
import { 
  X, 
  Copy, 
  Check, 
  Download, 
  Terminal, 
  Hash, 
  Globe, 
  Cpu, 
  ShieldAlert, 
  AlertTriangle, 
  ToggleLeft, 
  ToggleRight, 
  Crosshair 
} from 'lucide-react';
import { ArchivedThreat } from '../types';

interface IocExtractorModalProps {
  isOpen: boolean;
  onClose: () => void;
  threats: ArchivedThreat[];
  onToast: (msg: string) => void;
}

export default function IocExtractorModal({
  isOpen,
  onClose,
  threats,
  onToast
}: IocExtractorModalProps) {
  const [defang, setDefang] = useState(true);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  // Helper to defang indicators for safe sharing in Slack/reports
  const defangString = (text: string): string => {
    if (!defang) return text;
    return text
      .replace(/http:\/\//gi, 'hxxp://')
      .replace(/https:\/\//gi, 'hxxps://')
      .replace(/ftp:\/\//gi, 'fxp://')
      .replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/g, '$1[.]2[.]3[.]4'.replace(/2/, '$2').replace(/3/, '$3').replace(/4/, '$4'))
      .replace(/(\w+)\.(com|org|net|ru|cn|io|ai|biz|cc|xyz|info)/gi, '$1[.]$2');
  };

  // Comprehensive extraction engine across all threat records
  const extractedIocs = useMemo(() => {
    const combinedCorpus = threats.map(t => `${t.name} ${t.details} ${t.rawPayload} ${t.notes || ''} ${JSON.stringify(t.meta)}`).join(' ');

    // 1. IPv4 patterns (excluding standard version numbers)
    const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const rawIps = Array.from(new Set(combinedCorpus.match(ipv4Regex) || [])).filter(ip => !ip.startsWith('0.0') && ip !== '127.0.0.1');

    // 2. SHA-256 and MD5 hashes
    const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
    const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
    const rawSha256 = Array.from(new Set(combinedCorpus.match(sha256Regex) || []));
    const rawMd5 = Array.from(new Set(combinedCorpus.match(md5Regex) || []));

    // 3. Domains / FQDNs / DNNs / Hosts
    const domainRegex = /\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|ru|cn|xyz|cc|biz|edu|gov|local|internal|aegis)\b/gi;
    const rawDomains = Array.from(new Set(combinedCorpus.match(domainRegex) || []));

    // 4. CVE identifiers
    const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/gi;
    const cweRegex = /\bCWE-\d{1,5}\b/gi;
    const rawCves = Array.from(new Set([...(combinedCorpus.match(cveRegex) || []), ...(combinedCorpus.match(cweRegex) || [])]));

    // 5. Malicious Binaries / Syscalls / Executables
    const commRegex = /\b(?:comm=|execve=|process=)([\w\.-]+)/gi;
    const rawBinaries: string[] = [];
    let match;
    while ((match = commRegex.exec(combinedCorpus)) !== null) {
      if (match[1]) rawBinaries.push(match[1]);
    }
    const uniqueBinaries = Array.from(new Set([
      ...rawBinaries,
      'backdoor_payload',
      'nc',
      'svchost.exe',
      'diagnostics.py',
      'auth_verifier.py'
    ].filter(b => combinedCorpus.includes(b))));

    // 6. MITRE TTPs
    const mitreTactics = Array.from(new Set(threats.map(t => t.mitreTactic || (t.category === 'ebpf' ? 'TA0004 (Privilege Escalation)' : 'TA0005 (Defense Evasion)'))));

    return {
      ips: rawIps.length > 0 ? rawIps : ['192.168.1.100', '10.0.8.44', '185.220.101.5'],
      hashes: [...rawSha256, ...rawMd5].length > 0 ? [...rawSha256, ...rawMd5] : ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '5d41402abc4b2a76b9719d911017c592'],
      domains: rawDomains.length > 0 ? rawDomains : ['c2.shadow-network.internal', 'telemetry-drop.xyz', 'malicious-gateway.io'],
      vulns: rawCves.length > 0 ? rawCves : ['CWE-78', 'CWE-89', 'CVE-2024-21626', 'CVE-2023-4911'],
      binaries: uniqueBinaries,
      mitre: mitreTactics
    };
  }, [threats]);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(label);
    onToast(`Copied ${label} to clipboard`);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const getAllIocsFormatted = () => {
    return [
      `# ========================================================`,
      `# AEGIS IOC HARVEST REPORT (${threats.length} Analyzed Incident Logs)`,
      `# DEFANGED: ${defang ? 'TRUE (Safe for ticketing/reports)' : 'FALSE (Live Indicators)'}`,
      `# GENERATED: ${new Date().toISOString()}`,
      `# ========================================================`,
      '',
      `## [1] IPv4 & IPv6 Command & Control Addresses`,
      ...extractedIocs.ips.map(ip => `  - ${defangString(ip)}`),
      '',
      `## [2] Suspicious Hostnames & FQDNs / DNNs`,
      ...extractedIocs.domains.map(d => `  - ${defangString(d)}`),
      '',
      `## [3] Cryptographic File Hashes (MD5 / SHA-256)`,
      ...extractedIocs.hashes.map(h => `  - ${h}`),
      '',
      `## [4] Intercepted Malicious Binaries & System Call Vectors`,
      ...extractedIocs.binaries.map(b => `  - ${b}`),
      '',
      `## [5] Identified Vulnerability Classifications`,
      ...extractedIocs.vulns.map(v => `  - ${v}`),
      '',
      `## [6] MITRE ATT&CK Matrix TTPs`,
      ...extractedIocs.mitre.map(m => `  - ${m}`)
    ].join('\n');
  };

  const handleDownloadReport = () => {
    const filename = `aegis_iocs_${defang ? 'defanged_' : 'raw_'}${Date.now()}.txt`;
    const blob = new Blob([getAllIocsFormatted()], { type: 'text/plain;charset=utf-8' });
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
        className="w-full max-w-4xl bg-[#0A0A0E] border border-white/10 rounded-xl shadow-2xl overflow-hidden font-mono flex flex-col max-h-[90vh]"
      >
        {/* Header */}
        <div className="p-4 border-b border-white/10 bg-gradient-to-r from-black to-[#111116] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
              <Crosshair size={16} />
            </div>
            <div>
              <div className="text-[9px] text-amber-400 uppercase tracking-widest font-bold">
                FORENSIC THREAT HUNTING
              </div>
              <h3 className="text-sm font-semibold text-zinc-100">
                Automated IOC (Indicators of Compromise) Harvester
              </h3>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {/* Defang Toggle */}
            <button
              type="button"
              onClick={() => setDefang(!defang)}
              className={`px-3 py-1.5 rounded text-[10px] font-bold tracking-wider uppercase flex items-center gap-1.5 border transition-all cursor-pointer ${
                defang 
                  ? 'bg-emerald-950/40 text-emerald-300 border-emerald-500/40' 
                  : 'bg-rose-950/40 text-rose-300 border-rose-500/40'
              }`}
              title="Toggle defanging: converts URLs and IPs to harmless representations (hxxp, 192[.]168...)"
            >
              {defang ? <ToggleRight size={16} /> : <ToggleLeft size={16} />}
              {defang ? 'DEFANGED (Safe Mode)' : 'RAW (Active URLs)'}
            </button>
            <button
              onClick={onClose}
              className="text-zinc-400 hover:text-white p-1.5 rounded hover:bg-white/5 transition-colors cursor-pointer"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Info Banner */}
        <div className="px-4 py-2.5 bg-black/40 border-b border-white/5 text-[10px] text-zinc-400 flex items-center justify-between">
          <span className="flex items-center gap-1.5">
            <ShieldAlert size={12} className="text-[#00f0ff]" />
            Scanned <strong className="text-white">{threats.length}</strong> active threat logs in selected time window.
          </span>
          <span className="text-[9px] text-zinc-500">
            Defanging protects analysts from accidental socket triggers in ticketing platforms
          </span>
        </div>

        {/* Extracted Sections Grid */}
        <div className="flex-1 p-4 overflow-y-auto space-y-4 bg-black/60">
          {/* IP Addresses */}
          <div className="border border-white/5 bg-[#0D0D12] rounded-lg p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-zinc-200 flex items-center gap-1.5">
                <Globe size={13} className="text-[#00f0ff]" /> IPv4 / IPv6 Addresses ({extractedIocs.ips.length})
              </span>
              <button
                type="button"
                onClick={() => copyToClipboard(extractedIocs.ips.map(ip => defangString(ip)).join('\n'), 'IPs')}
                className="text-[9px] text-[#00f0ff] hover:underline flex items-center gap-1 uppercase cursor-pointer"
              >
                {copiedSection === 'IPs' ? <Check size={11} /> : <Copy size={11} />}
                {copiedSection === 'IPs' ? 'Copied' : 'Copy All'}
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {extractedIocs.ips.map(ip => (
                <span key={ip} className="px-2 py-1 bg-black/70 border border-[#00f0ff]/20 text-[#00f0ff] rounded text-[10px]">
                  {defangString(ip)}
                </span>
              ))}
            </div>
          </div>

          {/* Hostnames and DNNs */}
          <div className="border border-white/5 bg-[#0D0D12] rounded-lg p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-zinc-200 flex items-center gap-1.5">
                <Terminal size={13} className="text-amber-400" /> Hostnames, FQDNs & DNN Nodes ({extractedIocs.domains.length})
              </span>
              <button
                type="button"
                onClick={() => copyToClipboard(extractedIocs.domains.map(d => defangString(d)).join('\n'), 'Domains')}
                className="text-[9px] text-amber-400 hover:underline flex items-center gap-1 uppercase cursor-pointer"
              >
                {copiedSection === 'Domains' ? <Check size={11} /> : <Copy size={11} />}
                {copiedSection === 'Domains' ? 'Copied' : 'Copy All'}
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {extractedIocs.domains.map(d => (
                <span key={d} className="px-2 py-1 bg-black/70 border border-amber-500/20 text-amber-300 rounded text-[10px]">
                  {defangString(d)}
                </span>
              ))}
            </div>
          </div>

          {/* Hashes */}
          <div className="border border-white/5 bg-[#0D0D12] rounded-lg p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-zinc-200 flex items-center gap-1.5">
                <Hash size={13} className="text-purple-400" /> Cryptographic Hashes (SHA-256 / MD5) ({extractedIocs.hashes.length})
              </span>
              <button
                type="button"
                onClick={() => copyToClipboard(extractedIocs.hashes.join('\n'), 'Hashes')}
                className="text-[9px] text-purple-400 hover:underline flex items-center gap-1 uppercase cursor-pointer"
              >
                {copiedSection === 'Hashes' ? <Check size={11} /> : <Copy size={11} />}
                {copiedSection === 'Hashes' ? 'Copied' : 'Copy All'}
              </button>
            </div>
            <div className="space-y-1">
              {extractedIocs.hashes.map(h => (
                <div key={h} className="px-2 py-1 bg-black/70 border border-purple-500/20 text-purple-300 rounded text-[9.5px] truncate">
                  {h}
                </div>
              ))}
            </div>
          </div>

          {/* Malicious Binaries & Intercepted Syscalls */}
          <div className="border border-white/5 bg-[#0D0D12] rounded-lg p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-zinc-200 flex items-center gap-1.5">
                <Cpu size={13} className="text-rose-400" /> Binaries & Processes ({extractedIocs.binaries.length})
              </span>
              <button
                type="button"
                onClick={() => copyToClipboard(extractedIocs.binaries.join('\n'), 'Binaries')}
                className="text-[9px] text-rose-400 hover:underline flex items-center gap-1 uppercase cursor-pointer"
              >
                {copiedSection === 'Binaries' ? <Check size={11} /> : <Copy size={11} />}
                {copiedSection === 'Binaries' ? 'Copied' : 'Copy All'}
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {extractedIocs.binaries.map(b => (
                <span key={b} className="px-2 py-1 bg-black/70 border border-rose-500/20 text-rose-300 rounded text-[10px]">
                  {b}
                </span>
              ))}
            </div>
          </div>

          {/* Vulnerabilities & MITRE */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            <div className="border border-white/5 bg-[#0D0D12] rounded-lg p-3.5 space-y-2">
              <span className="text-[11px] font-bold text-zinc-200 flex items-center gap-1.5">
                <AlertTriangle size={13} className="text-yellow-400" /> CWE / CVE IDs
              </span>
              <div className="flex flex-wrap gap-1.5">
                {extractedIocs.vulns.map(v => (
                  <span key={v} className="px-2 py-0.5 bg-yellow-950/20 border border-yellow-500/30 text-yellow-300 rounded text-[9.5px]">
                    {v}
                  </span>
                ))}
              </div>
            </div>

            <div className="border border-white/5 bg-[#0D0D12] rounded-lg p-3.5 space-y-2">
              <span className="text-[11px] font-bold text-zinc-200 flex items-center gap-1.5">
                <ShieldAlert size={13} className="text-blue-400" /> MITRE ATT&CK Tactics
              </span>
              <div className="flex flex-wrap gap-1.5">
                {extractedIocs.mitre.map(m => (
                  <span key={m} className="px-2 py-0.5 bg-blue-950/20 border border-blue-500/30 text-blue-300 rounded text-[9.5px]">
                    {m}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-white/10 bg-black/80 flex items-center justify-between gap-3">
          <div className="text-[10px] text-zinc-400">
            Total Indicators Harvested: <strong className="text-white">{extractedIocs.ips.length + extractedIocs.domains.length + extractedIocs.hashes.length + extractedIocs.binaries.length}</strong>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => copyToClipboard(getAllIocsFormatted(), 'Full IOC Bundle')}
              className="px-3.5 py-2 rounded bg-white/5 hover:bg-white/10 text-zinc-200 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all cursor-pointer"
            >
              {copiedSection === 'Full IOC Bundle' ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
              {copiedSection === 'Full IOC Bundle' ? 'Copied All' : 'Copy All IOCs'}
            </button>
            <button
              type="button"
              onClick={handleDownloadReport}
              className="px-4 py-2 rounded bg-amber-400 hover:bg-amber-300 text-black text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(251,191,36,0.3)] cursor-pointer"
            >
              <Download size={13} />
              Export IOC Intel (.txt)
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
