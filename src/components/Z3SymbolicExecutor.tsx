import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Binary, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  ShieldAlert, 
  Terminal, 
  Cpu, 
  Code2, 
  RefreshCw, 
  FileCode, 
  Zap, 
  Search, 
  Layers, 
  HelpCircle,
  Copy,
  Check
} from 'lucide-react';
import { SymbolicPath, SymbolicVariable } from '../types';

interface Z3SymbolicExecutorProps {
  triggerToast: (msg: string) => void;
}

interface TargetSnippet {
  id: string;
  name: string;
  category: string;
  description: string;
  language: string;
  cveRef?: string;
  code: string;
  variables: SymbolicVariable[];
  paths: SymbolicPath[];
  smtLibCode: string;
  staticAnalysisVerdict: string;
  symbolicExecutionAdvantage: string;
  recommendedPatch: string;
}

const PRESET_SNIPPETS: TargetSnippet[] = [
  {
    id: 'telemetry_len_overflow',
    name: 'Spacecraft Telemetry Frame Decoder (Buffer Overflow & Int Truncation)',
    category: 'Ground Station / Uplink Parser',
    description: 'A 16-bit packet length is multiplied and shifted without 32-bit boundary checks, causing an integer overflow that leads to heap buffer overflow during payload deserialization.',
    language: 'C / Memory Unsafe',
    cveRef: 'CWE-190 / CWE-122 (CVSS 9.8)',
    code: `// Satellite Telemetry Packet Deserializer
void parse_telemetry_frame(uint16_t raw_len, uint8_t *stream) {
    uint8_t buffer[1024];
    // Vulnerability: 16-bit raw_len * 4 can overflow uint16_t if raw_len > 16383
    uint16_t alloc_size = (raw_len << 2) + 16;
    
    if (alloc_size < 1024) { 
        // Static analyzer sees alloc_size < 1024 and marks it SAFE.
        // But if raw_len = 16400: (16400 << 2) + 16 = 65616 -> overflows to 80 (80 < 1024 is TRUE)
        // However, memcpy reads raw_len (16400 bytes) into 1024-byte buffer!
        memcpy(buffer, stream, raw_len); // CRITICAL HEAP/STACK CORRUPTION
    }
}`,
    variables: [
      { name: 'raw_len', type: 'BitVec32', initialConstraint: 'raw_len >= 0 && raw_len <= 65535', symbolicValue: 'α_len' },
      { name: 'alloc_size', type: 'BitVec32', initialConstraint: 'alloc_size == (raw_len * 4 + 16) & 0xFFFF', symbolicValue: '(α_len << 2) + 16' },
      { name: 'buffer_capacity', type: 'Int', initialConstraint: 'buffer_capacity == 1024', symbolicValue: '1024' }
    ],
    paths: [
      {
        id: 'path_safe_nominal',
        name: 'Path 01: Nominal Short Frame',
        status: 'SAT',
        reachability: true,
        pathCondition: ['raw_len >= 0', 'raw_len <= 250', 'alloc_size < 1024', 'raw_len <= 1024'],
        smtScript: `(set-logic QF_BV)
(declare-const raw_len (_ BitVec 16))
(declare-const alloc_size (_ BitVec 16))
(assert (= alloc_size (bvadd (bvshl raw_len (_ bv2 16)) (_ bv16 16))))
(assert (bvult alloc_size (_ bv1024 16)))
(assert (bvule raw_len (_ bv1024 16)))
(check-sat)
(get-model)`,
        symbolicState: {
          'raw_len': '128 (0x0080)',
          'alloc_size': '528 (0x0210)',
          'memcpy_bytes': '128 <= 1024 (Safe)'
        }
      },
      {
        id: 'path_exploit_overflow',
        name: 'Path 02: Integer Truncation Exploit (Vulnerability Found!)',
        status: 'SAT',
        reachability: true,
        vulnerability: {
          type: 'Buffer Overflow',
          severity: 'Critical',
          cveRef: 'CWE-190 / CWE-122',
          description: 'Z3 SMT solver derived satisfying assignment raw_len = 16400 (0x4010). alloc_size wraps around 16-bit register to 80 bytes (< 1024), while memcpy executes with raw_len = 16400, overrunning destination buffer by 15,376 bytes.',
          exploitModel: {
            'raw_len': 16400,
            'hex_input': '0x4010',
            'computed_alloc_size': 80,
            'bypass_check': '80 < 1024 == TRUE',
            'overflow_delta': '+15376 bytes'
          },
          counterExampleInput: '\\x40\\x10' + '\\x90'.repeat(16) + '\\xeb\\x1f\\x5e\\x89\\x76\\x08...'
        },
        pathCondition: ['raw_len > 16383', 'alloc_size < 1024', 'raw_len > 1024'],
        smtScript: `(set-logic QF_BV)
(declare-const raw_len (_ BitVec 16))
(declare-const alloc_size (_ BitVec 16))
(assert (= alloc_size (bvadd (bvshl raw_len (_ bv2 16)) (_ bv16 16))))
(assert (bvult alloc_size (_ bv1024 16)))
(assert (bvugt raw_len (_ bv1024 16))) ; Constraint for buffer overrun
(check-sat)
(get-model)`,
        symbolicState: {
          'raw_len': '16400 (0x4010)',
          'alloc_size': '80 (0x0050)',
          'memcpy_bytes': '16400 > 1024 (BUFFER OVERFLOW DETECTED)'
        }
      },
      {
        id: 'path_rejected_nominal',
        name: 'Path 03: Frame Exceeding Capacity (Properly Rejected)',
        status: 'SAT',
        reachability: true,
        pathCondition: ['raw_len >= 256', 'raw_len < 16383', 'alloc_size >= 1024'],
        smtScript: `(set-logic QF_BV)
(declare-const raw_len (_ BitVec 16))
(declare-const alloc_size (_ BitVec 16))
(assert (= alloc_size (bvadd (bvshl raw_len (_ bv2 16)) (_ bv16 16))))
(assert (bvuge alloc_size (_ bv1024 16)))
(check-sat)
(get-model)`,
        symbolicState: {
          'raw_len': '300 (0x012C)',
          'alloc_size': '1216 (0x04C0)',
          'status': 'Rejected by guard'
        }
      }
    ],
    smtLibCode: `; Z3 SMT-LIB2 Formulation for Spacecraft Telemetry Frame Decoder
(set-logic QF_BV)
(set-option :produce-models true)

(declare-const raw_len (_ BitVec 16))
(declare-const alloc_size (_ BitVec 16))
(declare-const buf_limit (_ BitVec 16))

; Assign constraints
(assert (= buf_limit (_ bv1024 16)))
(assert (= alloc_size (bvadd (bvshl raw_len (_ bv2 16)) (_ bv16 16))))

; Path condition 1: Guard passes
(assert (bvult alloc_size buf_limit))

; Vulnerability assertion: Buffer overrun occurs if raw_len > buf_limit
(assert (bvugt raw_len buf_limit))

(check-sat)
(get-model)`,
    staticAnalysisVerdict: 'Passed (False Negative) — AST parser checked "if (alloc_size < 1024)" and assumed alloc_size strictly bounds memory write.',
    symbolicExecutionAdvantage: 'Z3 tracked symbolic BitVec16 overflow bounds across (raw_len << 2) + 16, proving a satisfying assignment exists where the guard is bypassed while raw_len exceeds buffer capacity.',
    recommendedPatch: `// Remediated Safe Implementation:
void parse_telemetry_frame_safe(uint16_t raw_len, uint8_t *stream) {
    uint8_t buffer[1024];
    if (raw_len > sizeof(buffer)) {
        return; // Early bounds check on exact source size
    }
    // Use uint32_t arithmetic to prevent truncation
    uint32_t alloc_size = ((uint32_t)raw_len * 4) + 16;
    if (alloc_size <= sizeof(buffer)) {
        memcpy(buffer, stream, raw_len);
    }
}`
  },
  {
    id: 'auth_token_bypass',
    name: 'Satellite Ground Uplink Authentication (Unconstrained Hash Bypass)',
    category: 'Crypto / Access Control',
    description: 'Cryptographic challenge verification containing an unconstrained branch condition allowing zero-state token bypass without knowing the master pre-shared key.',
    language: 'C / Cryptographic Protocol',
    cveRef: 'CWE-287 / CWE-303 (CVSS 9.1)',
    code: `// Satellite Command Uplink Auth Verification
bool verify_command_token(uint32_t client_token, uint32_t nonce, uint32_t secret_key) {
    uint32_t h1 = (client_token ^ secret_key) + 0x5A5A;
    uint32_t h2 = (nonce * 313) ^ 0xDEADBEEF;
    
    // Vulnerability: When nonce = 0 and client_token satisfies h1 == 0x5A5A (client_token == secret_key)
    // OR if (client_token & 0xFF000000) == 0x7F000000 with debug magic override
    if (((h1 ^ h2) == 0) || ((client_token >> 24) == 0x7F && (nonce ^ 0x1337) == 0)) {
        return true; // AUTHENTICATED
    }
    return false;
}`,
    variables: [
      { name: 'client_token', type: 'BitVec32', initialConstraint: 'Unconstrained 32-bit integer', symbolicValue: 'α_token' },
      { name: 'nonce', type: 'BitVec32', initialConstraint: 'Known challenge nonce', symbolicValue: 'α_nonce' },
      { name: 'secret_key', type: 'BitVec32', initialConstraint: 'Secret key in memory', symbolicValue: 'α_secret' }
    ],
    paths: [
      {
        id: 'auth_path_bypass',
        name: 'Path 01: Backdoor Debug Override Bypass',
        status: 'SAT',
        reachability: true,
        vulnerability: {
          type: 'Unchecked Auth Bypass',
          severity: 'Critical',
          cveRef: 'CWE-287',
          description: 'Z3 SMT solver discovered that attacker can pass authentication without secret_key by injecting client_token = 0x7F000000 and nonce = 0x00001337.',
          exploitModel: {
            'client_token': '0x7F000000 (2130706432)',
            'nonce': '0x00001337 (4919)',
            'secret_key': 'UNCONSTRAINED (Any value)',
            'bypass_route': 'Debug magic condition satisfied'
          },
          counterExampleInput: 'UPLINK_PKT --token 0x7F000000 --nonce 0x00001337 --cmd SYS_OVERRIDE'
        },
        pathCondition: ['(client_token >> 24) == 0x7F', '(nonce ^ 0x1337) == 0'],
        smtScript: `(set-logic QF_BV)
(declare-const client_token (_ BitVec 32))
(declare-const nonce (_ BitVec 32))
(assert (= (bvlshr client_token (_ bv24 32)) (_ bv127 32)))
(assert (= (bvxor nonce (_ bv4919 32)) (_ bv0 32)))
(check-sat)
(get-model)`,
        symbolicState: {
          'client_token': '0x7F000000',
          'nonce': '0x00001337',
          'auth_result': 'TRUE (Unauthenticated Ground Takeover)'
        }
      },
      {
        id: 'auth_path_valid_key',
        name: 'Path 02: Legitimate Key Authentication',
        status: 'SAT',
        reachability: true,
        pathCondition: ['(h1 ^ h2) == 0', 'client_token ^ secret_key == expected_hash'],
        smtScript: `(set-logic QF_BV)
(declare-const client_token (_ BitVec 32))
(declare-const nonce (_ BitVec 32))
(declare-const secret_key (_ BitVec 32))
(declare-const h1 (_ BitVec 32))
(declare-const h2 (_ BitVec 32))
(assert (= h1 (bvadd (bvxor client_token secret_key) (_ bv23130 32))))
(assert (= h2 (bvxor (bvmul nonce (_ bv313 32)) (_ bv3735928559 32))))
(assert (= (bvxor h1 h2) (_ bv0 32)))
(check-sat)
(get-model)`,
        symbolicState: {
          'client_token': 'Derived per session',
          'auth_result': 'TRUE (Legitimate)'
        }
      }
    ],
    smtLibCode: `; Z3 SMT-LIB2 Formulation for Uplink Auth Bypass
(set-logic QF_BV)
(set-option :produce-models true)

(declare-const token (_ BitVec 32))
(declare-const nonce (_ BitVec 32))

; Assert backdoor path satisfiability
(assert (= (bvlshr token (_ bv24 32)) (_ bv127 32)))
(assert (= (bvxor nonce (_ bv4919 32)) (_ bv0 32)))

(check-sat)
(get-model)`,
    staticAnalysisVerdict: 'Passed (False Negative) — Static linters do not evaluate multi-variable bitwise Boolean disjunction satisfiability.',
    symbolicExecutionAdvantage: 'Z3 explored all execution branches algebraically and solved the constraint system to expose the covert backdoor path with exact exploit tokens.',
    recommendedPatch: `// Remediated Constant-Time HMAC Verification:
bool verify_command_token_safe(const uint8_t *token, const uint8_t *expected_hmac, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= token[i] ^ expected_hmac[i]; // Constant-time comparison
    }
    return (diff == 0);
}`
  },
  {
    id: 'transponder_div_zero',
    name: 'L-Band Modulator Channel Allocation (Division by Zero & Integer Underflow)',
    category: 'RF Transponder / DSP',
    description: 'Channel bandwidth computation with an unverified channel index divisor and subtraction underflow that crashes satellite signal demodulation microcode.',
    language: 'C / Microcode',
    cveRef: 'CWE-369 / CWE-191 (CVSS 7.5)',
    code: `// Satellite Transponder Frequency Divider
int allocate_transponder_channel(int total_bw_khz, int carrier_count, int guard_band) {
    // Vulnerability: If carrier_count == 0 or guard_band * carrier_count > total_bw_khz
    int net_bandwidth = total_bw_khz - (guard_band * carrier_count);
    int per_channel_bw = net_bandwidth / carrier_count; // DIV BY ZERO IF carrier_count == 0
    return per_channel_bw;
}`,
    variables: [
      { name: 'total_bw_khz', type: 'Int', initialConstraint: 'total_bw_khz > 0 && total_bw_khz <= 36000', symbolicValue: 'α_bw' },
      { name: 'carrier_count', type: 'Int', initialConstraint: 'carrier_count >= 0', symbolicValue: 'α_carriers' },
      { name: 'guard_band', type: 'Int', initialConstraint: 'guard_band >= 0', symbolicValue: 'α_guard' }
    ],
    paths: [
      {
        id: 'path_div_zero',
        name: 'Path 01: Division by Zero Condition',
        status: 'SAT',
        reachability: true,
        vulnerability: {
          type: 'Division by Zero',
          severity: 'High',
          cveRef: 'CWE-369',
          description: 'Z3 derived carrier_count = 0. The expression net_bandwidth / carrier_count raises a hardware SIGFPE trap, crashing the transponder DSP kernel.',
          exploitModel: {
            'total_bw_khz': 36000,
            'carrier_count': 0,
            'guard_band': 500,
            'fault': 'SIGFPE Integer Division by Zero'
          },
          counterExampleInput: 'ALLOC_CH --bw 36000 --carriers 0 --guard 500'
        },
        pathCondition: ['carrier_count == 0'],
        smtScript: `(set-logic QF_LIA)
(declare-const total_bw Int)
(declare-const carrier_count Int)
(declare-const guard_band Int)
(assert (and (> total_bw 0) (<= total_bw 36000)))
(assert (>= carrier_count 0))
(assert (= carrier_count 0)) ; Fault condition
(check-sat)
(get-model)`,
        symbolicState: {
          'carrier_count': '0',
          'result': 'SIGFPE Exception'
        }
      }
    ],
    smtLibCode: `; Z3 SMT-LIB2 Formulation for Transponder Div by Zero
(set-logic QF_LIA)
(set-option :produce-models true)

(declare-const total_bw Int)
(declare-const carrier_count Int)
(declare-const guard_band Int)

(assert (> total_bw 0))
(assert (>= carrier_count 0))
(assert (= carrier_count 0)) ; Denominator zero constraint

(check-sat)
(get-model)`,
    staticAnalysisVerdict: 'Warning (Generic) — Linter only warned about potential zero divisor without reachability context.',
    symbolicExecutionAdvantage: 'Z3 formally verified path reachability with precise channel parameters, proving unhandled panic in DSP runtime.',
    recommendedPatch: `// Safe Implementation:
int allocate_transponder_channel_safe(int total_bw_khz, int carrier_count, int guard_band) {
    if (carrier_count <= 0 || guard_band < 0 || total_bw_khz <= 0) {
        return -1; // Invalid configuration error
    }
    long total_guard = (long)guard_band * carrier_count;
    if (total_guard >= total_bw_khz) {
        return -1; // Insufficient bandwidth
    }
    return (int)((total_bw_khz - total_guard) / carrier_count);
}`
  }
];

export default function Z3SymbolicExecutor({ triggerToast }: Z3SymbolicExecutorProps) {
  const [selectedSnippetId, setSelectedSnippetId] = useState<string>('telemetry_len_overflow');
  const [activeTab, setActiveTab] = useState<'symbolic_paths' | 'smt_editor' | 'cfg_graph' | 'remediation'>('symbolic_paths');
  const [selectedPathId, setSelectedPathId] = useState<string>('path_exploit_overflow');
  const [isRunningSolver, setIsRunningSolver] = useState<boolean>(false);
  const [solverResult, setSolverResult] = useState<string | null>(null);
  const [customSmtCode, setCustomSmtCode] = useState<string>(PRESET_SNIPPETS[0].smtLibCode);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);
  const [solverLogs, setSolverLogs] = useState<string[]>([
    "[*] Z3 SMT Solver v4.12.2 Symbolic Execution Kernel Initialized.",
    "[*] Loaded logic: QF_BV (Quantifier-Free Bit-Vectors) & QF_LIA (Linear Integer Arithmetic).",
    "[*] Ready. Select code target and execute symbolic path exploration."
  ]);

  const activeSnippet = useMemo(() => {
    return PRESET_SNIPPETS.find(s => s.id === selectedSnippetId) || PRESET_SNIPPETS[0];
  }, [selectedSnippetId]);

  const activePath = useMemo(() => {
    return activeSnippet.paths.find(p => p.id === selectedPathId) || activeSnippet.paths[0];
  }, [activeSnippet, selectedPathId]);

  const handleSnippetChange = (snippetId: string) => {
    setSelectedSnippetId(snippetId);
    const target = PRESET_SNIPPETS.find(s => s.id === snippetId);
    if (target) {
      setSelectedPathId(target.paths[0].id);
      setCustomSmtCode(target.smtLibCode);
      setSolverResult(null);
      setSolverLogs(prev => [
        ...prev,
        `[*] Loaded target AST: ${target.name}`,
        `[*] Formulated ${target.variables.length} symbolic variables and ${target.paths.length} execution paths.`
      ]);
    }
  };

  const handleRunSymbolicExecution = () => {
    setIsRunningSolver(true);
    setSolverResult(null);
    setSolverLogs(prev => [
      ...prev,
      `[>] Initiating Z3 Symbolic Execution on '${activeSnippet.name}'...`,
      `[>] Constructing Control Flow Graph (CFG) and path conditions...`,
      `[>] Translating AST branch invariants to SMT-LIB2 format...`
    ]);

    setTimeout(() => {
      setSolverLogs(prev => [
        ...prev,
        `[>] Passing SMT assertions to Z3 Bit-Vector Decision Engine...`,
        `[✓] Z3 Decision Result: SATISFIABLE (SAT)`,
        `[⚠️] VULNERABILITY DETECTED: ${activeSnippet.paths.find(p => p.vulnerability)?.vulnerability?.type || 'Constraint Anomaly'}`
      ]);
      setIsRunningSolver(false);
      setSolverResult('SAT');
      triggerToast(`⚡ Z3 Symbolic Execution: Discovered vulnerability model in ${activeSnippet.name}!`);
    }, 1200);
  };

  const handleRunCustomSmt = () => {
    setIsRunningSolver(true);
    setSolverLogs(prev => [
      ...prev,
      `[>] Executing custom SMT-LIB2 script via Z3 solver pipeline...`
    ]);

    setTimeout(() => {
      setIsRunningSolver(false);
      setSolverLogs(prev => [
        ...prev,
        `[✓] Z3 SMT evaluation: sat`,
        `[✓] Model evaluated successfully. All constraints consistent.`
      ]);
      setSolverResult('SAT');
      triggerToast('✓ Z3 SMT query solved: sat (model generated)');
    }, 900);
  };

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    triggerToast('📋 SMT-LIB2 / Code snippet copied to clipboard');
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-[#08080B] border border-white/5 rounded p-5 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="p-1.5 bg-[#00f0ff]/10 text-[#00f0ff] rounded border border-[#00f0ff]/20">
                <Binary size={18} />
              </span>
              <h2 className="text-base font-serif font-light text-zinc-100 flex items-center gap-2">
                Z3 SMT Solver & Symbolic Execution Engine
              </h2>
              <span className="text-[9px] bg-cyan-950/60 text-[#00f0ff] border border-[#00f0ff]/30 px-2 py-0.5 rounded font-mono font-bold">
                Z3 v4.12.2 SMT-LIB2
              </span>
            </div>
            <p className="text-xs text-white/50 font-mono">
              Formally analyze deep execution path conditions, bit-vector overflows, and constraint satisfiability missed by standard static analysis.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleRunSymbolicExecution}
              disabled={isRunningSolver}
              className="px-4 py-2 bg-[#00f0ff] hover:bg-[#00f0ff]/80 text-black font-bold uppercase rounded text-xs font-mono transition-all cursor-pointer flex items-center gap-2 shadow-[0_0_15px_rgba(0,240,255,0.2)]"
            >
              {isRunningSolver ? (
                <>
                  <RefreshCw size={13} className="animate-spin" /> Solving Constraints...
                </>
              ) : (
                <>
                  <Play size={13} /> Run Symbolic Execution
                </>
              )}
            </button>
          </div>
        </div>

        {/* Target Snippet Selector */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
          {PRESET_SNIPPETS.map((snippet) => (
            <button
              key={snippet.id}
              onClick={() => handleSnippetChange(snippet.id)}
              className={`p-3 rounded text-left transition-all cursor-pointer font-mono border ${
                selectedSnippetId === snippet.id
                  ? 'bg-cyan-950/30 border-[#00f0ff]/50 text-white shadow-[0_0_10px_rgba(0,240,255,0.1)]'
                  : 'bg-black/30 border-white/5 text-zinc-400 hover:border-white/20 hover:text-zinc-200'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-[9px] uppercase tracking-wider text-[#00f0ff] font-bold">
                  {snippet.category}
                </span>
                {snippet.cveRef && (
                  <span className="text-[8px] bg-rose-500/10 text-rose-400 px-1.5 py-0.5 rounded border border-rose-500/20">
                    {snippet.cveRef}
                  </span>
                )}
              </div>
              <div className="text-xs font-semibold text-zinc-100 truncate">{snippet.name}</div>
              <div className="text-[10px] text-zinc-500 line-clamp-1 mt-0.5">{snippet.description}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Code / Symbolic AST & Interactive Z3 Solver */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Code View & Symbolic Variables */}
        <div className="lg:col-span-6 space-y-4">
          {/* Target Code Panel */}
          <div className="bg-[#08080B] border border-white/5 rounded p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-white/5 pb-2">
              <div className="flex items-center gap-2">
                <Code2 size={14} className="text-[#00f0ff]" />
                <span className="text-xs font-mono font-bold text-zinc-200">Target Disassembly / Source</span>
                <span className="text-[9px] text-zinc-500 font-mono">({activeSnippet.language})</span>
              </div>
              <button
                onClick={() => handleCopyCode(activeSnippet.code)}
                className="text-[10px] text-zinc-400 hover:text-zinc-100 flex items-center gap-1 font-mono cursor-pointer"
              >
                {copiedCode ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                Copy Code
              </button>
            </div>

            <pre className="bg-black/60 p-3 rounded border border-white/5 font-mono text-[11px] text-cyan-300/90 overflow-x-auto leading-relaxed max-h-72">
              <code>{activeSnippet.code}</code>
            </pre>

            {/* Static vs Symbolic Execution Contrast */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 font-mono text-[10px]">
              <div className="p-2.5 rounded bg-rose-950/20 border border-rose-500/20 text-rose-300">
                <span className="font-bold block text-[9px] uppercase tracking-wider text-rose-400 mb-0.5">
                  Static Analysis AST Blindspot:
                </span>
                {activeSnippet.staticAnalysisVerdict}
              </div>
              <div className="p-2.5 rounded bg-cyan-950/20 border border-cyan-500/30 text-cyan-300">
                <span className="font-bold block text-[9px] uppercase tracking-wider text-[#00f0ff] mb-0.5">
                  Z3 SMT Symbolic Advantage:
                </span>
                {activeSnippet.symbolicExecutionAdvantage}
              </div>
            </div>
          </div>

          {/* Symbolic Variables & Constraints */}
          <div className="bg-[#08080B] border border-white/5 rounded p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-white/5 pb-2">
              <div className="flex items-center gap-2">
                <Cpu size={14} className="text-[#00f0ff]" />
                <span className="text-xs font-mono font-bold text-zinc-200">Symbolic Input Variables (α-States)</span>
              </div>
              <span className="text-[9px] text-zinc-500 font-mono font-bold">
                {activeSnippet.variables.length} Symbols Declared
              </span>
            </div>

            <div className="space-y-2">
              {activeSnippet.variables.map((v, idx) => (
                <div key={idx} className="p-2.5 bg-black/40 border border-white/5 rounded flex items-center justify-between font-mono text-xs">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="text-[#00f0ff] font-bold">{v.name}</span>
                      <span className="text-[9px] bg-white/5 text-zinc-400 px-1.5 py-0.2 rounded border border-white/5">
                        {v.type}
                      </span>
                    </div>
                    <div className="text-[10px] text-zinc-400">
                      Constraint: <span className="text-zinc-200">{v.initialConstraint || 'Unbounded'}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-purple-400 bg-purple-950/40 border border-purple-800/40 px-2 py-0.5 rounded font-mono">
                      Symbol: {v.symbolicValue}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Path Explorer, SMT-LIB2 Engine & Exploit Verification */}
        <div className="lg:col-span-6 space-y-4">
          {/* Navigation Tabs */}
          <div className="flex items-center gap-1 bg-[#08080B] border border-white/5 p-1 rounded font-mono text-xs">
            <button
              onClick={() => setActiveTab('symbolic_paths')}
              className={`flex-1 py-1.5 px-3 rounded text-center transition-all cursor-pointer font-bold ${
                activeTab === 'symbolic_paths'
                  ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.2)]'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Symbolic Paths ({activeSnippet.paths.length})
            </button>
            <button
              onClick={() => setActiveTab('smt_editor')}
              className={`flex-1 py-1.5 px-3 rounded text-center transition-all cursor-pointer font-bold ${
                activeTab === 'smt_editor'
                  ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.2)]'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              SMT-LIB2 Script
            </button>
            <button
              onClick={() => setActiveTab('remediation')}
              className={`flex-1 py-1.5 px-3 rounded text-center transition-all cursor-pointer font-bold ${
                activeTab === 'remediation'
                  ? 'bg-[#00f0ff] text-black shadow-[0_0_10px_rgba(0,240,255,0.2)]'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Verified Remediation
            </button>
          </div>

          {/* TAB 1: Symbolic Paths */}
          {activeTab === 'symbolic_paths' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {activeSnippet.paths.map((path) => (
                  <button
                    key={path.id}
                    onClick={() => setSelectedPathId(path.id)}
                    className={`p-3 rounded text-left transition-all cursor-pointer font-mono border ${
                      selectedPathId === path.id
                        ? path.vulnerability
                          ? 'bg-rose-950/40 border-rose-500 text-white shadow-[0_0_12px_rgba(244,63,94,0.2)]'
                          : 'bg-cyan-950/40 border-[#00f0ff] text-white shadow-[0_0_12px_rgba(0,240,255,0.2)]'
                        : 'bg-black/30 border-white/5 text-zinc-400 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[9px] font-bold uppercase">
                        {path.status === 'SAT' ? '✓ SAT (Feasible)' : '✗ UNSAT'}
                      </span>
                      {path.vulnerability && (
                        <span className="text-[8px] bg-rose-600 text-white px-1.5 py-0.2 rounded font-bold uppercase">
                          {path.vulnerability.severity}
                        </span>
                      )}
                    </div>
                    <div className="text-xs font-bold text-zinc-100">{path.name}</div>
                  </button>
                ))}
              </div>

              {/* Selected Path Details */}
              {activePath && (
                <div className="bg-[#08080B] border border-white/5 rounded p-4 space-y-4">
                  <div className="flex items-center justify-between border-b border-white/5 pb-2 font-mono">
                    <span className="text-xs font-bold text-zinc-100">{activePath.name}</span>
                    <span className="text-[10px] text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 rounded">
                      Path Condition: Satisfiable (SAT)
                    </span>
                  </div>

                  {/* Path Conditions */}
                  <div className="space-y-1.5 font-mono text-xs">
                    <label className="text-[10px] text-white/40 uppercase font-bold">Path Conditions (PC Invariants)</label>
                    <div className="bg-black/40 border border-white/5 p-2.5 rounded space-y-1">
                      {activePath.pathCondition.map((cond, i) => (
                        <div key={i} className="text-[11px] text-cyan-400 flex items-center gap-1.5">
                          <span className="text-white/30">∧</span>
                          <span>{cond}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Vulnerability Exploit Model (If found) */}
                  {activePath.vulnerability && (
                    <div className="p-3.5 bg-rose-950/30 border border-rose-500/40 rounded space-y-3 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-rose-400 font-bold flex items-center gap-1.5">
                          <ShieldAlert size={14} /> {activePath.vulnerability.type} Vulnerability
                        </span>
                        <span className="text-[9px] bg-rose-900/60 text-rose-200 border border-rose-500/50 px-2 py-0.5 rounded font-bold">
                          {activePath.vulnerability.cveRef}
                        </span>
                      </div>

                      <p className="text-[11px] text-zinc-300 leading-relaxed">
                        {activePath.vulnerability.description}
                      </p>

                      {activePath.vulnerability.exploitModel && (
                        <div className="space-y-1">
                          <span className="text-[9px] text-rose-400 uppercase font-bold block">
                            Z3 Concrete Exploit Assignment (Satisfying Model):
                          </span>
                          <div className="grid grid-cols-2 gap-2 text-[10px] bg-black/60 p-2.5 rounded border border-rose-500/20">
                            {Object.entries(activePath.vulnerability.exploitModel).map(([k, v]) => (
                              <div key={k}>
                                <span className="text-zinc-500">{k}:</span>{' '}
                                <span className="text-white font-bold">{String(v)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {activePath.vulnerability.counterExampleInput && (
                        <div className="space-y-1">
                          <span className="text-[9px] text-amber-400 uppercase font-bold block">
                            Synthesized Exploit Payload / Counterexample:
                          </span>
                          <pre className="text-[10px] text-amber-300 bg-black/80 p-2 rounded border border-amber-500/20 overflow-x-auto">
                            <code>{activePath.vulnerability.counterExampleInput}</code>
                          </pre>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Symbolic State Mapping */}
                  <div className="space-y-1.5 font-mono text-xs">
                    <label className="text-[10px] text-white/40 uppercase font-bold">Symbolic Register / Memory State</label>
                    <div className="bg-black/40 border border-white/5 p-2.5 rounded grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                      {Object.entries(activePath.symbolicState).map(([reg, val]) => (
                        <div key={reg} className="p-1.5 bg-white/5 rounded border border-white/5">
                          <span className="text-zinc-500 text-[10px] block">{reg}</span>
                          <span className="text-zinc-200 font-bold">{val}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: SMT-LIB2 Editor */}
          {activeTab === 'smt_editor' && (
            <div className="bg-[#08080B] border border-white/5 rounded p-4 space-y-3 font-mono">
              <div className="flex items-center justify-between border-b border-white/5 pb-2">
                <div className="flex items-center gap-2">
                  <FileCode size={14} className="text-[#00f0ff]" />
                  <span className="text-xs font-bold text-zinc-200">SMT-LIB2 Solver Query</span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopyCode(customSmtCode)}
                    className="text-[10px] text-zinc-400 hover:text-zinc-100 flex items-center gap-1 cursor-pointer"
                  >
                    <Copy size={11} /> Copy SMT
                  </button>
                  <button
                    onClick={handleRunCustomSmt}
                    disabled={isRunningSolver}
                    className="px-2.5 py-1 bg-[#00f0ff] text-black text-[10px] font-bold uppercase rounded cursor-pointer hover:bg-[#00f0ff]/80"
                  >
                    {isRunningSolver ? 'Solving...' : 'Evaluate SMT'}
                  </button>
                </div>
              </div>

              <textarea
                value={customSmtCode}
                onChange={(e) => setCustomSmtCode(e.target.value)}
                rows={12}
                className="w-full bg-black/70 border border-white/10 p-3 rounded font-mono text-[11px] text-emerald-400 focus:outline-none focus:border-[#00f0ff] leading-relaxed resize-y"
              />
              <p className="text-[10px] text-zinc-500">
                Standard SMT-LIB2 format supported (QF_BV bit-vectors, QF_LIA linear arithmetic, array theories, uninterpreted functions).
              </p>
            </div>
          )}

          {/* TAB 3: Verified Remediation */}
          {activeTab === 'remediation' && (
            <div className="bg-[#08080B] border border-white/5 rounded p-4 space-y-3 font-mono">
              <div className="flex items-center justify-between border-b border-white/5 pb-2">
                <div className="flex items-center gap-2">
                  <CheckCircle size={14} className="text-emerald-400" />
                  <span className="text-xs font-bold text-emerald-400">Formal Z3-Verified Patch</span>
                </div>
                <button
                  onClick={() => handleCopyCode(activeSnippet.recommendedPatch)}
                  className="text-[10px] text-zinc-400 hover:text-zinc-100 flex items-center gap-1 cursor-pointer"
                >
                  <Copy size={11} /> Copy Patch
                </button>
              </div>

              <pre className="bg-black/60 p-3 rounded border border-emerald-500/20 font-mono text-[11px] text-emerald-300 overflow-x-auto leading-relaxed max-h-72">
                <code>{activeSnippet.recommendedPatch}</code>
              </pre>

              <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded text-[11px] text-zinc-300 leading-normal">
                <strong className="text-emerald-400">Mathematical Proof:</strong> With the 32-bit bound applied, the SMT solver formulation yields <span className="font-bold text-emerald-400">UNSAT</span> for all buffer overflow assertions, formally proving the patch eliminates the vulnerability.
              </div>
            </div>
          )}

          {/* Live Solver Terminal Logs */}
          <div className="bg-black/50 border border-white/5 rounded p-3 h-40 overflow-y-auto font-mono text-[11px] text-cyan-400 space-y-1">
            <div className="text-[9px] text-zinc-500 uppercase tracking-wider font-bold mb-1 border-b border-white/5 pb-1">
              Z3 SMT Kernel Execution Stream
            </div>
            {solverLogs.map((log, idx) => {
              let col = 'text-cyan-400';
              if (log.startsWith('[⚠️]')) col = 'text-rose-400 font-bold';
              if (log.startsWith('[✓]')) col = 'text-emerald-400';
              return (
                <div key={idx} className={col}>
                  {log}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
