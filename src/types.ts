export type ActiveTool = 'operational-dashboard' | 'vuln-scanner' | 'penetration-framework' | 'network-analysis' | 'z3-symbolic' | 'hardware-tee' | 'entropy' | 'ast' | 'ebpf' | 'pe' | 'signature' | 'crypto' | 'sandbox' | 'waf' | 'wireless' | 'console' | 'archive' | 'overviews' | 'ai-coprocessor' | 'yara' | 'decryption-validator';

export interface SysCallAlert {
  id: string;
  timestamp: string;
  pid: number;
  ppid: number;
  comm: string;
  syscall: string;
  args: string;
  status: 'allowed' | 'intercepted';
  severity: 'low' | 'medium' | 'high';
}

export interface ArchivedThreat {
  id: string;
  timestamp: string;
  category: 'ebpf' | 'ast';
  name: string;
  severity: 'low' | 'medium' | 'high';
  details: string;
  rawPayload: string;
  notes?: string;
  status: 'Unresolved' | 'Triaged' | 'Remediated' | 'False Positive';
  assignedOfficer?: string;
  meta: Record<string, any>;
}

export interface EbpfRule {
  id: string;
  name: string;
  type: 'comm' | 'syscall' | 'path';
  pattern: string;
  action: 'allow' | 'block';
  active: boolean;
}

export interface PeSection {
  name: string;
  virtualSize: number;
  virtualAddress: string;
  rawSize: number;
  rawAddress: string;
  entropy: number;
  characteristics: string[];
  anomalous: boolean;
}

export interface PeFileMetadata {
  fileName: string;
  fileSize: number;
  magic: string;
  machine: string;
  numberOfSections: number;
  timeDateStamp: string;
  entryPoint: string;
  subsystem: string;
  sections: PeSection[];
  imports: string[];
}

// Z3 SMT Symbolic Execution Interfaces
export interface SymbolicVariable {
  name: string;
  type: 'Int' | 'BitVec32' | 'BitVec64' | 'Bool' | 'String';
  initialConstraint?: string;
  symbolicValue: string;
}

export interface SymbolicPath {
  id: string;
  name: string;
  status: 'SAT' | 'UNSAT' | 'UNKNOWN';
  pathCondition: string[];
  smtScript: string;
  reachability: boolean;
  vulnerability?: {
    type: 'Buffer Overflow' | 'Integer Underflow' | 'Unchecked Auth Bypass' | 'Division by Zero' | 'Use-After-Free' | 'Format String';
    severity: 'Critical' | 'High' | 'Medium';
    cveRef?: string;
    description: string;
    exploitModel?: Record<string, string | number | boolean>;
    counterExampleInput?: string;
  };
  symbolicState: Record<string, string>;
}

// Hardware TEE (Intel SGX / AMD SEV) Interfaces
export type TeePlatform = 'Intel SGX' | 'AMD SEV-SNP' | 'ARM TrustZone / Realm';

export interface EnclaveMeasurement {
  mrEnclave: string; // Hash of enclave memory pages at initialization
  mrSigner: string;  // Hash of ISV key that signed enclave
  isvProdId: number;
  isvSvn: number;
  attributes: {
    debugMode: boolean;
    mode64bit: boolean;
    kssEnabled: boolean;
    memorySizeMb: number;
  };
}

export interface SealedKeyVaultItem {
  id: string;
  label: string;
  keyType: 'AES-256-GCM' | 'Ed25519-Private' | 'HMAC-SHA256' | 'RSA-4096-Private' | '313-BIND-RootKey';
  sealedData: string; // Ciphertext
  authTag: string;
  policy: 'POLICY_MRENCLAVE' | 'POLICY_MRSIGNER';
  createdAt: string;
  lastAccessTime?: string;
  isSealed: boolean;
}

export interface AttestationQuote {
  quoteId: string;
  teeType: TeePlatform;
  timestamp: string;
  nonceChallenge: string;
  reportDataHash: string; // SHA256(challenge || agent_pubkey)
  measurement: EnclaveMeasurement;
  qeReport: {
    qeSvn: number;
    pckCertChain: string;
    ecdsaSignature: string;
  };
  verificationStatus: 'VERIFIED_VALID' | 'SIGNATURE_INVALID' | 'MEASUREMENT_MISMATCH' | 'TCB_OUT_OF_DATE';
}

