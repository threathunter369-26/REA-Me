/**
 * Eleven AI Reverse Engineering & Binary Analysis Platform
 * TypeScript Data Models and Schema Definitions
 */

export type ArtifactType = 
  | 'elf'
  | 'pe'
  | 'macho'
  | 'shader'
  | 'model'
  | 'firmware'
  | 'source_archive'
  | 'app';

export type TargetArchitecture = 
  | 'x86_64'
  | 'aarch64'
  | 'armv7'
  | 'spirv'
  | 'metal'
  | 'universal';

export type AnalysisProfile = 
  | 'quick'
  | 'standard'
  | 'deep'
  | 'security';

export type AnalysisEngineId = 
  | 'eleven-static'
  | 'ghidra-mcp'
  | 'rea-assistant'
  | 'reverse-skill';

export type ExecutionSafetyMode = 
  | 'static-only'
  | 'sandbox-prompt'
  | 'isolated-sandbox';

export interface Artifact {
  id: string;
  name: string;
  size: number;
  type: ArtifactType;
  formatDetails: string;
  architecture: TargetArchitecture;
  sha256: string;
  md5: string;
  uploadedAt: string;
  status: 'uploaded' | 'analyzing' | 'analyzed' | 'failed';
  iconType: 'binary' | 'app' | 'model' | 'shader' | 'archive';
  description?: string;
  chatCount?: number;
  lastAnalyzed?: string;
}

export interface AnalysisConfig {
  profile: AnalysisProfile;
  engines: AnalysisEngineId[];
  safetyMode: ExecutionSafetyMode;
  targetArchitecture: TargetArchitecture;
  decompileAll: boolean;
  extractStrings: boolean;
  computeEntropy: boolean;
  runVulnerabilityScan: boolean;
  timeoutSeconds: number;
  customQuestions: string[];
}

export interface ToolLogItem {
  id: string;
  timestamp: string;
  tool: string;
  status: 'running' | 'success' | 'warn' | 'error';
  message: string;
  durationMs?: number;
  details?: Record<string, unknown>;
}

export interface AnalysisStage {
  id: string;
  name: string;
  description: string;
  status: 'pending' | 'running' | 'completed' | 'error';
  progress: number;
  durationMs?: number;
  findingsCount?: number;
}

export interface SectionInfo {
  name: string;
  virtualAddress: string;
  virtualSize: number;
  rawSize: number;
  entropy: number; // 0.0 to 8.0 (Shannon entropy)
  permissions: {
    read: boolean;
    write: boolean;
    execute: boolean;
  };
  characteristics: string[];
}

export interface AsmInstruction {
  address: string;
  bytes: string;
  mnemonic: string;
  operands: string;
  comment?: string;
  xref?: string;
  isJumpOrCall?: boolean;
}

export interface CfgBlock {
  id: string;
  label: string;
  startAddress: string;
  endAddress: string;
  instructions: AsmInstruction[];
  successors: string[]; // block IDs
  predecessors: string[];
  branchType?: 'conditional' | 'unconditional' | 'call' | 'return';
  isEntry?: boolean;
  isExit?: boolean;
}

export interface FunctionInfo {
  id: string;
  name: string;
  address: string;
  size: number;
  cyclomaticComplexity: number;
  callersCount: number;
  calleesCount: number;
  callers: string[];
  callees: string[];
  isExported: boolean;
  isVulnerable: boolean;
  signature: string;
  decompiledCode: string;
  assemblyInstructions: AsmInstruction[];
  cfgBlocks: CfgBlock[];
}

export interface StringItem {
  id: string;
  value: string;
  address: string;
  section: string;
  length: number;
  category: 'url' | 'path' | 'command' | 'crypto_key' | 'general' | 'registry';
  suspicious: boolean;
}

export interface ImportExportItem {
  id: string;
  library: string;
  functionName: string;
  ordinal?: number;
  address?: string;
  type: 'import' | 'export';
  isDangerous: boolean;
  riskNote?: string;
}

export interface SecurityFinding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cweId: string;
  cvss: number;
  category: string;
  description: string;
  functionName?: string;
  address?: string;
  snippet?: string;
  detectedBy: AnalysisEngineId;
  remediation: string;
  confidence: 'verified' | 'high' | 'heuristic';
}

export interface BinaryMetadata {
  fileFormat: string;
  architecture: TargetArchitecture;
  subArchitecture?: string;
  bitness: 32 | 64;
  endianness: 'little' | 'big';
  entryPoint: string;
  imageBase: string;
  compiler: string;
  packerDetected?: string;
  sectionsCount: number;
  symbolsCount: number;
  importsCount: number;
  exportsCount: number;
  overallEntropy: number;
  mitigations: {
    aslrPie: boolean;
    depNx: boolean;
    stackCanary: boolean;
    relro: 'full' | 'partial' | 'none';
    authenticodeSigned?: boolean;
    hardenedRuntime?: boolean;
  };
}

export interface AnalysisResult {
  artifactId: string;
  jobId: string;
  completedAt: string;
  metadata: BinaryMetadata;
  sections: SectionInfo[];
  functions: FunctionInfo[];
  strings: StringItem[];
  importsExports: ImportExportItem[];
  findings: SecurityFinding[];
  entropyChunks: { offset: number; entropy: number; sectionName: string }[];
  summary: {
    overview: string;
    keyBehaviors: string[];
    riskScore: number; // 0 - 100
    securityPosture: 'Clean' | 'Suspicious' | 'High Risk' | 'Malicious Patterns Detected';
    decompiledCoveragePercent: number;
  };
  toolLogs: ToolLogItem[];
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  toolInvocations?: {
    tool: string;
    engine: AnalysisEngineId;
    status: 'completed' | 'running';
    query?: string;
  }[];
  evidenceRefs?: {
    type: 'function' | 'address' | 'finding' | 'section';
    title: string;
    targetId: string;
  }[];
}

export interface AuditLog {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  resource: string;
  status: 'allowed' | 'quarantined' | 'completed' | 'denied';
  ipAddress: string;
  details: string;
}

export interface YaraRule {
  id: string;
  name: string;
  tags: string[];
  meta: {
    author: string;
    description: string;
    reference?: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    threatGroup?: string;
    date: string;
  };
  ruleText: string;
  enabled: boolean;
}

export interface YaraMatchResult {
  ruleId: string;
  ruleName: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  matchedOffsets: {
    identifier: string;
    offset: string;
    preview: string;
  }[];
}

export interface MitreAttackTechnique {
  id: string; // e.g. T1055
  name: string; // Process Injection
  tactic: 'Initial Access' | 'Execution' | 'Persistence' | 'Privilege Escalation' | 'Defense Evasion' | 'Credential Access' | 'Discovery' | 'Command and Control' | 'Exfiltration';
  description: string;
  matchedApis: string[];
  matchedStrings: string[];
  confidence: 'verified' | 'high' | 'heuristic';
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface CapaCapability {
  id: string;
  namespace: string;
  name: string;
  description: string;
  scope: 'file' | 'function';
  addresses: string[];
  attAndCk: string[];
}

export interface DeobfuscatedString {
  id: string;
  originalAddress: string;
  rawSample: string;
  decodedValue: string;
  method: 'xor_single' | 'xor_multibyte' | 'base64' | 'rot13' | 'stack_string';
  keyUsed?: string;
  category: 'c2_url' | 'command' | 'registry' | 'file_path' | 'internal_api' | 'general';
  suspicious: boolean;
}

export interface CpuRegisters {
  rax: string;
  rbx: string;
  rcx: string;
  rdx: string;
  rsi: string;
  rdi: string;
  rbp: string;
  rsp: string;
  r8: string;
  r9: string;
  r10: string;
  r11: string;
  r12: string;
  r13: string;
  r14: string;
  r15: string;
  rip: string;
  flags: {
    cf: boolean; // Carry
    zf: boolean; // Zero
    sf: boolean; // Sign
    of: boolean; // Overflow
    pf: boolean; // Parity
    af: boolean; // Auxiliary
  };
}

export interface Breakpoint {
  id: string;
  address: string;
  functionName?: string;
  enabled: boolean;
  hitCount: number;
  condition?: string;
}

export interface StackFrameEntry {
  address: string;
  offsetFromRsp: string;
  valueHex: string;
  resolvedSymbol?: string;
  description?: string;
}

export interface ApiCallEvent {
  id: string;
  seq: number;
  timestamp: string;
  threadId: string;
  library: string;
  apiName: string;
  category: 'memory' | 'registry' | 'network' | 'filesystem' | 'process' | 'system' | 'crypto';
  parameters: {
    name: string;
    value: string;
    interpreted?: string;
  }[];
  returnValue: string;
  durationUs: number;
  isSuspicious: boolean;
  riskNote?: string;
}

// ==========================================
// Data Flow & Taint Analysis Schema
// ==========================================

export type TaintSourceType =
  | 'network_socket'
  | 'file_input'
  | 'user_arg'
  | 'environment_var'
  | 'registry'
  | 'ipc';

export type TaintSinkType =
  | 'buffer_copy'
  | 'format_string'
  | 'system_exec'
  | 'memory_write'
  | 'sql_query'
  | 'crypto_seed';

export type DataFlowSanitization = 'unsanitized' | 'partially_checked' | 'sanitized';

export interface DataFlowNode {
  id: string;
  label: string;
  instructionAddress?: string;
  functionName: string;
  type: 'source' | 'propagation' | 'sanitizer' | 'sink' | 'phi';
  description: string;
  variableName?: string;
  registersInvolved?: string[];
  codeSnippet?: string;
  isTainted: boolean;
  taintLevel: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  posX?: number;
  posY?: number;
}

export interface DataFlowEdge {
  id: string;
  fromNodeId: string;
  toNodeId: string;
  edgeType:
    | 'direct_assignment'
    | 'arithmetic'
    | 'pointer_deref'
    | 'call_argument'
    | 'return_val'
    | 'control_dependency';
  label?: string;
  isTaintedPath?: boolean;
}

export interface DefUseNode {
  variable: string;
  defAddress: string;
  defInstruction: string;
  useAddresses: string[];
  useInstructions: string[];
  scope: string;
  storage: 'register' | 'stack' | 'heap' | 'data_segment';
}

export interface TaintPath {
  id: string;
  title: string;
  functionName: string;
  source: {
    type: TaintSourceType;
    api: string;
    address: string;
    variable: string;
  };
  sink: {
    type: TaintSinkType;
    api: string;
    address: string;
    variable: string;
    cweId: string;
  };
  sanitization: DataFlowSanitization;
  exploitability: 'critical' | 'high' | 'medium' | 'low';
  nodes: DataFlowNode[];
  edges: DataFlowEdge[];
  defUseChains?: DefUseNode[];
  summary: string;
  remediationAdvice: string;
}

// ==========================================
// Signature Database Management Schema
// ==========================================

export type SignatureType = 'flirt' | 'yara' | 'hash' | 'byte_pattern' | 'threat_actor';
export type SignatureCategory =
  | 'crypto'
  | 'malware'
  | 'packer'
  | 'compiler_rt'
  | 'c2'
  | 'injection'
  | 'library';

export interface SignatureRecord {
  id: string;
  name: string;
  type: SignatureType;
  category: SignatureCategory;
  pattern: string;
  wildcardMask?: string;
  description: string;
  targetArch: TargetArchitecture | 'all';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'exact' | 'heuristic' | 'fuzzy';
  source:
    | 'Eleven ThreatLab'
    | 'Community'
    | 'User Custom'
    | 'Ghidra SigDB'
    | 'VirusTotal YARA';
  version: string;
  lastUpdated: string;
  hitCount: number;
  enabled: boolean;
  matchedFunctions?: string[];
}

export interface SignatureMatchResult {
  signatureId: string;
  signatureName: string;
  type: SignatureType;
  category: SignatureCategory;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  offset: string;
  matchedFunction?: string;
  confidence: 'exact' | 'heuristic' | 'fuzzy';
  snippet: string;
  timestamp: string;
}

// ==========================================
// VEX-IR Intermediate Representation & Taint Schema
// ==========================================

export type VexArchitecture = 'amd64' | 'x86' | 'arm' | 'arm64' | 'mips32';

export type VexType =
  | 'Ity_I1'
  | 'Ity_I8'
  | 'Ity_I16'
  | 'Ity_I32'
  | 'Ity_I64'
  | 'Ity_V128'
  | 'Ity_V256';

export type VexJumpKind =
  | 'Ijk_Boring'
  | 'Ijk_Call'
  | 'Ijk_Ret'
  | 'Ijk_Yield'
  | 'Ijk_SigTRAP'
  | 'Ijk_NoDecode';

export type VexStatementTag =
  | 'IMark'
  | 'WrTmp'
  | 'Put'
  | 'PutI'
  | 'Store'
  | 'Exit'
  | 'AbiHint'
  | 'Dirty'
  | 'MBE';

export interface VexTempDecl {
  id: string; // e.g., "t0", "t1"
  type: VexType;
}

export interface VexStatement {
  id: string;
  tag: VexStatementTag;
  lineNum: number;
  instructionAddress?: string;
  instructionLength?: number;
  rawAsm?: string;
  temp?: string;
  tempType?: VexType;
  expression?: string;
  targetOffset?: number;
  targetRegister?: string;
  sourceExpr?: string;
  storeAddrExpr?: string;
  storeDataExpr?: string;
  guardExpr?: string;
  exitTarget?: string;
  comment?: string;
  // Dynamic taint analysis annotation
  isTainted?: boolean;
  taintLevel?: 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'sanitized';
  taintReason?: string;
  taintOrigin?: string;
}

export interface VexIRSB {
  id: string;
  name: string;
  functionName: string;
  architecture: VexArchitecture;
  entryAddress: string;
  sizeBytes: number;
  instructionCount: number;
  temps: VexTempDecl[];
  statements: VexStatement[];
  exitTarget: string;
  jumpKind: VexJumpKind;
  directAsm: string[];
  ssaForm: boolean;
  optimizedStatements?: VexStatement[];
  vulnerabilitiesDetected?: {
    cwe: string;
    title: string;
    severity: 'critical' | 'high' | 'medium';
    statementIndex: number;
    explanation: string;
  }[];
}

export interface VexTaintPolicy {
  sources: {
    target: string; // e.g. "rdi", "t0", "buffer[0x4010]"
    type: 'register' | 'memory' | 'temp' | 'api';
    tag: string;
    description: string;
  }[];
  sinks: {
    target: string; // e.g. "rip", "memcpy_dest", "system_arg"
    type: 'register' | 'memory' | 'control_flow' | 'api';
    cwe: string;
    description: string;
  }[];
  sanitizers: {
    operation: string;
    variable: string;
    condition: string;
  }[];
}

export interface VexTaintStep {
  stepIndex: number;
  statement: VexStatement;
  taintedTemps: Record<string, { tag: string; origin: string; level: 'critical' | 'high' | 'medium' }>;
  taintedRegisters: Record<string, { tag: string; origin: string; level: 'critical' | 'high' | 'medium' }>;
  taintedMemory: { addressOrOffset: string; size: number; origin: string }[];
  sanitizedVars: string[];
  alert?: {
    title: string;
    cwe: string;
    severity: 'critical' | 'high';
    message: string;
    exploitPrimitive: string;
  };
  isSanitizedEvent?: boolean;
}
