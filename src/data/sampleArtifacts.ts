/**
 * Pre-loaded Authentic Reverse Engineering Projects & Sample Artifacts
 * Matching Eleven platform capabilities and user's workspace
 */

import { Artifact, AnalysisResult } from '../types/reverseEngineering';

export const SAMPLE_ARTIFACTS: Artifact[] = [
  {
    id: 'art-bin-ls',
    name: 'ls',
    size: 142848,
    type: 'elf',
    formatDetails: 'ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV)',
    architecture: 'x86_64',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    md5: 'a437f8d39b8c2e6f3d81b94208e9f51a',
    uploadedAt: '25 minutes ago',
    status: 'analyzed',
    iconType: 'binary',
    description: 'GNU Coreutils directory listing utility with POSIX terminal formatting and inode traversal.',
    chatCount: 0,
    lastAnalyzed: '25 minutes ago',
  },
  {
    id: 'art-calculator-app',
    name: 'Calculator.app',
    size: 2840920,
    type: 'macho',
    formatDetails: 'Mach-O universal binary with 2 architectures: [x86_64] [arm64e]',
    architecture: 'universal',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    md5: '6e1a4f91d8a39b2c8e7f123456789abc',
    uploadedAt: '11 minutes ago',
    status: 'analyzed',
    iconType: 'app',
    description: 'macOS desktop calculation application featuring scientific expression parser and decimal precision engine.',
    chatCount: 0,
    lastAnalyzed: '11 minutes ago',
  },
  {
    id: 'art-photofilter-app',
    name: 'PhotoFilter.app',
    size: 8940120,
    type: 'shader',
    formatDetails: 'Metal Shading Language & SPIR-V compiled compute kernels',
    architecture: 'spirv',
    sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    md5: 'd41d8cd98f00b204e9800998ecf8427e',
    uploadedAt: '36 minutes ago',
    status: 'analyzed',
    iconType: 'shader',
    description: 'High-performance GPU image processing engine with spatial blur and color grading shader kernels.',
    chatCount: 1,
    lastAnalyzed: '36 minutes ago',
  },
  {
    id: 'art-dictionary-app',
    name: 'Dictionary.app',
    size: 15420000,
    type: 'app',
    formatDetails: 'macOS application bundle with embedded SQLite dictionary lexicon database',
    architecture: 'aarch64',
    sha256: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    md5: 'c4ca4238a0b923820dcc509a6f75849b',
    uploadedAt: '4 hours ago',
    status: 'analyzed',
    iconType: 'app',
    description: 'Reference dictionary lookup tool with indexed SQLite B-Tree text matching and morphology lemmatization.',
    chatCount: 1,
    lastAnalyzed: '4 hours ago',
  },
  {
    id: 'art-malware-sample',
    name: 'suspicious_loader.exe',
    size: 421800,
    type: 'pe',
    formatDetails: 'PE32+ executable (GUI) x86-64, for MS Windows, UPX packed',
    architecture: 'x86_64',
    sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    md5: '8b1a9953c4611296a827abf8c47804d7',
    uploadedAt: '1 hour ago',
    status: 'analyzed',
    iconType: 'binary',
    description: 'High-entropy packed PE binary exhibiting suspicious memory allocation and registry persistence primitives.',
    chatCount: 3,
    lastAnalyzed: '1 hour ago',
  },
  {
    id: 'art-model-pt',
    name: 'resnet50_weights.pt',
    size: 102488000,
    type: 'model',
    formatDetails: 'PyTorch v2.1 Pickle Model Archive (Serialized Object Graph)',
    architecture: 'universal',
    sha256: 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
    md5: '5d41402abc4b2a76b9719d911017c592',
    uploadedAt: '2 hours ago',
    status: 'analyzed',
    iconType: 'model',
    description: 'Deep neural network weight tensor checkpoint with serialized Python bytecode graph.',
    chatCount: 2,
    lastAnalyzed: '2 hours ago',
  },
];

export const SAMPLE_ANALYSIS_RESULTS: Record<string, AnalysisResult> = {
  'art-bin-ls': {
    artifactId: 'art-bin-ls',
    jobId: 'job-ls-001',
    completedAt: '2026-10-16T09:10:00Z',
    metadata: {
      fileFormat: 'ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV)',
      architecture: 'x86_64',
      bitness: 64,
      endianness: 'little',
      entryPoint: '0x00003b80',
      imageBase: '0x00000000',
      compiler: 'GCC 13.2.0 (Ubuntu 13.2.0-23ubuntu4)',
      sectionsCount: 31,
      symbolsCount: 184,
      importsCount: 42,
      exportsCount: 1,
      overallEntropy: 6.24,
      mitigations: {
        aslrPie: true,
        depNx: true,
        stackCanary: true,
        relro: 'full',
        authenticodeSigned: false,
        hardenedRuntime: true,
      },
    },
    sections: [
      {
        name: '.interp',
        virtualAddress: '0x00000318',
        virtualSize: 28,
        rawSize: 28,
        entropy: 3.82,
        permissions: { read: true, write: false, execute: false },
        characteristics: ['ALLOC'],
      },
      {
        name: '.text',
        virtualAddress: '0x000038b0',
        virtualSize: 74218,
        rawSize: 74240,
        entropy: 6.51,
        permissions: { read: true, write: false, execute: true },
        characteristics: ['ALLOC', 'EXECINSTR'],
      },
      {
        name: '.rodata',
        virtualAddress: '0x00016000',
        virtualSize: 21940,
        rawSize: 22016,
        entropy: 5.48,
        permissions: { read: true, write: false, execute: false },
        characteristics: ['ALLOC'],
      },
      {
        name: '.data',
        virtualAddress: '0x00021000',
        virtualSize: 3240,
        rawSize: 3240,
        entropy: 3.12,
        permissions: { read: true, write: true, execute: false },
        characteristics: ['ALLOC', 'WRITE'],
      },
      {
        name: '.bss',
        virtualAddress: '0x00022000',
        virtualSize: 5824,
        rawSize: 0,
        entropy: 0.0,
        permissions: { read: true, write: true, execute: false },
        characteristics: ['ALLOC', 'WRITE', 'NOBITS'],
      },
    ],
    functions: [
      {
        id: 'fn-main',
        name: 'main',
        address: '0x000043f0',
        size: 896,
        cyclomaticComplexity: 14,
        callersCount: 1,
        calleesCount: 12,
        callers: ['_start'],
        callees: ['setlocale', 'textdomain', 'bindtextdomain', 'decode_switches', 'print_dir', 'exit_cleanup'],
        isExported: true,
        isVulnerable: false,
        signature: 'int main(int argc, char **argv)',
        decompiledCode: `int main(int argc, char **argv)
{
    int iVar1;
    char *locale_str;
    
    // Set program name for diagnostics
    program_name = argv[0];
    
    // Initialize internationalization & locale configuration
    setlocale(LC_ALL, "");
    bindtextdomain("coreutils", "/usr/share/locale");
    textdomain("coreutils");
    
    atexit(close_stdout);
    
    // Parse command line arguments (-l, -a, -h, --color)
    iVar1 = decode_switches(argc, argv);
    
    // Process directory queue
    if (iVar1 == argc) {
        queue_directory(".", NULL, false);
    } else {
        do {
            queue_directory(argv[iVar1], NULL, true);
            iVar1++;
        } while (iVar1 < argc);
    }
    
    sort_files();
    print_current_files();
    
    return (exit_status == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}`,
        assemblyInstructions: [
          { address: '0x000043f0', bytes: '55', mnemonic: 'push', operands: 'rbp', comment: 'Establish stack frame' },
          { address: '0x000043f1', bytes: '48 89 e5', mnemonic: 'mov', operands: 'rbp, rsp' },
          { address: '0x000043f4', bytes: '41 57', mnemonic: 'push', operands: 'r15' },
          { address: '0x000043f6', bytes: '41 56', mnemonic: 'push', operands: 'r14' },
          { address: '0x000043f8', bytes: '48 83 ec 30', mnemonic: 'sub', operands: 'rsp, 0x30' },
          { address: '0x000043fc', bytes: '89 7d d4', mnemonic: 'mov', operands: 'dword ptr [rbp - 0x2c], edi', comment: 'argc' },
          { address: '0x000043ff', bytes: '48 89 75 c8', mnemonic: 'mov', operands: 'qword ptr [rbp - 0x38], rsi', comment: 'argv' },
          { address: '0x00004403', bytes: '48 8b 06', mnemonic: 'mov', operands: 'rax, qword ptr [rsi]', comment: 'argv[0]' },
          { address: '0x00004406', bytes: '48 89 05 b3 c5 01 00', mnemonic: 'mov', operands: 'qword ptr [program_name], rax' },
          { address: '0x0000440d', bytes: '48 8d 35 c4 1e 01 00', mnemonic: 'lea', operands: 'rsi, [rip + 0x11ec4]', comment: '""' },
          { address: '0x00004414', bytes: 'bf 06 00 00 00', mnemonic: 'mov', operands: 'edi, 6', comment: 'LC_ALL' },
          { address: '0x00004419', bytes: 'e8 e2 f7 ff ff', mnemonic: 'call', operands: '0x00003c00', comment: 'setlocale()' },
          { address: '0x0000441e', bytes: '85 c0', mnemonic: 'test', operands: 'eax, eax' },
          { address: '0x00004420', bytes: '74 18', mnemonic: 'je', operands: '0x0000443a', isJumpOrCall: true },
        ],
        cfgBlocks: [
          {
            id: 'block-0',
            label: 'entry_point',
            startAddress: '0x000043f0',
            endAddress: '0x00004420',
            instructions: [
              { address: '0x000043f0', bytes: '55', mnemonic: 'push', operands: 'rbp' },
              { address: '0x000043f4', bytes: 'sub', mnemonic: 'rsp, 0x30', operands: '' },
              { address: '0x00004419', bytes: 'call', mnemonic: 'setlocale', operands: '' },
              { address: '0x00004420', bytes: 'je', mnemonic: 'loc_fallback', operands: '' },
            ],
            successors: ['block-1', 'block-fallback'],
            predecessors: [],
            isEntry: true,
            branchType: 'conditional',
          },
          {
            id: 'block-1',
            label: 'init_switches',
            startAddress: '0x00004422',
            endAddress: '0x00004460',
            instructions: [
              { address: '0x00004422', bytes: 'call', mnemonic: 'decode_switches', operands: 'argc, argv' },
              { address: '0x00004458', bytes: 'cmp', mnemonic: 'eax, [rbp-0x2c]', operands: '' },
              { address: '0x0000445e', bytes: 'jne', mnemonic: 'loc_queue_args', operands: '' },
            ],
            successors: ['block-default-dir', 'block-queue-args'],
            predecessors: ['block-0'],
            branchType: 'conditional',
          },
          {
            id: 'block-default-dir',
            label: 'queue_current_dir',
            startAddress: '0x00004462',
            endAddress: '0x00004485',
            instructions: [
              { address: '0x00004462', bytes: 'lea', mnemonic: 'rdi, ["."]', operands: '' },
              { address: '0x00004470', bytes: 'call', mnemonic: 'queue_directory', operands: '' },
              { address: '0x00004480', bytes: 'jmp', mnemonic: 'loc_render', operands: '' },
            ],
            successors: ['block-render'],
            predecessors: ['block-1'],
            branchType: 'unconditional',
          },
          {
            id: 'block-queue-args',
            label: 'queue_cli_targets',
            startAddress: '0x00004490',
            endAddress: '0x000044c0',
            instructions: [
              { address: '0x00004490', bytes: 'mov', mnemonic: 'rdi, [argv+rcx*8]', operands: '' },
              { address: '0x000044a0', bytes: 'call', mnemonic: 'queue_directory', operands: '' },
              { address: '0x000044ba', bytes: 'loop', mnemonic: 'queue_cli_targets', operands: '' },
            ],
            successors: ['block-render'],
            predecessors: ['block-1'],
            branchType: 'unconditional',
          },
          {
            id: 'block-fallback',
            label: 'locale_fallback',
            startAddress: '0x0000443a',
            endAddress: '0x0000444f',
            instructions: [
              { address: '0x0000443a', bytes: 'mov', mnemonic: 'edi, 1', operands: '' },
              { address: '0x00004445', bytes: 'jmp', mnemonic: 'init_switches', operands: '' },
            ],
            successors: ['block-1'],
            predecessors: ['block-0'],
            branchType: 'unconditional',
          },
          {
            id: 'block-render',
            label: 'exit_render',
            startAddress: '0x000044d0',
            endAddress: '0x000044ff',
            instructions: [
              { address: '0x000044d0', bytes: 'call', mnemonic: 'print_current_files', operands: '' },
              { address: '0x000044ea', bytes: 'mov', mnemonic: 'eax, [exit_status]', operands: '' },
              { address: '0x000044fe', bytes: 'ret', mnemonic: '', operands: '' },
            ],
            successors: [],
            predecessors: ['block-default-dir', 'block-queue-args'],
            isExit: true,
            branchType: 'return',
          },
        ],
      },
      {
        id: 'fn-print-dir',
        name: 'print_dir',
        address: '0x000062a0',
        size: 1420,
        cyclomaticComplexity: 18,
        callersCount: 2,
        calleesCount: 8,
        callers: ['main', 'print_many_per_line'],
        callees: ['opendir', 'readdir', 'closedir', 'stat', 'file_has_acl', 'format_user_width'],
        isExported: false,
        isVulnerable: false,
        signature: 'void print_dir(char const *name, char const *realname, bool command_line_arg)',
        decompiledCode: `void print_dir(char const *name, char const *realname, bool command_line_arg)
{
    DIR *dirp;
    struct dirent *next;
    
    dirp = opendir(name);
    if (!dirp) {
        file_failure(command_line_arg, "%s", name);
        return;
    }
    
    clear_files();
    while ((next = readdir(dirp)) != NULL) {
        if (!file_ignored(next->d_name)) {
            gobble_file(next->d_name, 0, 0, command_line_arg, name);
        }
    }
    
    closedir(dirp);
    sort_files();
    print_current_files();
}`,
        assemblyInstructions: [
          { address: '0x000062a0', bytes: '48 83 ec 18', mnemonic: 'sub', operands: 'rsp, 0x18' },
          { address: '0x000062a4', bytes: 'e8 57 d9 ff ff', mnemonic: 'call', operands: 'opendir' },
          { address: '0x000062a9', bytes: '48 85 c0', mnemonic: 'test', operands: 'rax, rax' },
          { address: '0x000062ac', bytes: '74 32', mnemonic: 'je', operands: '0x000062e0', isJumpOrCall: true },
        ],
        cfgBlocks: [],
      },
      {
        id: 'fn-decode-switches',
        name: 'decode_switches',
        address: '0x00005110',
        size: 2150,
        cyclomaticComplexity: 32,
        callersCount: 1,
        calleesCount: 4,
        callers: ['main'],
        callees: ['getopt_long', 'getenv', 'isatty', 'usage'],
        isExported: false,
        isVulnerable: false,
        signature: 'int decode_switches(int argc, char **argv)',
        decompiledCode: `int decode_switches(int argc, char **argv)
{
    int opt;
    static struct option const long_options[] = {
        {"all", no_argument, NULL, 'a'},
        {"almost-all", no_argument, NULL, 'A'},
        {"color", optional_argument, NULL, 0x100},
        {"human-readable", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "abcdfghiklmnopqrstuvw:x1A:C:F:R:S:T:U:X", long_options, NULL)) != -1) {
        switch (opt) {
            case 'a': ignore_mode = IGNORE_MINIMAL; break;
            case 'A': ignore_mode = IGNORE_DEFAULT; break;
            case 'l': format = long_format; break;
            case 0x100: print_with_color = true; break;
        }
    }
    return optind;
}`,
        assemblyInstructions: [
          { address: '0x00005110', bytes: '55', mnemonic: 'push', operands: 'rbp' },
          { address: '0x00005111', bytes: '48 89 e5', mnemonic: 'mov', operands: 'rbp, rsp' },
          { address: '0x00005114', bytes: 'e8 c7 ea ff ff', mnemonic: 'call', operands: 'getopt_long' },
        ],
        cfgBlocks: [],
      },
    ],
    strings: [
      { id: 'str-01', value: '/usr/share/locale', address: '0x00016010', section: '.rodata', length: 17, category: 'path', suspicious: false },
      { id: 'str-02', value: 'coreutils', address: '0x00016028', section: '.rodata', length: 9, category: 'general', suspicious: false },
      { id: 'str-03', value: 'write error', address: '0x00016040', section: '.rodata', length: 11, category: 'general', suspicious: false },
      { id: 'str-04', value: 'POSIXLY_CORRECT', address: '0x00016080', section: '.rodata', length: 15, category: 'general', suspicious: false },
      { id: 'str-05', value: 'LS_COLORS', address: '0x000160b0', section: '.rodata', length: 9, category: 'general', suspicious: false },
      { id: 'str-06', value: 'QUOTING_STYLE', address: '0x000160e0', section: '.rodata', length: 13, category: 'general', suspicious: false },
    ],
    importsExports: [
      { id: 'ie-01', library: 'libc.so.6', functionName: 'opendir', address: '0x00003b00', type: 'import', isDangerous: false },
      { id: 'ie-02', library: 'libc.so.6', functionName: 'readdir', address: '0x00003b10', type: 'import', isDangerous: false },
      { id: 'ie-03', library: 'libc.so.6', functionName: 'closedir', address: '0x00003b20', type: 'import', isDangerous: false },
      { id: 'ie-04', library: 'libc.so.6', functionName: 'stat', address: '0x00003b30', type: 'import', isDangerous: false },
      { id: 'ie-05', library: 'libc.so.6', functionName: 'setlocale', address: '0x00003b40', type: 'import', isDangerous: false },
      { id: 'ie-06', library: 'libc.so.6', functionName: 'getopt_long', address: '0x00003b50', type: 'import', isDangerous: false },
      { id: 'ie-07', library: 'libc.so.6', functionName: 'main', address: '0x000043f0', type: 'export', isDangerous: false },
    ],
    findings: [
      {
        id: 'find-ls-01',
        title: 'Complete Binary Security Mitigations Enforced',
        severity: 'info',
        cweId: 'CWE-693',
        cvss: 0.0,
        category: 'Compiler Hardening',
        description: 'Binary is built with Full RELRO, Stack Canary protection, NX stack, and ASLR/PIE position-independent executable flags.',
        detectedBy: 'eleven-static',
        remediation: 'No remediation necessary. Modern GNU toolchain protections are fully active.',
        confidence: 'verified',
      },
    ],
    entropyChunks: [
      { offset: 0, entropy: 4.1, sectionName: '.interp' },
      { offset: 16384, entropy: 6.55, sectionName: '.text' },
      { offset: 32768, entropy: 6.48, sectionName: '.text' },
      { offset: 49152, entropy: 6.61, sectionName: '.text' },
      { offset: 65536, entropy: 6.42, sectionName: '.text' },
      { offset: 81920, entropy: 5.48, sectionName: '.rodata' },
      { offset: 98304, entropy: 3.12, sectionName: '.data' },
      { offset: 114688, entropy: 0.1, sectionName: '.bss' },
    ],
    summary: {
      overview: 'Clean, standard POSIX coreutil binary. Entry point initializes internationalization and parses command switches before delegating to directory traversal routines.',
      keyBehaviors: [
        'Reads local environment variables (LS_COLORS, QUOTING_STYLE, POSIXLY_CORRECT)',
        'Performs synchronous directory enumeration via POSIX opendir/readdir/stat syscalls',
        'Applies ANSI color escape codes when stdout is connected to a tty terminal',
      ],
      riskScore: 4,
      securityPosture: 'Clean',
      decompiledCoveragePercent: 96,
    },
    toolLogs: [
      { id: 'l1', timestamp: '2026-10-16T09:09:42Z', tool: 'Eleven Static Engine', status: 'success', message: 'ELF64 header verified. Extracted 5 program sections and 31 segment headers.' },
      { id: 'l2', timestamp: '2026-10-16T09:09:44Z', tool: 'Ghidra MCP Server', status: 'success', message: 'Analyzed 184 symbols. Decompiled 12 core routines including main, print_dir, decode_switches.' },
      { id: 'l3', timestamp: '2026-10-16T09:09:45Z', tool: 'REA Decompiler Assistant', status: 'success', message: 'Recovered struct signatures for DIR*, dirent, and struct stat layout.' },
      { id: 'l4', timestamp: '2026-10-16T09:09:46Z', tool: 'Reverse-Skill AST Auditor', status: 'success', message: 'Evaluated calls to memory buffers and string formatters: 0 critical vulnerabilities discovered.' },
    ],
  },
  'art-malware-sample': {
    artifactId: 'art-malware-sample',
    jobId: 'job-mal-99',
    completedAt: '2026-10-16T08:30:00Z',
    metadata: {
      fileFormat: 'PE32+ executable (GUI) Intel x86-64, for MS Windows',
      architecture: 'x86_64',
      bitness: 64,
      endianness: 'little',
      entryPoint: '0x00014020',
      imageBase: '0x00400000',
      compiler: 'Microsoft Visual C++ v14.0 (Custom Pack)',
      packerDetected: 'UPX / Polymorphic Section Encrypter (Entropy 7.91)',
      sectionsCount: 4,
      symbolsCount: 22,
      importsCount: 8,
      exportsCount: 0,
      overallEntropy: 7.74,
      mitigations: {
        aslrPie: false,
        depNx: false,
        stackCanary: false,
        relro: 'none',
        authenticodeSigned: false,
        hardenedRuntime: false,
      },
    },
    sections: [
      {
        name: '.text',
        virtualAddress: '0x00001000',
        virtualSize: 4096,
        rawSize: 4096,
        entropy: 7.85,
        permissions: { read: true, write: true, execute: true },
        characteristics: ['CODE', 'EXECUTE', 'WRITE', 'READ'],
      },
      {
        name: '.rdata',
        virtualAddress: '0x00002000',
        virtualSize: 8192,
        rawSize: 8192,
        entropy: 7.92,
        permissions: { read: true, write: false, execute: false },
        characteristics: ['INITIALIZED_DATA', 'READ'],
      },
      {
        name: '.packed',
        virtualAddress: '0x00004000',
        virtualSize: 390000,
        rawSize: 390000,
        entropy: 7.96,
        permissions: { read: true, write: true, execute: true },
        characteristics: ['UNINITIALIZED_DATA', 'EXECUTE', 'WRITE'],
      },
    ],
    functions: [
      {
        id: 'fn-unpack-stage',
        name: 'sub_14020_unpack_stub',
        address: '0x00014020',
        size: 340,
        cyclomaticComplexity: 8,
        callersCount: 0,
        calleesCount: 4,
        callers: [],
        callees: ['VirtualAlloc', 'VirtualProtect', 'RtlMoveMemory'],
        isExported: false,
        isVulnerable: true,
        signature: 'void* sub_14020_unpack_stub()',
        decompiledCode: `void* sub_14020_unpack_stub()
{
    LPVOID dest_buffer;
    DWORD old_protect;
    
    // Allocate RWX page in process memory
    dest_buffer = VirtualAlloc(NULL, 0x54000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!dest_buffer) return NULL;
    
    // Decrypt payload from .packed section using rolling XOR key (0x5A)
    xor_decrypt_stream((BYTE*)0x00404000, dest_buffer, 0x54000, 0x5a);
    
    // Resolve dynamic Win32 APIs via PEB InMemoryOrderModuleList
    resolve_kernel32_imports(dest_buffer);
    
    // Jump directly into decrypted payload entry point
    ((void(*)())dest_buffer)();
    
    return dest_buffer;
}`,
        assemblyInstructions: [
          { address: '0x00014020', bytes: '48 83 ec 28', mnemonic: 'sub', operands: 'rsp, 0x28' },
          { address: '0x00014024', bytes: '41 b9 40 00 00 00', mnemonic: 'mov', operands: 'r9d, 0x40', comment: 'PAGE_EXECUTE_READWRITE' },
          { address: '0x0001402a', bytes: '41 b8 00 30 00 00', mnemonic: 'mov', operands: 'r8d, 0x3000', comment: 'MEM_COMMIT|RESERVE' },
          { address: '0x00014030', bytes: 'ba 00 40 05 00', mnemonic: 'mov', operands: 'edx, 0x54000' },
          { address: '0x00014035', bytes: '31 c9', mnemonic: 'xor', operands: 'ecx, ecx' },
          { address: '0x00014037', bytes: 'ff 15 e3 1f 00 00', mnemonic: 'call', operands: 'qword ptr [VirtualAlloc]', isJumpOrCall: true },
        ],
        cfgBlocks: [],
      },
      {
        id: 'fn-persistence',
        name: 'install_startup_key',
        address: '0x00014280',
        size: 210,
        cyclomaticComplexity: 5,
        callersCount: 1,
        calleesCount: 3,
        callers: ['sub_14020_unpack_stub'],
        callees: ['RegCreateKeyExA', 'RegSetValueExA', 'RegCloseKey'],
        isExported: false,
        isVulnerable: true,
        signature: 'int install_startup_key(char *self_path)',
        decompiledCode: `int install_startup_key(char *self_path)
{
    HKEY hKey;
    LSTATUS status;
    
    status = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL
    );
    
    if (status == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "SecurityHealthUpdate", 0, REG_SZ, (BYTE*)self_path, strlen(self_path));
        RegCloseKey(hKey);
        return 1;
    }
    return 0;
}`,
        assemblyInstructions: [],
        cfgBlocks: [],
      },
    ],
    strings: [
      { id: 'ms-01', value: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', address: '0x00002100', section: '.rdata', length: 44, category: 'registry', suspicious: true },
      { id: 'ms-02', value: 'SecurityHealthUpdate', address: '0x00002140', section: '.rdata', length: 20, category: 'general', suspicious: true },
      { id: 'ms-03', value: 'http://c2.telemetry-sync-cdn.net/beacon', address: '0x00002180', section: '.rdata', length: 39, category: 'url', suspicious: true },
      { id: 'ms-04', value: 'cmd.exe /c ping 127.0.0.1 -n 3 & del', address: '0x000021c0', section: '.rdata', length: 37, category: 'command', suspicious: true },
    ],
    importsExports: [
      { id: 'mie-01', library: 'KERNEL32.dll', functionName: 'VirtualAlloc', address: '0x00002010', type: 'import', isDangerous: true, riskNote: 'Allocates executable RWX memory buffers' },
      { id: 'mie-02', library: 'KERNEL32.dll', functionName: 'VirtualProtect', address: '0x00002018', type: 'import', isDangerous: true, riskNote: 'Changes page permissions to RWX' },
      { id: 'mie-03', library: 'ADVAPI32.dll', functionName: 'RegSetValueExA', address: '0x00002020', type: 'import', isDangerous: true, riskNote: 'Modifies startup auto-run registry hive' },
    ],
    findings: [
      {
        id: 'find-mal-01',
        title: 'Polymorphic Packing & High Entropy Detected (.packed)',
        severity: 'critical',
        cweId: 'CWE-506',
        cvss: 9.3,
        category: 'Malware / Evasion',
        description: 'Binary sections exhibit Shannon entropy of 7.96 (maximum 8.0), characteristic of encrypted/compressed payload blobs unpackaged at runtime.',
        detectedBy: 'eleven-static',
        remediation: 'Quarantine binary. Conduct isolated dynamic analysis with memory dumping at OEP (Original Entry Point).',
        confidence: 'verified',
      },
      {
        id: 'find-mal-02',
        title: 'RWX Memory Page Allocation (VirtualAlloc PAGE_EXECUTE_READWRITE)',
        severity: 'critical',
        cweId: 'CWE-250',
        cvss: 9.0,
        category: 'Code Injection',
        description: 'Direct call to VirtualAlloc requesting RWX permissions, violating W^X security principles to execute decrypted shellcode.',
        functionName: 'sub_14020_unpack_stub',
        address: '0x00014020',
        detectedBy: 'reverse-skill',
        remediation: 'Enforce Data Execution Prevention (DEP / NX) and block arbitrary memory execution.',
        confidence: 'verified',
      },
      {
        id: 'find-mal-03',
        title: 'Persistent Auto-Run Registry Key Modification',
        severity: 'high',
        cweId: 'CWE-272',
        cvss: 7.5,
        category: 'Persistence Mechanism',
        description: 'Attempts to register binary under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run masquerading as "SecurityHealthUpdate".',
        functionName: 'install_startup_key',
        address: '0x00014280',
        detectedBy: 'rea-assistant',
        remediation: 'Remove registered registry values and inspect scheduled tasks.',
        confidence: 'verified',
      },
    ],
    entropyChunks: [
      { offset: 0, entropy: 7.82, sectionName: '.text' },
      { offset: 4096, entropy: 7.92, sectionName: '.rdata' },
      { offset: 12288, entropy: 7.96, sectionName: '.packed' },
      { offset: 200000, entropy: 7.98, sectionName: '.packed' },
      { offset: 380000, entropy: 7.95, sectionName: '.packed' },
    ],
    summary: {
      overview: 'High-risk suspicious binary exhibiting textbook dropper / loader characteristics: high entropy packed sections, self-decrypting stub, RWX memory allocation, and auto-run registry persistence.',
      keyBehaviors: [
        'Allocates RWX memory region and decrypts payload using XOR loop',
        'Adds HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entry',
        'References hardcoded C2 beacon endpoint: http://c2.telemetry-sync-cdn.net/beacon',
      ],
      riskScore: 94,
      securityPosture: 'Malicious Patterns Detected',
      decompiledCoveragePercent: 42,
    },
    toolLogs: [
      { id: 'ml1', timestamp: '2026-10-16T08:29:40Z', tool: 'Eleven Static Engine', status: 'warn', message: 'Entropy alert: Section .packed exceeds threshold (7.96 > 7.20). Packer heuristic triggered.' },
      { id: 'ml2', timestamp: '2026-10-16T08:29:43Z', tool: 'Reverse-Skill AST Auditor', status: 'error', message: 'Detected high-risk Win32 API combinations: VirtualAlloc(RWX) + RegSetValueExA.' },
      { id: 'ml3', timestamp: '2026-10-16T08:29:45Z', tool: 'REA Decompiler Assistant', status: 'warn', message: 'Decompiled stub routine sub_14020_unpack_stub(); recovered payload loop.' },
    ],
  },
};
