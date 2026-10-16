/**
 * Eleven Dynamic Emulation Debugger & API Call Tracking Service
 * Provides:
 * - CPU Register State & Instruction Pointer Emulation
 * - Call Stack Frame & Memory Watch Management
 * - Software Breakpoint Dispatcher
 * - Chronological Win32/POSIX API Call Traces with Security Anomaly Triage
 */

import {
  Artifact,
  FunctionInfo,
  AsmInstruction,
  CpuRegisters,
  Breakpoint,
  StackFrameEntry,
  ApiCallEvent,
} from '../types/reverseEngineering';

export class DynamicDebuggerService {
  /**
   * Initialize standard CPU register state for a given function or entrypoint
   */
  getInitialRegisters(fn: FunctionInfo): CpuRegisters {
    const entryHex = fn.address || '0x00001000';
    return {
      rax: '0x0000000000000001',
      rbx: '0x00007FFD5A120000',
      rcx: '0x0000000000000002',
      rdx: '0x00007FFD5A120040',
      rsi: '0x00007FFD5A120080',
      rdi: '0x0000000000000001',
      rbp: '0x00007FFFFFFFE480',
      rsp: '0x00007FFFFFFFE478',
      r8: '0x0000000000000000',
      r9: '0x0000000000000040',
      r10: '0x0000000000001000',
      r11: '0x0000000000000246',
      r12: '0x0000000000400000',
      r13: '0x00007FFFFFFFE590',
      r14: '0x0000000000000000',
      r15: '0x0000000000000000',
      rip: entryHex,
      flags: {
        cf: false,
        zf: true,
        sf: false,
        of: false,
        pf: true,
        af: false,
      },
    };
  }

  /**
   * Generate live stack frame entries corresponding to current RSP/RBP
   */
  getStackEntries(rspHex: string, rbpHex: string, fn: FunctionInfo): StackFrameEntry[] {
    return [
      {
        address: rspHex,
        offsetFromRsp: '+0x00',
        valueHex: '0x00007FFD584021A4',
        resolvedSymbol: '__libc_start_main + 244',
        description: 'Saved Return Address',
      },
      {
        address: '0x00007FFFFFFFE480',
        offsetFromRsp: '+0x08',
        valueHex: '0x00007FFFFFFFE4E0',
        resolvedSymbol: 'main_saved_rbp',
        description: 'Base Pointer (Previous Stack Frame)',
      },
      {
        address: '0x00007FFFFFFFE488',
        offsetFromRsp: '+0x10',
        valueHex: '0x0000000000000002',
        resolvedSymbol: 'argc',
        description: 'Argument Count (argc = 2)',
      },
      {
        address: '0x00007FFFFFFFE490',
        offsetFromRsp: '+0x18',
        valueHex: '0x00007FFFFFFFE5B0',
        resolvedSymbol: 'argv[0]',
        description: `Pointer to program name string "${fn.name}"`,
      },
      {
        address: '0x00007FFFFFFFE498',
        offsetFromRsp: '+0x20',
        valueHex: '0x0000000000054000',
        resolvedSymbol: 'local_buffer_size',
        description: 'Allocation Size Parameter (344,064 bytes)',
      },
    ];
  }

  /**
   * Emulate next instruction step
   */
  stepInstruction(
    instructions: AsmInstruction[],
    currentIndex: number,
    registers: CpuRegisters
  ): { nextIndex: number; updatedRegisters: CpuRegisters; executedInstruction: AsmInstruction } {
    const current = instructions[currentIndex] || instructions[0];
    const nextIdx = (currentIndex + 1) % instructions.length;
    const nextIns = instructions[nextIdx];

    const updated: CpuRegisters = {
      ...registers,
      rip: nextIns ? nextIns.address : registers.rip,
      flags: { ...registers.flags },
    };

    // Emulate basic register state updates
    if (current.mnemonic === 'push') {
      const rspNum = BigInt(registers.rsp) - BigInt(8);
      updated.rsp = '0x' + rspNum.toString(16).toUpperCase();
    } else if (current.mnemonic === 'pop') {
      const rspNum = BigInt(registers.rsp) + BigInt(8);
      updated.rsp = '0x' + rspNum.toString(16).toUpperCase();
    } else if (current.mnemonic === 'sub' && current.operands.includes('rsp')) {
      const rspNum = BigInt(registers.rsp) - BigInt(48);
      updated.rsp = '0x' + rspNum.toString(16).toUpperCase();
    } else if (current.mnemonic === 'xor' && current.operands.includes('ecx, ecx')) {
      updated.rcx = '0x0000000000000000';
      updated.flags.zf = true;
    } else if (current.mnemonic === 'test') {
      updated.flags.zf = false;
    } else if (current.mnemonic === 'mov' && current.operands.includes('rbp, rsp')) {
      updated.rbp = updated.rsp;
    }

    return {
      nextIndex: nextIdx,
      updatedRegisters: updated,
      executedInstruction: current,
    };
  }

  /**
   * Pre-load realistic dynamic API call traces for artifacts
   */
  getApiTracesForArtifact(artifactId: string): ApiCallEvent[] {
    if (artifactId === 'art-malware-sample') {
      return [
        {
          id: 'trace-m1',
          seq: 1,
          timestamp: '00:00:00.012',
          threadId: '0x14A0',
          library: 'KERNEL32.dll',
          apiName: 'VirtualAlloc',
          category: 'memory',
          parameters: [
            { name: 'lpAddress', value: '0x00000000', interpreted: 'NULL (System selects address)' },
            { name: 'dwSize', value: '0x00054000', interpreted: '344,064 bytes' },
            { name: 'flAllocationType', value: '0x00003000', interpreted: 'MEM_COMMIT | MEM_RESERVE' },
            { name: 'flProtect', value: '0x00000040', interpreted: 'PAGE_EXECUTE_READWRITE (RWX)' },
          ],
          returnValue: '0x00450000',
          durationUs: 42,
          isSuspicious: true,
          riskNote: 'CRITICAL: Allocation of executable memory with write permissions (W^X violation / Shellcode stage)',
        },
        {
          id: 'trace-m2',
          seq: 2,
          timestamp: '00:00:00.024',
          threadId: '0x14A0',
          library: 'NTDLL.dll',
          apiName: 'RtlMoveMemory',
          category: 'memory',
          parameters: [
            { name: 'Destination', value: '0x00450000', interpreted: 'Newly allocated RWX buffer' },
            { name: 'Source', value: '0x00404000', interpreted: '.packed section base' },
            { name: 'Length', value: '0x00054000', interpreted: '344,064 bytes' },
          ],
          returnValue: 'void',
          durationUs: 18,
          isSuspicious: false,
        },
        {
          id: 'trace-m3',
          seq: 3,
          timestamp: '00:00:00.038',
          threadId: '0x14A0',
          library: 'ADVAPI32.dll',
          apiName: 'RegCreateKeyExA',
          category: 'registry',
          parameters: [
            { name: 'hKey', value: '0x80000001', interpreted: 'HKEY_CURRENT_USER' },
            { name: 'lpSubKey', value: '"Software\\Microsoft\\Windows\\CurrentVersion\\Run"' },
            { name: 'samDesired', value: '0x00020006', interpreted: 'KEY_SET_VALUE' },
          ],
          returnValue: '0x00000000 (ERROR_SUCCESS)',
          durationUs: 65,
          isSuspicious: true,
          riskNote: 'HIGH: Opening Windows AutoRun persistence registry key',
        },
        {
          id: 'trace-m4',
          seq: 4,
          timestamp: '00:00:00.045',
          threadId: '0x14A0',
          library: 'ADVAPI32.dll',
          apiName: 'RegSetValueExA',
          category: 'registry',
          parameters: [
            { name: 'hKey', value: '0x00000188', interpreted: 'Opened Run key handle' },
            { name: 'lpValueName', value: '"SecurityHealthUpdate"', interpreted: 'Masqueraded value name' },
            { name: 'dwType', value: '0x00000001', interpreted: 'REG_SZ' },
            { name: 'lpData', value: '"C:\\Users\\Victim\\AppData\\Local\\loader.exe"' },
          ],
          returnValue: '0x00000000 (ERROR_SUCCESS)',
          durationUs: 92,
          isSuspicious: true,
          riskNote: 'CRITICAL: Writing persistence entry masquerading as Windows Defender SecurityHealthUpdate',
        },
        {
          id: 'trace-m5',
          seq: 5,
          timestamp: '00:00:00.078',
          threadId: '0x14A0',
          library: 'WS2_32.dll',
          apiName: 'WSAStartup',
          category: 'network',
          parameters: [
            { name: 'wVersionRequired', value: '0x0202', interpreted: 'Winsock 2.2' },
            { name: 'lpWSAData', value: '0x0019FA80' },
          ],
          returnValue: '0x00000000',
          durationUs: 120,
          isSuspicious: false,
        },
        {
          id: 'trace-m6',
          seq: 6,
          timestamp: '00:00:00.114',
          threadId: '0x14A0',
          library: 'WS2_32.dll',
          apiName: 'connect',
          category: 'network',
          parameters: [
            { name: 's', value: '0x00000214', interpreted: 'Socket Descriptor' },
            { name: 'name', value: '"192.0.2.14:8080"', interpreted: 'c2.telemetry-sync-cdn.net:8080' },
          ],
          returnValue: '0x00000000',
          durationUs: 450,
          isSuspicious: true,
          riskNote: 'CRITICAL: Outbound TCP socket connection to known Command & Control beacon',
        },
        {
          id: 'trace-m7',
          seq: 7,
          timestamp: '00:00:00.142',
          threadId: '0x14A0',
          library: 'KERNEL32.dll',
          apiName: 'CreateProcessA',
          category: 'process',
          parameters: [
            { name: 'lpApplicationName', value: 'NULL' },
            { name: 'lpCommandLine', value: '"cmd.exe /c ping 127.0.0.1 -n 3 & del self.exe"' },
          ],
          returnValue: '0x00000001 (TRUE)',
          durationUs: 310,
          isSuspicious: true,
          riskNote: 'HIGH: Spawning shell command to delete original binary artifact after payload execution',
        },
      ];
    }

    // Default /bin/ls execution trace
    return [
      {
        id: 'trace-ls1',
        seq: 1,
        timestamp: '00:00:00.002',
        threadId: '0x08F2',
        library: 'libc.so.6',
        apiName: 'setlocale',
        category: 'system',
        parameters: [
          { name: 'category', value: '6', interpreted: 'LC_ALL' },
          { name: 'locale', value: '""', interpreted: 'Read user environment locale' },
        ],
        returnValue: '"en_US.UTF-8"',
        durationUs: 15,
        isSuspicious: false,
      },
      {
        id: 'trace-ls2',
        seq: 2,
        timestamp: '00:00:00.005',
        threadId: '0x08F2',
        library: 'libc.so.6',
        apiName: 'bindtextdomain',
        category: 'system',
        parameters: [
          { name: 'domainname', value: '"coreutils"' },
          { name: 'dirname', value: '"/usr/share/locale"' },
        ],
        returnValue: '"/usr/share/locale"',
        durationUs: 8,
        isSuspicious: false,
      },
      {
        id: 'trace-ls3',
        seq: 3,
        timestamp: '00:00:00.008',
        threadId: '0x08F2',
        library: 'libc.so.6',
        apiName: 'isatty',
        category: 'filesystem',
        parameters: [
          { name: 'fd', value: '1', interpreted: 'STDOUT_FILENO' },
        ],
        returnValue: '1 (TRUE)',
        durationUs: 4,
        isSuspicious: false,
      },
      {
        id: 'trace-ls4',
        seq: 4,
        timestamp: '00:00:00.012',
        threadId: '0x08F2',
        library: 'libc.so.6',
        apiName: 'opendir',
        category: 'filesystem',
        parameters: [
          { name: 'name', value: '"."', interpreted: 'Current Working Directory' },
        ],
        returnValue: '0x55A120 (DIR*)',
        durationUs: 22,
        isSuspicious: false,
      },
      {
        id: 'trace-ls5',
        seq: 5,
        timestamp: '00:00:00.018',
        threadId: '0x08F2',
        library: 'libc.so.6',
        apiName: 'readdir',
        category: 'filesystem',
        parameters: [
          { name: 'dirp', value: '0x55A120' },
        ],
        returnValue: '&dirent { d_ino: 104821, d_name: "main.c" }',
        durationUs: 12,
        isSuspicious: false,
      },
      {
        id: 'trace-ls6',
        seq: 6,
        timestamp: '00:00:00.024',
        threadId: '0x08F2',
        library: 'libc.so.6',
        apiName: 'stat',
        category: 'filesystem',
        parameters: [
          { name: 'pathname', value: '"./main.c"' },
          { name: 'statbuf', value: '&st' },
        ],
        returnValue: '0 (SUCCESS)',
        durationUs: 18,
        isSuspicious: false,
      },
      {
        id: 'trace-ls7',
        seq: 7,
        timestamp: '00:00:00.030',
        threadId: '0x08F2',
        library: 'libc.so.6',
        apiName: 'closedir',
        category: 'filesystem',
        parameters: [
          { name: 'dirp', value: '0x55A120' },
        ],
        returnValue: '0',
        durationUs: 7,
        isSuspicious: false,
      },
    ];
  }
}

export const dynamicDebuggerService = new DynamicDebuggerService();
