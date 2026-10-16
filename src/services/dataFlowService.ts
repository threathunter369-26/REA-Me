/**
 * Eleven Advanced Data Flow & Taint Analysis Service
 * Provides:
 * - Inter-procedural & intra-procedural taint propagation tracking
 * - Source-to-sink graph construction & DAG rendering coordinates
 * - Forward program slicing (influence of tainted sources)
 * - Backward program slicing (root-cause discovery from sinks)
 * - Variable Def-Use chains tracking
 * - Sanitizer verification and CWE severity assessment
 */

import {
  TaintPath,
  DataFlowNode,
  DataFlowEdge,
  DefUseNode,
} from '../types/reverseEngineering';

export class DataFlowService {
  /**
   * Comprehensive default taint paths based on real binary reverse engineering patterns
   */
  getDefaultTaintPaths(): TaintPath[] {
    return [
      {
        id: 'taint-buf-overflow',
        title: 'Network Packet Payload to Stack Buffer Overflow',
        functionName: 'process_network_packet',
        source: {
          type: 'network_socket',
          api: 'recv',
          address: '0x004018A0',
          variable: 'net_rx_buf',
        },
        sink: {
          type: 'buffer_copy',
          api: 'memcpy',
          address: '0x0040194C',
          variable: 'stack_packet_header',
          cweId: 'CWE-121: Stack-based Buffer Overflow',
        },
        sanitization: 'unsanitized',
        exploitability: 'critical',
        summary:
          'Untrusted network bytes received from socket descriptor are copied directly into a fixed 64-byte stack frame buffer without verifying the packet length header.',
        remediationAdvice:
          'Enforce strict packet length validation prior to copy: if (len > sizeof(stack_packet_header)) return -1; Use memcpy_s or bounded strncpy.',
        nodes: [
          {
            id: 'node-1',
            label: 'recv(sockfd, net_rx_buf, 4096, 0)',
            instructionAddress: '0x004018A0',
            functionName: 'process_network_packet',
            type: 'source',
            description: 'Network socket input receives arbitrary remote client bytes into heap buffer net_rx_buf.',
            variableName: 'net_rx_buf',
            registersInvolved: ['%rdi', '%rsi', '%rdx', '%rax'],
            codeSnippet: 'ssize_t bytes_received = recv(client_sock, net_rx_buf, 4096, 0);',
            isTainted: true,
            taintLevel: 'critical',
            posX: 50,
            posY: 80,
          },
          {
            id: 'node-2',
            label: 'mov %rax, -0x18(%rbp) [len]',
            instructionAddress: '0x004018B8',
            functionName: 'process_network_packet',
            type: 'propagation',
            description: 'Received byte count transferred from %rax into local frame variable packet_len.',
            variableName: 'packet_len',
            registersInvolved: ['%rax', '%rbp'],
            codeSnippet: 'packet_len = bytes_received;',
            isTainted: true,
            taintLevel: 'critical',
            posX: 250,
            posY: 80,
          },
          {
            id: 'node-3',
            label: 'mov -0x8(%rbp), %rax [ptr deref]',
            instructionAddress: '0x004018E4',
            functionName: 'process_network_packet',
            type: 'propagation',
            description: 'Pointer arithmetic extracts sub-payload pointer without verifying packet type discriminator.',
            variableName: 'payload_ptr',
            registersInvolved: ['%rax', '%rcx'],
            codeSnippet: 'uint8_t *payload_ptr = (uint8_t *)(net_rx_buf + 4);',
            isTainted: true,
            taintLevel: 'high',
            posX: 450,
            posY: 80,
          },
          {
            id: 'node-4',
            label: 'lea -0x50(%rbp), %rdi [dest buf]',
            instructionAddress: '0x00401920',
            functionName: 'process_network_packet',
            type: 'propagation',
            description: 'Stack frame pointer points to 64-byte stack array: char stack_packet_header[64].',
            variableName: 'stack_packet_header',
            registersInvolved: ['%rdi', '%rbp'],
            codeSnippet: 'char stack_packet_header[64]; // Fixed stack frame',
            isTainted: false,
            taintLevel: 'clean',
            posX: 450,
            posY: 220,
          },
          {
            id: 'node-5',
            label: 'test %eax, %eax (Missing Bounds Check)',
            instructionAddress: '0x00401938',
            functionName: 'process_network_packet',
            type: 'sanitizer',
            description: 'Checks only if length is zero; completely omits upper bound check against destination 64 bytes!',
            variableName: 'len_validation',
            registersInvolved: ['%eax', '%eflags'],
            codeSnippet: 'if (packet_len <= 0) return -1; // Missing packet_len > 64 check',
            isTainted: true,
            taintLevel: 'high',
            posX: 650,
            posY: 80,
          },
          {
            id: 'node-6',
            label: 'memcpy(stack_packet_header, payload, len)',
            instructionAddress: '0x0040194C',
            functionName: 'process_network_packet',
            type: 'sink',
            description: 'Unbounded memory copy overwrites saved RBP and return address on stack, granting control-flow hijacking.',
            variableName: 'memcpy_sink',
            registersInvolved: ['%rdi', '%rsi', '%rdx'],
            codeSnippet: 'memcpy(stack_packet_header, payload_ptr, packet_len);',
            isTainted: true,
            taintLevel: 'critical',
            posX: 850,
            posY: 150,
          },
        ],
        edges: [
          {
            id: 'edge-1-2',
            fromNodeId: 'node-1',
            toNodeId: 'node-2',
            edgeType: 'direct_assignment',
            label: 'return_val (%rax)',
            isTaintedPath: true,
          },
          {
            id: 'edge-2-3',
            fromNodeId: 'node-2',
            toNodeId: 'node-3',
            edgeType: 'arithmetic',
            label: 'offset indexing',
            isTaintedPath: true,
          },
          {
            id: 'edge-2-5',
            fromNodeId: 'node-2',
            toNodeId: 'node-5',
            edgeType: 'control_dependency',
            label: 'cmp packet_len, 0',
            isTaintedPath: true,
          },
          {
            id: 'edge-3-6',
            fromNodeId: 'node-3',
            toNodeId: 'node-6',
            edgeType: 'call_argument',
            label: 'arg2: %rsi (payload_ptr)',
            isTaintedPath: true,
          },
          {
            id: 'edge-4-6',
            fromNodeId: 'node-4',
            toNodeId: 'node-6',
            edgeType: 'call_argument',
            label: 'arg1: %rdi (dest)',
            isTaintedPath: false,
          },
          {
            id: 'edge-5-6',
            fromNodeId: 'node-5',
            toNodeId: 'node-6',
            edgeType: 'control_dependency',
            label: 'unbounded fallthrough',
            isTaintedPath: true,
          },
        ],
        defUseChains: [
          {
            variable: 'net_rx_buf',
            defAddress: '0x004018A0',
            defInstruction: 'call <recv@plt>',
            useAddresses: ['0x004018E4', '0x0040194C'],
            useInstructions: ['mov -0x8(%rbp), %rax', 'mov %rax, %rsi'],
            scope: 'process_network_packet',
            storage: 'heap',
          },
          {
            variable: 'packet_len',
            defAddress: '0x004018B8',
            defInstruction: 'mov %rax, -0x18(%rbp)',
            useAddresses: ['0x00401938', '0x00401948'],
            useInstructions: ['cmp $0x0, -0x18(%rbp)', 'mov -0x18(%rbp), %rdx'],
            scope: 'process_network_packet',
            storage: 'stack',
          },
          {
            variable: 'stack_packet_header',
            defAddress: '0x00401920',
            defInstruction: 'lea -0x50(%rbp), %rdi',
            useAddresses: ['0x0040194C'],
            useInstructions: ['call <memcpy@plt>'],
            scope: 'process_network_packet',
            storage: 'stack',
          },
        ],
      },
      {
        id: 'taint-cmd-injection',
        title: 'Environment Query String to Arbitrary Command Execution',
        functionName: 'handle_cgi_request',
        source: {
          type: 'environment_var',
          api: 'getenv',
          address: '0x00402110',
          variable: 'raw_query',
        },
        sink: {
          type: 'system_exec',
          api: 'system',
          address: '0x004021F0',
          variable: 'cmd_string',
          cweId: 'CWE-78: OS Command Injection',
        },
        sanitization: 'unsanitized',
        exploitability: 'critical',
        summary:
          'User-controlled QUERY_STRING environment variable is directly concatenated into a system() shell execution string without shell metacharacter filtering.',
        remediationAdvice:
          'Do not use system() or popen(). Use execve() with structured string arguments array, and reject non-alphanumeric input characters.',
        nodes: [
          {
            id: 'cmd-1',
            label: 'getenv("QUERY_STRING")',
            instructionAddress: '0x00402110',
            functionName: 'handle_cgi_request',
            type: 'source',
            description: 'Fetches untrusted query string from HTTP CGI environment variable.',
            variableName: 'raw_query',
            registersInvolved: ['%rdi', '%rax'],
            codeSnippet: 'char *raw_query = getenv("QUERY_STRING");',
            isTainted: true,
            taintLevel: 'critical',
            posX: 50,
            posY: 80,
          },
          {
            id: 'cmd-2',
            label: 'test %rax, %rax (Null Pointer Check)',
            instructionAddress: '0x00402128',
            functionName: 'handle_cgi_request',
            type: 'propagation',
            description: 'Verifies pointer is not NULL, but allows arbitrary shell metacharacters (; | ` $ &).',
            variableName: 'raw_query',
            registersInvolved: ['%rax', '%eflags'],
            codeSnippet: 'if (!raw_query) return 400;',
            isTainted: true,
            taintLevel: 'critical',
            posX: 260,
            posY: 80,
          },
          {
            id: 'cmd-3',
            label: 'sprintf(cmd_buf, "/usr/bin/tool %s", raw_query)',
            instructionAddress: '0x00402184',
            functionName: 'handle_cgi_request',
            type: 'propagation',
            description: 'Concatenates tainted query string directly into command formatting buffer.',
            variableName: 'cmd_string',
            registersInvolved: ['%rdi', '%rsi', '%rdx'],
            codeSnippet: 'sprintf(cmd_string, "/usr/bin/tool --action=%s", raw_query);',
            isTainted: true,
            taintLevel: 'critical',
            posX: 500,
            posY: 80,
          },
          {
            id: 'cmd-4',
            label: 'system(cmd_string)',
            instructionAddress: '0x004021F0',
            functionName: 'handle_cgi_request',
            type: 'sink',
            description: 'Executes shell command with /bin/sh -c, allowing arbitrary command chaining via semicolon or backticks.',
            variableName: 'system_sink',
            registersInvolved: ['%rdi'],
            codeSnippet: 'system(cmd_string);',
            isTainted: true,
            taintLevel: 'critical',
            posX: 750,
            posY: 80,
          },
        ],
        edges: [
          {
            id: 'cmd-e1-2',
            fromNodeId: 'cmd-1',
            toNodeId: 'cmd-2',
            edgeType: 'direct_assignment',
            label: 'query_ptr',
            isTaintedPath: true,
          },
          {
            id: 'cmd-e2-3',
            fromNodeId: 'cmd-2',
            toNodeId: 'cmd-3',
            edgeType: 'call_argument',
            label: 'arg3: raw_query',
            isTaintedPath: true,
          },
          {
            id: 'cmd-e3-4',
            fromNodeId: 'cmd-3',
            toNodeId: 'cmd-4',
            edgeType: 'call_argument',
            label: 'arg1: cmd_string',
            isTaintedPath: true,
          },
        ],
        defUseChains: [
          {
            variable: 'raw_query',
            defAddress: '0x00402110',
            defInstruction: 'call <getenv@plt>',
            useAddresses: ['0x00402128', '0x00402184'],
            useInstructions: ['test %rax, %rax', 'mov %rax, %rdx'],
            scope: 'handle_cgi_request',
            storage: 'register',
          },
          {
            variable: 'cmd_string',
            defAddress: '0x00402184',
            defInstruction: 'call <sprintf@plt>',
            useAddresses: ['0x004021F0'],
            useInstructions: ['call <system@plt>'],
            scope: 'handle_cgi_request',
            storage: 'stack',
          },
        ],
      },
      {
        id: 'taint-format-string',
        title: 'Untrusted Config File Stream to Format String Specifier',
        functionName: 'load_server_configuration',
        source: {
          type: 'file_input',
          api: 'fgets',
          address: '0x00403340',
          variable: 'cfg_line_buf',
        },
        sink: {
          type: 'format_string',
          api: 'printf',
          address: '0x004033C0',
          variable: 'cfg_line_buf',
          cweId: 'CWE-134: Use of Externally-Controlled Format String',
        },
        sanitization: 'unsanitized',
        exploitability: 'high',
        summary:
          'Configuration file line read into memory is passed directly as format argument to printf() instead of using printf("%s", line), allowing arbitrary memory leaks and %n write primitives.',
        remediationAdvice:
          'Always supply explicit format string: printf("%s", cfg_line_buf); or fputs(cfg_line_buf, stdout).',
        nodes: [
          {
            id: 'fmt-1',
            label: 'fgets(cfg_line_buf, 256, config_file)',
            instructionAddress: '0x00403340',
            functionName: 'load_server_configuration',
            type: 'source',
            description: 'Reads line from user-modifiable config file into stack array cfg_line_buf.',
            variableName: 'cfg_line_buf',
            registersInvolved: ['%rdi', '%esi', '%rdx'],
            codeSnippet: 'fgets(cfg_line_buf, 256, config_file);',
            isTainted: true,
            taintLevel: 'high',
            posX: 50,
            posY: 80,
          },
          {
            id: 'fmt-2',
            label: 'strchr(cfg_line_buf, \'\\n\') [strip newline]',
            instructionAddress: '0x00403370',
            functionName: 'load_server_configuration',
            type: 'propagation',
            description: 'Locates newline character and replaces with null terminator. Fails to escape % characters.',
            variableName: 'cfg_line_buf',
            registersInvolved: ['%rdi', '%esi', '%rax'],
            codeSnippet: 'char *nl = strchr(cfg_line_buf, \'\\n\'); if (nl) *nl = 0;',
            isTainted: true,
            taintLevel: 'high',
            posX: 320,
            posY: 80,
          },
          {
            id: 'fmt-3',
            label: 'printf(cfg_line_buf) [Missing format specifier]',
            instructionAddress: '0x004033C0',
            functionName: 'load_server_configuration',
            type: 'sink',
            description: 'Direct call to printf with user input in %rdi register. %x and %s reveal stack memory; %n enables arbitrary write.',
            variableName: 'printf_sink',
            registersInvolved: ['%rdi'],
            codeSnippet: 'printf(cfg_line_buf); // Vulnerable: missing "%s"',
            isTainted: true,
            taintLevel: 'critical',
            posX: 640,
            posY: 80,
          },
        ],
        edges: [
          {
            id: 'fmt-e1-2',
            fromNodeId: 'fmt-1',
            toNodeId: 'fmt-2',
            edgeType: 'pointer_deref',
            label: 'buf ptr',
            isTaintedPath: true,
          },
          {
            id: 'fmt-e2-3',
            fromNodeId: 'fmt-2',
            toNodeId: 'fmt-3',
            edgeType: 'call_argument',
            label: 'arg1: %rdi (format)',
            isTaintedPath: true,
          },
        ],
        defUseChains: [
          {
            variable: 'cfg_line_buf',
            defAddress: '0x00403340',
            defInstruction: 'call <fgets@plt>',
            useAddresses: ['0x00403370', '0x004033C0'],
            useInstructions: ['mov %rax, %rdi', 'call <printf@plt>'],
            scope: 'load_server_configuration',
            storage: 'stack',
          },
        ],
      },
      {
        id: 'taint-int-overflow',
        title: '32-bit Integer Multiplication Wrap to Heap Out-of-Bounds',
        functionName: 'allocate_record_table',
        source: {
          type: 'file_input',
          api: 'read_record_count',
          address: '0x00404100',
          variable: 'record_count',
        },
        sink: {
          type: 'memory_write',
          api: 'malloc_and_write',
          address: '0x00404180',
          variable: 'record_table',
          cweId: 'CWE-190: Integer Overflow or Wraparound',
        },
        sanitization: 'partially_checked',
        exploitability: 'high',
        summary:
          'Arithmetic multiplication of record count by record size wraps 32-bit integer boundary (e.g. 0x40000001 * 4 = 4 bytes). Resulting small heap allocation is overrun by full element loop.',
        remediationAdvice:
          'Perform overflow check before multiplication: if (__builtin_mul_overflow(count, sizeof(Record), &alloc_size)) return -1; or calloc().',
        nodes: [
          {
            id: 'int-1',
            label: 'read(fd, &num_records, 4)',
            instructionAddress: '0x00404100',
            functionName: 'allocate_record_table',
            type: 'source',
            description: 'Reads 32-bit unsigned record count from file stream.',
            variableName: 'num_records',
            registersInvolved: ['%eax'],
            codeSnippet: 'uint32_t num_records; read(fd, &num_records, sizeof(uint32_t));',
            isTainted: true,
            taintLevel: 'high',
            posX: 50,
            posY: 80,
          },
          {
            id: 'int-2',
            label: 'imul $0x40, %eax, %edi [Wrap at 4GB]',
            instructionAddress: '0x00404128',
            functionName: 'allocate_record_table',
            type: 'propagation',
            description: 'Calculates total byte size: num_records * 64 bytes. Large values wrap modulo 2^32.',
            variableName: 'alloc_size',
            registersInvolved: ['%eax', '%edi'],
            codeSnippet: 'uint32_t alloc_size = num_records * sizeof(Record);',
            isTainted: true,
            taintLevel: 'critical',
            posX: 280,
            posY: 80,
          },
          {
            id: 'int-3',
            label: 'malloc(alloc_size)',
            instructionAddress: '0x00404150',
            functionName: 'allocate_record_table',
            type: 'propagation',
            description: 'Allocates undersized heap buffer due to wrapped alloc_size.',
            variableName: 'record_table',
            registersInvolved: ['%rdi', '%rax'],
            codeSnippet: 'Record *table = (Record *)malloc(alloc_size);',
            isTainted: true,
            taintLevel: 'high',
            posX: 500,
            posY: 80,
          },
          {
            id: 'int-4',
            label: 'for (i = 0; i < num_records; i++) table[i] = read()',
            instructionAddress: '0x00404180',
            functionName: 'allocate_record_table',
            type: 'sink',
            description: 'Loop relies on unwrapped num_records, writing past the allocated heap boundary.',
            variableName: 'heap_write_sink',
            registersInvolved: ['%rcx', '%rax', '%rdx'],
            codeSnippet: 'for (uint32_t i = 0; i < num_records; i++) { read(fd, &table[i], 64); }',
            isTainted: true,
            taintLevel: 'critical',
            posX: 750,
            posY: 80,
          },
        ],
        edges: [
          {
            id: 'int-e1-2',
            fromNodeId: 'int-1',
            toNodeId: 'int-2',
            edgeType: 'arithmetic',
            label: '* 64 (wrap risk)',
            isTaintedPath: true,
          },
          {
            id: 'int-e2-3',
            fromNodeId: 'int-2',
            toNodeId: 'int-3',
            edgeType: 'call_argument',
            label: 'arg1: alloc_size',
            isTaintedPath: true,
          },
          {
            id: 'int-e3-4',
            fromNodeId: 'int-3',
            toNodeId: 'int-4',
            edgeType: 'pointer_deref',
            label: 'heap table base',
            isTaintedPath: true,
          },
          {
            id: 'int-e1-4',
            fromNodeId: 'int-1',
            toNodeId: 'int-4',
            edgeType: 'control_dependency',
            label: 'loop limit: num_records',
            isTaintedPath: true,
          },
        ],
        defUseChains: [
          {
            variable: 'num_records',
            defAddress: '0x00404100',
            defInstruction: 'call <read@plt>',
            useAddresses: ['0x00404128', '0x00404180'],
            useInstructions: ['imul $0x40, %eax, %edi', 'cmp %eax, %ecx'],
            scope: 'allocate_record_table',
            storage: 'register',
          },
        ],
      },
      {
        id: 'taint-sanitized-safe',
        title: 'Bounded User Input with Character Whitelist Sanitizer',
        functionName: 'parse_username_input',
        source: {
          type: 'user_arg',
          api: 'fgets',
          address: '0x00405200',
          variable: 'raw_username',
        },
        sink: {
          type: 'buffer_copy',
          api: 'strncpy',
          address: '0x00405290',
          variable: 'dest_username',
          cweId: 'CWE-0: Verified Safe & Sanitized',
        },
        sanitization: 'sanitized',
        exploitability: 'low',
        summary:
          'Input string undergoes explicit boundary verification and regex alphanumeric character filtering prior to bounded strncpy. Taint label stripped by sanitizer node.',
        remediationAdvice:
          'Demonstrates ideal defensive practice. Retain bounds check and ensure destination buffer is explicitly null-terminated.',
        nodes: [
          {
            id: 'safe-1',
            label: 'fgets(raw_username, 64, stdin)',
            instructionAddress: '0x00405200',
            functionName: 'parse_username_input',
            type: 'source',
            description: 'Accepts raw input string from standard input.',
            variableName: 'raw_username',
            registersInvolved: ['%rdi', '%rsi', '%rdx'],
            codeSnippet: 'fgets(raw_username, 64, stdin);',
            isTainted: true,
            taintLevel: 'medium',
            posX: 50,
            posY: 80,
          },
          {
            id: 'safe-2',
            label: 'sanitize_alphanumeric(raw_username)',
            instructionAddress: '0x00405240',
            functionName: 'parse_username_input',
            type: 'sanitizer',
            description: 'Sanitizer function verifies all characters match [a-zA-Z0-9_] and length <= 32.',
            variableName: 'sanitized_name',
            registersInvolved: ['%rdi', '%rax'],
            codeSnippet: 'if (!is_valid_identifier(raw_username, 32)) return -1;',
            isTainted: false,
            taintLevel: 'clean',
            posX: 340,
            posY: 80,
          },
          {
            id: 'safe-3',
            label: 'strncpy(dest_username, sanitized_name, 32)',
            instructionAddress: '0x00405290',
            functionName: 'parse_username_input',
            type: 'sink',
            description: 'Safe bounded copy with guaranteed null termination.',
            variableName: 'dest_username',
            registersInvolved: ['%rdi', '%rsi', '%rdx'],
            codeSnippet: 'strncpy(dest_username, raw_username, 32); dest_username[31] = \'\\0\';',
            isTainted: false,
            taintLevel: 'clean',
            posX: 660,
            posY: 80,
          },
        ],
        edges: [
          {
            id: 'safe-e1-2',
            fromNodeId: 'safe-1',
            toNodeId: 'safe-2',
            edgeType: 'call_argument',
            label: 'untrusted string',
            isTaintedPath: true,
          },
          {
            id: 'safe-e2-3',
            fromNodeId: 'safe-2',
            toNodeId: 'safe-3',
            edgeType: 'call_argument',
            label: 'sanitized & clean',
            isTaintedPath: false,
          },
        ],
        defUseChains: [
          {
            variable: 'raw_username',
            defAddress: '0x00405200',
            defInstruction: 'call <fgets@plt>',
            useAddresses: ['0x00405240', '0x00405290'],
            useInstructions: ['call is_valid_identifier', 'call <strncpy@plt>'],
            scope: 'parse_username_input',
            storage: 'stack',
          },
        ],
      },
    ];
  }

  /**
   * Compute forward slice: all nodes reachable downstream from startNodeId
   */
  computeForwardSlice(path: TaintPath, startNodeId: string): Set<string> {
    const visited = new Set<string>();
    const queue = [startNodeId];
    visited.add(startNodeId);

    while (queue.length > 0) {
      const current = queue.shift()!;
      for (const edge of path.edges) {
        if (edge.fromNodeId === current && !visited.has(edge.toNodeId)) {
          visited.add(edge.toNodeId);
          queue.push(edge.toNodeId);
        }
      }
    }
    return visited;
  }

  /**
   * Compute backward slice: all nodes upstream that influence targetNodeId
   */
  computeBackwardSlice(path: TaintPath, targetNodeId: string): Set<string> {
    const visited = new Set<string>();
    const queue = [targetNodeId];
    visited.add(targetNodeId);

    while (queue.length > 0) {
      const current = queue.shift()!;
      for (const edge of path.edges) {
        if (edge.toNodeId === current && !visited.has(edge.fromNodeId)) {
          visited.add(edge.fromNodeId);
          queue.push(edge.fromNodeId);
        }
      }
    }
    return visited;
  }
}

export const dataFlowService = new DataFlowService();
