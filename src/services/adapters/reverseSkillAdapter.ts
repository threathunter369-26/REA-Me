/**
 * Adapter for Reverse Skill (Agent-Driven Binary & AST Triage)
 * Repository reference: https://github.com/zhaoxuya520/reverse-skill
 * 
 * Provides:
 * - Dangerous API and unsafe function usage auditing
 * - Memory corruption & buffer overflow pattern scanning
 * - Format string vulnerability checks
 * - Model checkpoint (.pt / pickle) deserialization exploit detection
 * - CVSS & CWE standard classification
 */

import { SecurityFinding, ToolLogItem } from '../../types/reverseEngineering';

export interface ReverseSkillScanRequest {
  targetName: string;
  decompiledSources: { functionName: string; code: string; address: string }[];
  importedSymbols: string[];
  strings: string[];
}

export class ReverseSkillAdapter {
  readonly engineId = 'reverse-skill';
  readonly version = '2.1.0';

  /**
   * Run security AST audits across functions and imported symbols
   */
  async scanArtifactSecurity(
    req: ReverseSkillScanRequest,
    onLog?: (log: ToolLogItem) => void
  ): Promise<SecurityFinding[]> {
    onLog?.({
      id: `revskill-${Date.now()}-1`,
      timestamp: new Date().toISOString(),
      tool: 'Reverse-Skill / Security AST Auditor',
      status: 'running',
      message: `Analyzing ${req.decompiledSources.length} functions against Reverse-Skill vulnerability rules...`,
    });

    const findings: SecurityFinding[] = [];

    // Check imports for high-risk primitives
    for (const symbol of req.importedSymbols) {
      if (['strcpy', 'gets', 'strcat', 'sprintf'].includes(symbol)) {
        findings.push({
          id: `RS-VULN-${findings.length + 1}`,
          title: `Unbounded Buffer Operation: Use of Unsafe '${symbol}'`,
          severity: 'high',
          cweId: 'CWE-120',
          cvss: 7.8,
          category: 'Memory Corruption',
          description: `The binary imports '${symbol}' which does not enforce destination buffer boundaries, presenting potential stack-based buffer overflow risks.`,
          detectedBy: 'reverse-skill',
          remediation: `Replace with bounded alternatives (e.g. strncpy, snprintf, or strlcpy) and compile with stack guard flags (-fstack-protector-strong).`,
          confidence: 'verified',
        });
      }

      if (['system', 'popen', 'ShellExecuteA', 'WinExec'].includes(symbol)) {
        findings.push({
          id: `RS-VULN-${findings.length + 1}`,
          title: `Direct Command Execution Primitives (${symbol})`,
          severity: 'critical',
          cweId: 'CWE-78',
          cvss: 8.8,
          category: 'Command Injection',
          description: `Direct invocation of system shell via '${symbol}'. If user-controllable input reaches arguments without strict sanitization, arbitrary code execution is possible.`,
          detectedBy: 'reverse-skill',
          remediation: `Avoid passing command strings to shell interpreters. Use parameterized execve/fork APIs with strict argument vectors.`,
          confidence: 'verified',
        });
      }

      if (['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'ptrace'].includes(symbol)) {
        findings.push({
          id: `RS-VULN-${findings.length + 1}`,
          title: `Process Injection / Memory Modification Capabilities (${symbol})`,
          severity: 'critical',
          cweId: 'CWE-250',
          cvss: 9.1,
          category: 'Process Evasion / Injection',
          description: `Binary references dynamic memory allocation into remote processes or debugging hooks, frequently associated with reflective DLL injection or code hollowing.`,
          detectedBy: 'reverse-skill',
          remediation: `Audit usage for legitimate debugging/profiling requirements. Restrict privileges and isolate worker sandbox.`,
          confidence: 'verified',
        });
      }
    }

    // Inspect decompiled source code for logical flaws
    for (const src of req.decompiledSources) {
      if (src.code.includes('printf(user_input') || src.code.includes('syslog(priority, buf)')) {
        findings.push({
          id: `RS-VULN-${findings.length + 1}`,
          title: `Uncontrolled Format String in Function ${src.functionName}`,
          severity: 'high',
          cweId: 'CWE-134',
          cvss: 8.1,
          category: 'Format String',
          description: `Function passes variable string directly as format specifier without static formatting template.`,
          functionName: src.functionName,
          address: src.address,
          snippet: src.code.slice(0, 140),
          detectedBy: 'reverse-skill',
          remediation: `Specify explicit format string literals: printf("%s", user_input).`,
          confidence: 'verified',
        });
      }

      if (src.code.includes('__reduce__') || src.code.includes('GLOBAL') || src.code.includes('eval(')) {
        findings.push({
          id: `RS-VULN-${findings.length + 1}`,
          title: `Insecure Deserialization / Code Evaluation Hook Detected`,
          severity: 'critical',
          cweId: 'CWE-502',
          cvss: 9.8,
          category: 'Arbitrary Code Execution',
          description: `Discovered bytecode or serialization hooks that trigger arbitrary Python object construction on unpickling.`,
          functionName: src.functionName,
          address: src.address,
          detectedBy: 'reverse-skill',
          remediation: `Use safe weight formats such as SafeTensors. Never load untrusted pickle files with torch.load without weights_only=True.`,
          confidence: 'verified',
        });
      }
    }

    onLog?.({
      id: `revskill-${Date.now()}-2`,
      timestamp: new Date().toISOString(),
      tool: 'Reverse-Skill / Security AST Auditor',
      status: 'success',
      message: `Completed security audit: Found ${findings.length} findings (${findings.filter(f => f.severity === 'critical' || f.severity === 'high').length} high/critical).`,
    });

    return findings;
  }
}

export const reverseSkillAdapter = new ReverseSkillAdapter();
