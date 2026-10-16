import React, { useState } from 'react';
import { Artifact, AnalysisResult } from '../types/reverseEngineering';
import {
  FileText,
  Download,
  Copy,
  Check,
  ShieldCheck,
  Hash,
  Terminal,
  ExternalLink,
} from 'lucide-react';

interface ReportsCenterProps {
  artifact: Artifact;
  analysis: AnalysisResult;
}

export const ReportsCenter: React.FC<ReportsCenterProps> = ({
  artifact,
  analysis,
}) => {
  const [copiedFormat, setCopiedFormat] = useState<string | null>(null);

  const generateMarkdownReport = (): string => {
    return `# Reverse Engineering & Binary Analysis Dossier
**Target Artifact:** ${artifact.name}
**Format:** ${analysis.metadata.fileFormat}
**Architecture:** ${analysis.metadata.architecture} (${analysis.metadata.bitness}-bit ${analysis.metadata.endianness})
**Cryptographic SHA-256:** \`${artifact.sha256}\`
**Cryptographic MD5:** \`${artifact.md5}\`
**Date of Analysis:** ${analysis.completedAt}
**Analysis Suite:** Eleven v1.0.4, Ghidra MCP v11.1.2, REA v1.4.2, Reverse-Skill v2.1.0

---

## 1. Executive Summary
${analysis.summary.overview}

- **Risk Score:** ${analysis.summary.riskScore}/100
- **Security Posture:** ${analysis.summary.securityPosture}
- **Decompiled Coverage:** ${analysis.summary.decompiledCoveragePercent}%
- **Overall Shannon Entropy:** ${analysis.metadata.overallEntropy.toFixed(2)}/8.0

### Key Observed Behaviors
${analysis.summary.keyBehaviors.map(b => `- ${b}`).join('\n')}

---

## 2. Binary Mitigations & Hardening
- **ASLR / PIE:** ${analysis.metadata.mitigations.aslrPie ? 'Enforced' : 'Disabled'}
- **DEP / NX:** ${analysis.metadata.mitigations.depNx ? 'Enforced' : 'Disabled'}
- **Stack Canaries:** ${analysis.metadata.mitigations.stackCanary ? 'Detected' : 'Not Found'}
- **RELRO:** ${analysis.metadata.mitigations.relro}
- **Code Signature:** ${analysis.metadata.mitigations.authenticodeSigned ? 'Valid' : 'Unsigned / Self-Signed'}

---

## 3. Discovered Security Findings (${analysis.findings.length})
${analysis.findings
  .map(
    f => `### [${f.severity.toUpperCase()}] ${f.title}
- **CWE / CVSS:** ${f.cweId} (Score: ${f.cvss.toFixed(1)})
- **Engine:** ${f.detectedBy}
- **Description:** ${f.description}
- **Evidence:** Function \`${f.functionName || 'Global'}\` at \`${f.address || 'N/A'}\`
- **Remediation:** ${f.remediation}
`
  )
  .join('\n')}

---

## 4. Verification & Provenance
Analysis produced in isolated non-executing worker environment. No arbitrary payload execution permitted without explicit sandbox token.
`;
  };

  const handleDownloadMarkdown = () => {
    const md = generateMarkdownReport();
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${artifact.name}_analysis_report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadJSON = () => {
    const jsonStr = JSON.stringify(
      {
        artifact,
        analysis,
        exportedAt: new Date().toISOString(),
        formatVersion: 'eleven-bundle-v1',
      },
      null,
      2
    );
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${artifact.name}_analysis_bundle.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyMarkdown = () => {
    navigator.clipboard.writeText(generateMarkdownReport());
    setCopiedFormat('md');
    setTimeout(() => setCopiedFormat(null), 2000);
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 bg-neutral-950 text-neutral-200">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-neutral-900 pb-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <FileText className="w-5 h-5 text-amber-400" />
              <h2 className="text-xl font-bold text-white tracking-tight">
                Technical Analysis Report & Export
              </h2>
            </div>
            <p className="text-xs text-neutral-400">
              Cryptographically stamped technical dossier with provenance verification.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-neutral-800 bg-neutral-900 text-xs font-medium text-neutral-300 hover:text-white hover:bg-neutral-800 transition-colors"
            >
              {copiedFormat === 'md' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedFormat === 'md' ? 'Copied' : 'Copy Markdown'}</span>
            </button>

            <button
              onClick={handleDownloadMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-neutral-800 bg-neutral-900 text-xs font-medium text-neutral-300 hover:text-white hover:bg-neutral-800 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download .MD</span>
            </button>

            <button
              onClick={handleDownloadJSON}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-medium text-white transition-colors shadow-lg shadow-indigo-600/20"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON Bundle</span>
            </button>
          </div>
        </div>

        {/* Verification & Provenance Card */}
        <div className="p-4 rounded-xl border border-neutral-800 bg-neutral-900/60 flex items-start gap-4">
          <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-800/40 text-emerald-400 shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div className="space-y-1 text-xs">
            <div className="font-semibold text-white">Cryptographic Integrity & Chain of Custody</div>
            <div className="text-neutral-400 font-mono text-[11px] break-all">
              SHA-256: {artifact.sha256}
            </div>
            <div className="text-neutral-500 font-mono text-[11px]">
              MD5: {artifact.md5} · Captured: {artifact.uploadedAt}
            </div>
          </div>
        </div>

        {/* Report Preview Body */}
        <div className="p-6 rounded-2xl border border-neutral-800 bg-neutral-900/30 space-y-6">
          {/* Executive Overview */}
          <div>
            <h3 className="text-base font-semibold text-white mb-2">1. Executive Overview</h3>
            <p className="text-sm text-neutral-300 leading-relaxed">
              {analysis.summary.overview}
            </p>
          </div>

          {/* Key Behaviors */}
          <div>
            <h3 className="text-base font-semibold text-white mb-2">2. Observed Key Behaviors</h3>
            <ul className="list-disc pl-5 space-y-1 text-xs text-neutral-300">
              {analysis.summary.keyBehaviors.map((b, i) => (
                <li key={i}>{b}</li>
              ))}
            </ul>
          </div>

          {/* Tool Versions Table */}
          <div>
            <h3 className="text-base font-semibold text-white mb-2">3. Tool Versions & Engines</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded-lg bg-neutral-950 border border-neutral-800">
                <div className="text-neutral-500 text-[10px]">Eleven Native</div>
                <div className="text-neutral-200 font-semibold">v1.0.4</div>
              </div>
              <div className="p-2.5 rounded-lg bg-neutral-950 border border-neutral-800">
                <div className="text-neutral-500 text-[10px]">Ghidra MCP</div>
                <div className="text-neutral-200 font-semibold">v11.1.2-mcp</div>
              </div>
              <div className="p-2.5 rounded-lg bg-neutral-950 border border-neutral-800">
                <div className="text-neutral-500 text-[10px]">REA Assistant</div>
                <div className="text-neutral-200 font-semibold">v1.4.2</div>
              </div>
              <div className="p-2.5 rounded-lg bg-neutral-950 border border-neutral-800">
                <div className="text-neutral-500 text-[10px]">Reverse-Skill</div>
                <div className="text-neutral-200 font-semibold">v2.1.0</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
