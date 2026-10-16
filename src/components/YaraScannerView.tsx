import React, { useState } from 'react';
import {
  ShieldAlert,
  Play,
  Plus,
  Sparkles,
  CheckCircle2,
  Copy,
  Check,
  Code,
  FileCheck,
  Tag,
  AlertTriangle,
} from 'lucide-react';
import { Artifact, AnalysisResult, YaraRule, YaraMatchResult } from '../types/reverseEngineering';
import { malwareAnalysisService } from '../services/malwareAnalysisService';

interface YaraScannerViewProps {
  artifact: Artifact;
  analysis: AnalysisResult;
}

export const YaraScannerView: React.FC<YaraScannerViewProps> = ({
  artifact,
  analysis,
}) => {
  const [rules, setRules] = useState<YaraRule[]>(malwareAnalysisService.getDefaultYaraRules());
  const [selectedRuleId, setSelectedRuleId] = useState<string>(rules[0]?.id || '');
  const [matches, setMatches] = useState<YaraMatchResult[]>(() =>
    malwareAnalysisService.scanYara(artifact, analysis, rules)
  );
  const [isScanning, setIsScanning] = useState(false);
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);
  const [copiedRule, setCopiedRule] = useState(false);

  const selectedRule = rules.find(r => r.id === selectedRuleId) || rules[0];

  const handleRunScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      const results = malwareAnalysisService.scanYara(artifact, analysis, rules);
      setMatches(results);
      setIsScanning(false);
    }, 400);
  };

  const handleToggleRule = (id: string) => {
    setRules(prev =>
      prev.map(r => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const handleGenerateAiRule = async () => {
    setIsGeneratingAi(true);
    try {
      const res = await fetch('/api/ai/generate-yara', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          artifactName: artifact.name,
          architecture: artifact.architecture,
          format: artifact.formatDetails,
          findings: analysis.findings.map(f => f.title),
          strings: analysis.strings.slice(0, 8).map(s => s.value),
        }),
      });

      if (res.ok) {
        const data = await res.json();
        const newRule: YaraRule = {
          id: `rule-ai-${Date.now()}`,
          name: data.ruleName || `AI_Generated_${artifact.name.replace(/[^a-zA-Z0-9]/g, '_')}`,
          tags: ['ai_generated', 'threat_intel', artifact.type],
          meta: {
            author: 'Eleven Gemini Threat Agent',
            description: `Automated detection signature for ${artifact.name}`,
            severity: 'high',
            date: new Date().toISOString().split('T')[0],
          },
          ruleText: data.ruleText,
          enabled: true,
        };
        setRules(prev => [newRule, ...prev]);
        setSelectedRuleId(newRule.id);
      }
    } catch (err) {
      console.warn('Using fallback AI YARA rule generator');
      const fallbackRuleText = `rule Malicious_${artifact.name.replace(/[^a-zA-Z0-9]/g, '_')}_Signature {
    meta:
        description = "Identifies indicators associated with ${artifact.name}"
        author = "Eleven AI Lab"
        sha256 = "${artifact.sha256}"
        date = "${new Date().toISOString().split('T')[0]}"
    strings:
        $s1 = "${analysis.strings[0]?.value || 'http://'}" ascii
        $s2 = "${analysis.strings[1]?.value || 'cmd.exe'}" ascii
        $entry_magic = { 55 48 89 E5 }
    condition:
        all of ($s*) or $entry_magic
}`;
      const newRule: YaraRule = {
        id: `rule-ai-${Date.now()}`,
        name: `Signature_${artifact.name.replace(/[^a-zA-Z0-9]/g, '_')}`,
        tags: ['ai_generated', 'heuristics'],
        meta: {
          author: 'Eleven AI Lab',
          description: `Custom heuristic rule for ${artifact.name}`,
          severity: 'high',
          date: new Date().toISOString().split('T')[0],
        },
        ruleText: fallbackRuleText,
        enabled: true,
      };
      setRules(prev => [newRule, ...prev]);
      setSelectedRuleId(newRule.id);
    } finally {
      setIsGeneratingAi(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2000);
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-neutral-950 text-neutral-200 overflow-hidden">
      {/* Top Action Bar */}
      <div className="px-6 py-3 border-b border-neutral-900 bg-neutral-950/80 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-indigo-950 border border-indigo-800/60 text-indigo-400">
            <FileCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="text-sm font-semibold text-white flex items-center gap-2">
              <span>YARA Pattern Matching & Rule Engine</span>
              <span className="text-[11px] font-mono text-cyan-400">
                ({matches.length} Matches Detected)
              </span>
            </div>
            <p className="text-xs text-neutral-400">
              Live byte-pattern and string signature scanner for threat triage and malware family attribution.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleGenerateAiRule}
            disabled={isGeneratingAi}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-indigo-800/60 bg-indigo-950/60 hover:bg-indigo-900/80 text-indigo-300 text-xs font-medium transition-colors shadow-sm"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>{isGeneratingAi ? 'Generating Rule...' : 'Generate AI YARA Rule'}</span>
          </button>

          <button
            onClick={handleRunScan}
            disabled={isScanning}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold transition-colors shadow-sm"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isScanning ? 'Scanning...' : 'Scan Binary Now'}</span>
          </button>
        </div>
      </div>

      {/* Main Split Layout: Left Rules / Matches & Right Rule Editor */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Active Rules & Matches */}
        <div className="w-96 border-r border-neutral-900 bg-neutral-950 flex flex-col shrink-0 overflow-y-auto">
          {/* Matches Section */}
          <div className="p-3 border-b border-neutral-900 bg-neutral-900/30">
            <div className="text-xs font-semibold text-neutral-300 uppercase tracking-wider mb-2 flex items-center justify-between">
              <span>Detection Matches</span>
              <span className="px-2 py-0.2 rounded bg-red-950 text-red-400 text-[10px] font-bold">
                {matches.length} TRIGGERS
              </span>
            </div>

            {matches.length === 0 ? (
              <div className="p-3 rounded-lg border border-neutral-800 text-[11px] text-neutral-500 text-center">
                No signatures triggered for {artifact.name}.
              </div>
            ) : (
              <div className="space-y-2">
                {matches.map((m, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl border border-red-900/40 bg-red-950/20 text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-red-400">{m.ruleName}</span>
                      <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800/40">
                        {m.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-neutral-300">{m.description}</p>
                    <div className="space-y-1 pt-1 border-t border-red-900/30 font-mono text-[10px] text-neutral-400">
                      {m.matchedOffsets.map((mo, i) => (
                        <div key={i} className="flex items-center justify-between">
                          <span className="text-indigo-400">{mo.identifier}</span>
                          <span className="text-neutral-500">{mo.offset}</span>
                          <span className="truncate max-w-[120px] text-neutral-300">{mo.preview}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Rules List */}
          <div className="flex-1 p-3 space-y-1">
            <div className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-2 px-1">
              Active Signature Rules ({rules.length})
            </div>
            {rules.map(rule => {
              const isSelected = selectedRule?.id === rule.id;
              const hasMatched = matches.some(m => m.ruleId === rule.id);
              return (
                <div
                  key={rule.id}
                  onClick={() => setSelectedRuleId(rule.id)}
                  className={`p-3 rounded-xl border cursor-pointer transition-colors flex items-start justify-between ${
                    isSelected
                      ? 'border-indigo-500/60 bg-neutral-900 text-white'
                      : 'border-neutral-900 hover:border-neutral-800 bg-neutral-950 text-neutral-300'
                  }`}
                >
                  <div className="min-w-0 pr-2 space-y-1">
                    <div className="font-mono text-xs font-semibold truncate flex items-center gap-1.5">
                      <span>{rule.name}</span>
                      {hasMatched && (
                        <span className="w-2 h-2 rounded-full bg-red-500 shrink-0" title="Matched" />
                      )}
                    </div>
                    <div className="text-[11px] text-neutral-400 line-clamp-1">
                      {rule.meta.description}
                    </div>
                    <div className="flex flex-wrap gap-1 pt-0.5">
                      {rule.tags.map(t => (
                        <span
                          key={t}
                          className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-neutral-900 text-neutral-400 border border-neutral-800"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    onChange={() => handleToggleRule(rule.id)}
                    onClick={e => e.stopPropagation()}
                    className="mt-1 cursor-pointer accent-indigo-600"
                  />
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: YARA Rule Definition & Syntax View */}
        <div className="flex-1 flex flex-col overflow-hidden bg-neutral-950 p-6">
          {selectedRule ? (
            <div className="flex-1 flex flex-col space-y-4 max-w-4xl">
              <div className="flex items-center justify-between pb-3 border-b border-neutral-900">
                <div>
                  <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                    <Code className="w-4 h-4 text-indigo-400" />
                    <span>{selectedRule.name}</span>
                  </h3>
                  <p className="text-xs text-neutral-400 mt-0.5">
                    Author: {selectedRule.meta.author} · Severity: {selectedRule.meta.severity}
                  </p>
                </div>

                <button
                  onClick={() => handleCopy(selectedRule.ruleText)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-neutral-800 bg-neutral-900 hover:bg-neutral-800 text-xs text-neutral-300 transition-colors"
                >
                  {copiedRule ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedRule ? 'Copied' : 'Copy Rule'}</span>
                </button>
              </div>

              {/* Rule Editor / Display */}
              <div className="flex-1 rounded-xl border border-neutral-800 bg-neutral-900/60 p-4 font-mono text-xs text-neutral-200 overflow-auto whitespace-pre leading-relaxed shadow-inner">
                {selectedRule.ruleText}
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-neutral-500">
              Select a rule to view syntax and definitions.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
