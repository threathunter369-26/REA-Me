import React, { useState } from 'react';
import {
  Shield,
  Layers,
  ExternalLink,
  Download,
  AlertTriangle,
  CheckCircle2,
  Filter,
  FileCode,
} from 'lucide-react';
import { Artifact, AnalysisResult } from '../types/reverseEngineering';
import { malwareAnalysisService } from '../services/malwareAnalysisService';

interface MitreCapaMatrixProps {
  artifact: Artifact;
  analysis: AnalysisResult;
}

export const MitreCapaMatrix: React.FC<MitreCapaMatrixProps> = ({
  artifact,
  analysis,
}) => {
  const [selectedTactic, setSelectedTactic] = useState<string>('all');
  const { techniques, capaCapabilities } = malwareAnalysisService.getMitreAttackCapabilities(
    artifact,
    analysis
  );

  const tacticsList = [
    'all',
    'Defense Evasion',
    'Persistence',
    'Command and Control',
    'Discovery',
    'Execution',
  ];

  const filteredTechniques = techniques.filter(t => {
    if (selectedTactic === 'all') return true;
    return t.tactic === selectedTactic;
  });

  const handleExportNavigator = () => {
    const navigatorBundle = {
      name: `Eleven ATT&CK Matrix - ${artifact.name}`,
      version: '4.5',
      domain: 'enterprise-attack',
      description: `Automated capability extraction for ${artifact.name} (${artifact.sha256})`,
      techniques: techniques.map(t => ({
        techniqueID: t.id,
        tactic: t.tactic.toLowerCase().replace(/\s+/g, '-'),
        score: t.severity === 'critical' ? 100 : t.severity === 'high' ? 75 : 40,
        comment: t.description,
        enabled: true,
      })),
      gradient: {
        colors: ['#22c55e', '#eab308', '#ef4444'],
        minValue: 0,
        maxValue: 100,
      },
    };

    const blob = new Blob([JSON.stringify(navigatorBundle, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${artifact.name}_mitre_attack_navigator.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-neutral-950 text-neutral-200 overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-neutral-900 bg-neutral-950/80 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-purple-950 border border-purple-800/60 text-purple-400">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <div className="text-sm font-semibold text-white flex items-center gap-2">
              <span>MITRE ATT&CK® & Capa Capability Matrix</span>
              <span className="text-[11px] font-mono text-purple-400">
                ({techniques.length} Techniques Mapped)
              </span>
            </div>
            <p className="text-xs text-neutral-400">
              Correlates decompiled program behavior, API invocation patterns, and opcodes with cyber threat tactics.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleExportNavigator}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-neutral-800 bg-neutral-900 hover:bg-neutral-800 text-xs text-neutral-300 font-medium transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export ATT&CK Navigator JSON</span>
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Tactics Filter Bar */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
          <span className="text-neutral-500 font-medium shrink-0 flex items-center gap-1">
            <Filter className="w-3 h-3" />
            <span>Tactic:</span>
          </span>
          {tacticsList.map(tactic => (
            <button
              key={tactic}
              onClick={() => setSelectedTactic(tactic)}
              className={`px-3 py-1.5 rounded-lg font-medium whitespace-nowrap transition-colors ${
                selectedTactic === tactic
                  ? 'bg-neutral-800 text-white border border-neutral-700'
                  : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
              }`}
            >
              {tactic}
            </button>
          ))}
        </div>

        {/* MITRE Techniques Grid */}
        <div>
          <h3 className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-3">
            Identified Threat Techniques ({filteredTechniques.length})
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredTechniques.map(tech => (
              <div
                key={tech.id}
                className="p-4 rounded-xl border border-neutral-800 bg-neutral-900/60 space-y-3 shadow-md"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <span className="font-mono text-xs font-bold text-indigo-400">{tech.id}</span>
                    <div className="text-xs font-semibold text-white mt-0.5">{tech.name}</div>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold ${
                      tech.severity === 'critical'
                        ? 'bg-red-950 text-red-300 border border-red-800/40'
                        : tech.severity === 'high'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800/40'
                        : 'bg-neutral-800 text-neutral-300'
                    }`}
                  >
                    {tech.tactic}
                  </span>
                </div>

                <p className="text-xs text-neutral-300 leading-relaxed">{tech.description}</p>

                {tech.matchedApis.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] text-neutral-500 uppercase font-mono">Matched Win32/POSIX APIs:</span>
                    <div className="flex flex-wrap gap-1">
                      {tech.matchedApis.map(api => (
                        <span
                          key={api}
                          className="px-1.5 py-0.5 rounded bg-neutral-950 border border-neutral-800 text-[10px] font-mono text-cyan-300"
                        >
                          {api}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Capa Capabilities Section */}
        <div className="pt-4 border-t border-neutral-900">
          <h3 className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-3">
            Capa-Style Program Capabilities ({capaCapabilities.length})
          </h3>
          <div className="divide-y divide-neutral-900 rounded-xl border border-neutral-800 bg-neutral-900/40 overflow-hidden">
            {capaCapabilities.map(cap => (
              <div key={cap.id} className="p-3.5 flex items-start justify-between text-xs hover:bg-neutral-900/60 transition-colors">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-neutral-400">{cap.namespace}</span>
                    <span className="text-neutral-600">/</span>
                    <span className="font-semibold text-white">{cap.name}</span>
                  </div>
                  <p className="text-neutral-400 text-[11px]">{cap.description}</p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {cap.addresses.map(addr => (
                    <span key={addr} className="font-mono text-[10px] text-cyan-400 bg-neutral-950 px-2 py-0.5 rounded border border-neutral-800">
                      {addr}
                    </span>
                  ))}
                  {cap.attAndCk.map(t => (
                    <span key={t} className="font-mono text-[10px] text-purple-300 bg-purple-950/80 px-2 py-0.5 rounded border border-purple-800/40">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
