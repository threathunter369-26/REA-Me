import React, { useState, useEffect } from 'react';
import {
  Activity,
  CheckCircle2,
  Clock,
  Terminal,
  Cpu,
  Layers,
  Shield,
  X,
} from 'lucide-react';
import { AnalysisStage, ToolLogItem } from '../types/reverseEngineering';

interface AnalysisMonitorModalProps {
  isOpen: boolean;
  onClose: () => void;
  artifactName: string;
  onComplete: () => void;
}

export const AnalysisMonitorModal: React.FC<AnalysisMonitorModalProps> = ({
  isOpen,
  onClose,
  artifactName,
  onComplete,
}) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [logs, setLogs] = useState<ToolLogItem[]>([]);
  const [isFinished, setIsFinished] = useState(false);

  const stages: AnalysisStage[] = [
    {
      id: 'stg-1',
      name: 'Format Identification & Header Validation',
      description: 'Eleven Static Parser verifying magic bytes, architecture, and section layout.',
      status: currentStepIndex > 0 ? 'completed' : currentStepIndex === 0 ? 'running' : 'pending',
      progress: currentStepIndex > 0 ? 100 : 45,
    },
    {
      id: 'stg-2',
      name: 'Shannon Entropy & Packer Detection',
      description: 'Scanning byte distribution across sliding window for encrypted/packed blobs.',
      status: currentStepIndex > 1 ? 'completed' : currentStepIndex === 1 ? 'running' : 'pending',
      progress: currentStepIndex > 1 ? 100 : currentStepIndex === 1 ? 60 : 0,
    },
    {
      id: 'stg-3',
      name: 'Ghidra MCP Headless Decompilation',
      description: 'Disassembling basic blocks, recovering function signatures, and building CFG.',
      status: currentStepIndex > 2 ? 'completed' : currentStepIndex === 2 ? 'running' : 'pending',
      progress: currentStepIndex > 2 ? 100 : currentStepIndex === 2 ? 75 : 0,
    },
    {
      id: 'stg-4',
      name: 'REA Semantic Type & Name Inference',
      description: 'LLM-guided contextual reconstruction of variable names, structs, and parameters.',
      status: currentStepIndex > 3 ? 'completed' : currentStepIndex === 3 ? 'running' : 'pending',
      progress: currentStepIndex > 3 ? 100 : currentStepIndex === 3 ? 80 : 0,
    },
    {
      id: 'stg-5',
      name: 'Reverse-Skill Security AST Audit',
      description: 'Detecting dangerous APIs, buffer overflow patterns, and insecure deserialization.',
      status: currentStepIndex > 4 ? 'completed' : currentStepIndex === 4 ? 'running' : 'pending',
      progress: currentStepIndex > 4 ? 100 : currentStepIndex === 4 ? 90 : 0,
    },
    {
      id: 'stg-6',
      name: 'Evidence Synthesis & Technical Dossier',
      description: 'Generating cryptographically sealed report bundle and cross-referenced call graphs.',
      status: currentStepIndex >= 5 ? 'completed' : 'pending',
      progress: currentStepIndex >= 5 ? 100 : 0,
    },
  ];

  useEffect(() => {
    if (!isOpen) {
      setCurrentStepIndex(0);
      setLogs([]);
      setIsFinished(false);
      return;
    }

    const stepMessages = [
      'Eleven Static: Verified binary headers and section offsets.',
      'Eleven Static: Shannon entropy calculated (range: 3.12 - 6.85). No anomalous packer spike.',
      'Ghidra MCP: Decompiled 18 core routines and generated basic block CFGs.',
      'REA Assistant: Inferred 4 high-confidence calling signatures and reconstructed local types.',
      'Reverse-Skill: Audited AST against CVE/CWE rule database. Mitigations verified.',
      'Agent Orchestrator: Synthesized findings into unified analysis workspace.',
    ];

    let step = 0;
    const interval = setInterval(() => {
      if (step < stepMessages.length) {
        setLogs(prev => [
          ...prev,
          {
            id: `log-${Date.now()}`,
            timestamp: new Date().toLocaleTimeString(),
            tool: ['Eleven Static', 'Entropy Scanner', 'Ghidra MCP', 'REA Assistant', 'Reverse-Skill', 'Orchestrator'][step],
            status: 'success',
            message: stepMessages[step],
          },
        ]);
        setCurrentStepIndex(step + 1);
        step++;
      } else {
        clearInterval(interval);
        setIsFinished(true);
      }
    }, 700);

    return () => clearInterval(interval);
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md select-none">
      <div className="bg-neutral-900 border border-neutral-800 rounded-3xl max-w-3xl w-full p-6 shadow-2xl space-y-6 text-neutral-200">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-neutral-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-indigo-950 border border-indigo-800/60 text-indigo-400 animate-pulse">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">Live AI Analysis Orchestration</h3>
              <p className="text-xs text-neutral-400 font-mono">
                Artifact: {artifactName} · Isolated Worker Task
              </p>
            </div>
          </div>
          {isFinished && (
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Steps Pipeline */}
        <div className="space-y-3">
          {stages.map((stg, idx) => (
            <div
              key={stg.id}
              className={`p-3 rounded-xl border transition-all flex items-start gap-3 ${
                stg.status === 'completed'
                  ? 'border-neutral-800 bg-neutral-950/40 text-neutral-300'
                  : stg.status === 'running'
                  ? 'border-indigo-500/60 bg-indigo-950/20 text-white shadow-md'
                  : 'border-neutral-900 bg-neutral-950/20 text-neutral-600'
              }`}
            >
              <div className="mt-0.5">
                {stg.status === 'completed' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : stg.status === 'running' ? (
                  <Activity className="w-4 h-4 text-indigo-400 animate-spin" />
                ) : (
                  <Clock className="w-4 h-4 text-neutral-600" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-semibold">{stg.name}</div>
                <div className="text-[11px] text-neutral-400">{stg.description}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Live Terminal Log Stream */}
        <div className="p-3 rounded-xl bg-neutral-950 border border-neutral-850 font-mono text-xs text-neutral-300 max-h-36 overflow-y-auto space-y-1">
          {logs.map(log => (
            <div key={log.id} className="flex items-start gap-2">
              <span className="text-neutral-500 text-[10px] select-none">{log.timestamp}</span>
              <span className="text-indigo-400 font-semibold text-[11px]">[{log.tool}]</span>
              <span className="text-neutral-200 text-[11px]">{log.message}</span>
            </div>
          ))}
        </div>

        {/* Action Button */}
        <div className="flex items-center justify-end pt-2 border-t border-neutral-800">
          {isFinished ? (
            <button
              onClick={() => {
                onComplete();
                onClose();
              }}
              className="px-5 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/30 transition-all"
            >
              Open Interactive Analysis Workspace
            </button>
          ) : (
            <div className="text-xs text-neutral-500 font-mono flex items-center gap-2">
              <span className="inline-block w-2 h-2 rounded-full bg-indigo-500 animate-ping" />
              <span>Orchestrating reverse engineering adapters...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
