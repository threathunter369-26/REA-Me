import React, { useState, useEffect } from 'react';
import {
  Artifact,
  AnalysisResult,
  TaintPath,
  DataFlowNode,
} from '../types/reverseEngineering';
import { dataFlowService } from '../services/dataFlowService';
import {
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  Pause,
  RotateCcw,
  SkipForward,
  SkipBack,
  Sparkles,
  GitCommit,
  Network,
  Split,
  Layers,
  Cpu,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  ChevronRight,
  Database,
} from 'lucide-react';

interface DataFlowAnalysisViewProps {
  artifact: Artifact;
  analysis?: AnalysisResult;
  onNavigateToVexIr?: () => void;
}

export const DataFlowAnalysisView: React.FC<DataFlowAnalysisViewProps> = ({
  artifact,
  analysis,
  onNavigateToVexIr,
}) => {
  const [taintPaths, setTaintPaths] = useState<TaintPath[]>([]);
  const [selectedPathId, setSelectedPathId] = useState<string>('');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // Stepper state
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);

  // Slicing state
  const [sliceMode, setSliceMode] = useState<'none' | 'forward' | 'backward'>('none');
  const [slicedNodeIds, setSlicedNodeIds] = useState<Set<string>>(new Set());

  // Active Tab
  const [activeTab, setActiveTab] = useState<'graph' | 'defuse' | 'ai'>('graph');

  // AI Analysis state
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  useEffect(() => {
    const paths = dataFlowService.getDefaultTaintPaths();
    setTaintPaths(paths);
    if (paths.length > 0) {
      setSelectedPathId(paths[0].id);
      setCurrentStepIndex(0);
      setSelectedNodeId(paths[0].nodes[0]?.id || null);
    }
  }, [artifact.id]);

  const activePath = taintPaths.find((p) => p.id === selectedPathId) || taintPaths[0];

  // Auto-play stepper timer
  useEffect(() => {
    if (!isPlaying || !activePath) return;

    const timer = setInterval(() => {
      setCurrentStepIndex((prev) => {
        if (prev >= activePath.nodes.length - 1) {
          setIsPlaying(false);
          return prev;
        }
        const next = prev + 1;
        setSelectedNodeId(activePath.nodes[next]?.id || null);
        return next;
      });
    }, 1200);

    return () => clearInterval(timer);
  }, [isPlaying, activePath]);

  const handleSelectPath = (pathId: string) => {
    setSelectedPathId(pathId);
    setCurrentStepIndex(0);
    setIsPlaying(false);
    setSliceMode('none');
    setSlicedNodeIds(new Set());
    const path = taintPaths.find((p) => p.id === pathId);
    if (path && path.nodes.length > 0) {
      setSelectedNodeId(path.nodes[0].id);
    }
    setAiAnalysis(null);
  };

  const handleStepForward = () => {
    if (!activePath) return;
    if (currentStepIndex < activePath.nodes.length - 1) {
      const next = currentStepIndex + 1;
      setCurrentStepIndex(next);
      setSelectedNodeId(activePath.nodes[next]?.id || null);
    }
  };

  const handleStepBackward = () => {
    if (!activePath) return;
    if (currentStepIndex > 0) {
      const prev = currentStepIndex - 1;
      setCurrentStepIndex(prev);
      setSelectedNodeId(activePath.nodes[prev]?.id || null);
    }
  };

  const handleResetStepper = () => {
    setCurrentStepIndex(0);
    setIsPlaying(false);
    if (activePath && activePath.nodes.length > 0) {
      setSelectedNodeId(activePath.nodes[0].id);
    }
  };

  const handleComputeForwardSlice = (nodeId: string) => {
    if (!activePath) return;
    const slice = dataFlowService.computeForwardSlice(activePath, nodeId);
    setSlicedNodeIds(slice);
    setSliceMode('forward');
  };

  const handleComputeBackwardSlice = (nodeId: string) => {
    if (!activePath) return;
    const slice = dataFlowService.computeBackwardSlice(activePath, nodeId);
    setSlicedNodeIds(slice);
    setSliceMode('backward');
  };

  const handleClearSlice = () => {
    setSliceMode('none');
    setSlicedNodeIds(new Set());
  };

  const handleRunAiAnalysis = async () => {
    if (!activePath) return;
    setIsAiLoading(true);
    setActiveTab('ai');
    try {
      const response = await fetch('/api/ai/dataflow-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: activePath.title,
          functionName: activePath.functionName,
          source: activePath.source,
          sink: activePath.sink,
          nodes: activePath.nodes,
          sanitization: activePath.sanitization,
          exploitability: activePath.exploitability,
        }),
      });
      const data = await response.json();
      setAiAnalysis(data.analysis || 'Analysis generation complete.');
    } catch (e: any) {
      setAiAnalysis(`Error requesting AI root cause analysis: ${e.message}`);
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const selectedNode = activePath?.nodes.find((n) => n.id === selectedNodeId) || activePath?.nodes[0];

  return (
    <div className="flex-1 flex flex-col h-full bg-neutral-950 text-neutral-200 overflow-hidden select-none">
      {/* Top Header Bar */}
      <div className="border-b border-neutral-900 bg-neutral-950 px-6 py-3 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-red-950/40 border border-red-800/40 text-red-400">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-white tracking-tight">
                Data Flow & Taint Analysis
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-neutral-900 text-neutral-400 border border-neutral-800">
                Source-to-Sink Graph
              </span>
            </div>
            <p className="text-xs text-neutral-400">
              Inter-procedural taint propagation tracking, Def-Use chains, and invariant sanitization checks.
            </p>
          </div>
        </div>

        {/* Path Selector Tabs */}
        <div className="flex items-center gap-2 overflow-x-auto max-w-xl py-1">
          {taintPaths.map((p) => {
            const isSelected = p.id === selectedPathId;
            return (
              <button
                key={p.id}
                onClick={() => handleSelectPath(p.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors flex items-center gap-2 border ${
                  isSelected
                    ? 'bg-neutral-800 text-white border-neutral-700 shadow-sm'
                    : 'bg-neutral-900/60 text-neutral-400 border-neutral-800/60 hover:text-neutral-200 hover:bg-neutral-900'
                }`}
              >
                {p.sanitization === 'sanitized' ? (
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                ) : p.exploitability === 'critical' ? (
                  <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                ) : (
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                )}
                <span>{p.title.split(' to ')[0]}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Path Metadata Banner */}
      {activePath && (
        <div className="bg-neutral-900/40 border-b border-neutral-900 px-6 py-2.5 flex flex-wrap items-center justify-between gap-4 text-xs">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-1.5 text-neutral-400 font-mono">
              <span className="text-neutral-500">Fn:</span>
              <span className="text-indigo-300 font-semibold">{activePath.functionName}()</span>
            </div>

            <div className="flex items-center gap-1.5 font-mono">
              <span className="text-neutral-500">Source:</span>
              <span className="px-2 py-0.5 rounded bg-blue-950/50 border border-blue-900/50 text-blue-300">
                {activePath.source.api} ({activePath.source.address})
              </span>
            </div>

            <ArrowRight className="w-3.5 h-3.5 text-neutral-600 hidden sm:block" />

            <div className="flex items-center gap-1.5 font-mono">
              <span className="text-neutral-500">Sink:</span>
              <span className="px-2 py-0.5 rounded bg-red-950/50 border border-red-900/50 text-red-300">
                {activePath.sink.api} ({activePath.sink.address})
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-neutral-500 font-mono">Status:</span>
              <span
                className={`px-2 py-0.5 rounded font-mono text-[11px] font-medium border ${
                  activePath.sanitization === 'sanitized'
                    ? 'bg-emerald-950/40 text-emerald-300 border-emerald-800/40'
                    : activePath.sanitization === 'partially_checked'
                    ? 'bg-amber-950/40 text-amber-300 border-amber-800/40'
                    : 'bg-red-950/40 text-red-300 border-red-800/40'
                }`}
              >
                {activePath.sanitization.toUpperCase()}
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-neutral-500 font-mono">Exploitability:</span>
              <span
                className={`px-2 py-0.5 rounded font-mono text-[11px] font-semibold ${
                  activePath.exploitability === 'critical'
                    ? 'text-red-400'
                    : activePath.exploitability === 'high'
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {activePath.exploitability.toUpperCase()}
              </span>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2 ml-auto">
            {onNavigateToVexIr && (
              <button
                onClick={onNavigateToVexIr}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-neutral-800 hover:bg-neutral-700 text-indigo-300 border border-indigo-700/50 transition-colors shadow-sm"
              >
                <Cpu className="w-3.5 h-3.5 text-indigo-400" />
                <span>Open in VEX-IR Taint Engine</span>
              </button>
            )}

            <button
              onClick={handleRunAiAnalysis}
              disabled={isAiLoading}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors shadow-sm"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{isAiLoading ? 'Synthesizing...' : 'AI Vulnerability Diagnosis'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Main Workspace Layout */}
      <div className="flex-1 flex flex-col lg:flex-row overflow-hidden">
        {/* Left Side: Graph DAG / Flow Stepper / Def-Use */}
        <div className="flex-1 flex flex-col border-r border-neutral-900 overflow-hidden">
          {/* View Toolbar */}
          <div className="bg-neutral-900/30 border-b border-neutral-900 px-6 py-2 flex items-center justify-between gap-4">
            {/* View Sub-Tabs */}
            <div className="flex items-center gap-1 bg-neutral-900 p-1 rounded-lg border border-neutral-800">
              <button
                onClick={() => setActiveTab('graph')}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                  activeTab === 'graph'
                    ? 'bg-neutral-800 text-white shadow-sm'
                    : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                Taint DAG Graph
              </button>
              <button
                onClick={() => setActiveTab('defuse')}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                  activeTab === 'defuse'
                    ? 'bg-neutral-800 text-white shadow-sm'
                    : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                Def-Use Chains ({activePath?.defUseChains?.length || 0})
              </button>
              <button
                onClick={() => setActiveTab('ai')}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 ${
                  activeTab === 'ai'
                    ? 'bg-neutral-800 text-indigo-300 shadow-sm'
                    : 'text-neutral-400 hover:text-neutral-200'
                }`}
              >
                <Sparkles className="w-3 h-3 text-indigo-400" />
                <span>AI Root Cause</span>
              </button>
            </div>

            {/* Stepper Controls */}
            {activeTab === 'graph' && activePath && (
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono text-neutral-400 mr-2">
                  Step {currentStepIndex + 1} of {activePath.nodes.length}
                </span>

                <button
                  onClick={handleStepBackward}
                  disabled={currentStepIndex === 0}
                  className="p-1.5 rounded-lg bg-neutral-900 border border-neutral-800 text-neutral-400 hover:text-white disabled:opacity-40"
                  title="Previous Step"
                >
                  <SkipBack className="w-3.5 h-3.5" />
                </button>

                <button
                  onClick={() => setIsPlaying(!isPlaying)}
                  className="p-1.5 rounded-lg bg-neutral-900 border border-neutral-800 text-neutral-300 hover:text-white"
                  title={isPlaying ? 'Pause Emulation' : 'Play Taint Flow'}
                >
                  {isPlaying ? <Pause className="w-3.5 h-3.5 text-amber-400" /> : <Play className="w-3.5 h-3.5 text-emerald-400" />}
                </button>

                <button
                  onClick={handleStepForward}
                  disabled={currentStepIndex === activePath.nodes.length - 1}
                  className="p-1.5 rounded-lg bg-neutral-900 border border-neutral-800 text-neutral-400 hover:text-white disabled:opacity-40"
                  title="Next Step"
                >
                  <SkipForward className="w-3.5 h-3.5" />
                </button>

                <button
                  onClick={handleResetStepper}
                  className="p-1.5 rounded-lg bg-neutral-900 border border-neutral-800 text-neutral-400 hover:text-white"
                  title="Reset"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          {/* Tab 1: Interactive Taint DAG Graph View */}
          {activeTab === 'graph' && activePath && (
            <div className="flex-1 overflow-auto p-6 bg-neutral-950 relative flex flex-col justify-between">
              {/* Slicing Controls Pill */}
              <div className="flex items-center justify-between pb-4">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-neutral-400 font-medium">Program Slicing:</span>
                  {selectedNodeId && (
                    <>
                      <button
                        onClick={() => handleComputeForwardSlice(selectedNodeId)}
                        className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                          sliceMode === 'forward'
                            ? 'bg-purple-900/60 text-purple-300 border border-purple-700'
                            : 'bg-neutral-900 text-neutral-300 border border-neutral-800 hover:bg-neutral-800'
                        }`}
                      >
                        Forward Slice ↓
                      </button>
                      <button
                        onClick={() => handleComputeBackwardSlice(selectedNodeId)}
                        className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                          sliceMode === 'backward'
                            ? 'bg-blue-900/60 text-blue-300 border border-blue-700'
                            : 'bg-neutral-900 text-neutral-300 border border-neutral-800 hover:bg-neutral-800'
                        }`}
                      >
                        Backward Slice ↑
                      </button>
                    </>
                  )}
                  {sliceMode !== 'none' && (
                    <button
                      onClick={handleClearSlice}
                      className="px-2 py-1 rounded text-xs text-neutral-400 hover:text-neutral-200 underline"
                    >
                      Clear Slice ({slicedNodeIds.size} nodes)
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-4 text-[11px] font-mono text-neutral-400">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
                    <span>Tainted Source / Sink</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" />
                    <span>Propagation</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
                    <span>Sanitizer Check</span>
                  </div>
                </div>
              </div>

              {/* Sequential Flow Representation with DAG Node Cards */}
              <div className="flex-1 flex flex-col gap-6 items-center justify-center py-4">
                <div className="w-full max-w-3xl space-y-4">
                  {activePath.nodes.map((node, index) => {
                    const isCurrentStep = index === currentStepIndex;
                    const isSelected = node.id === selectedNodeId;
                    const isSliced = slicedNodeIds.has(node.id);

                    let badgeColor = 'bg-neutral-800 text-neutral-300 border-neutral-700';
                    let ringBorder = 'border-neutral-800';

                    if (node.type === 'source') {
                      badgeColor = 'bg-blue-950/80 text-blue-300 border-blue-800';
                      ringBorder = 'border-blue-700/60';
                    } else if (node.type === 'sink') {
                      badgeColor = 'bg-red-950/80 text-red-300 border-red-800';
                      ringBorder = 'border-red-700/60';
                    } else if (node.type === 'sanitizer') {
                      badgeColor = node.taintLevel === 'clean'
                        ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                        : 'bg-amber-950/80 text-amber-300 border-amber-800';
                      ringBorder = 'border-amber-700/60';
                    }

                    if (isCurrentStep) {
                      ringBorder = 'ring-2 ring-indigo-500 border-indigo-400';
                    } else if (isSelected) {
                      ringBorder = 'ring-1 ring-neutral-400 border-neutral-400';
                    }

                    if (isSliced) {
                      ringBorder += ' ring-2 ring-purple-500';
                    }

                    return (
                      <React.Fragment key={node.id}>
                        <div
                          onClick={() => {
                            setSelectedNodeId(node.id);
                            setCurrentStepIndex(index);
                          }}
                          className={`w-full p-4 rounded-xl bg-neutral-900/90 border transition-all cursor-pointer shadow-md ${ringBorder}`}
                        >
                          <div className="flex items-start justify-between gap-3 mb-2">
                            <div className="flex items-center gap-2">
                              <span
                                className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${badgeColor}`}
                              >
                                {node.type}
                              </span>
                              <span className="font-mono text-xs font-semibold text-white">
                                {node.label}
                              </span>
                            </div>

                            <div className="flex items-center gap-2 font-mono text-[11px] text-neutral-400">
                              <span>{node.instructionAddress || 'Offset N/A'}</span>
                              {node.isTainted ? (
                                <span className="flex items-center gap-1 text-red-400 bg-red-950/40 px-1.5 py-0.5 rounded border border-red-900/50">
                                  <AlertTriangle className="w-3 h-3" />
                                  <span>TAINTED</span>
                                </span>
                              ) : (
                                <span className="flex items-center gap-1 text-emerald-400 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-900/50">
                                  <CheckCircle2 className="w-3 h-3" />
                                  <span>CLEAN</span>
                                </span>
                              )}
                            </div>
                          </div>

                          <p className="text-xs text-neutral-400 mb-2 leading-relaxed">
                            {node.description}
                          </p>

                          {/* Code Snippet Box */}
                          {node.codeSnippet && (
                            <div className="bg-neutral-950 p-2.5 rounded-lg border border-neutral-800/80 font-mono text-xs text-neutral-300 overflow-x-auto">
                              <code>{node.codeSnippet}</code>
                            </div>
                          )}

                          {/* Involved registers & variable chips */}
                          <div className="flex flex-wrap items-center gap-2 mt-2 pt-2 border-t border-neutral-800/60 text-[11px] font-mono">
                            {node.variableName && (
                              <span className="text-indigo-400">
                                Var: <span className="text-neutral-300 font-semibold">{node.variableName}</span>
                              </span>
                            )}
                            {node.registersInvolved && node.registersInvolved.length > 0 && (
                              <span className="text-neutral-500 ml-auto">
                                Registers: {node.registersInvolved.join(', ')}
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Edge Connector */}
                        {index < activePath.nodes.length - 1 && (
                          <div className="flex flex-col items-center justify-center my-0.5">
                            <div className="w-0.5 h-4 bg-gradient-to-b from-neutral-700 to-indigo-500" />
                            <div className="w-2 h-2 rotate-45 border-b-2 border-r-2 border-indigo-400" />
                          </div>
                        )}
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Def-Use Chains */}
          {activeTab === 'defuse' && activePath && (
            <div className="flex-1 overflow-auto p-6 bg-neutral-950">
              <div className="max-w-4xl mx-auto space-y-4">
                <div className="border-b border-neutral-900 pb-2">
                  <h3 className="text-sm font-semibold text-white">
                    Variable Definition-Use (Def-Use) Chains
                  </h3>
                  <p className="text-xs text-neutral-400">
                    Static data dependency tracking connecting memory definitions to all consumption sites.
                  </p>
                </div>

                {activePath.defUseChains && activePath.defUseChains.length > 0 ? (
                  <div className="space-y-3">
                    {activePath.defUseChains.map((du, idx) => (
                      <div
                        key={idx}
                        className="p-4 rounded-xl bg-neutral-900/60 border border-neutral-800 space-y-3"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 font-mono text-xs">
                            <span className="px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/60 font-bold">
                              {du.variable}
                            </span>
                            <span className="text-neutral-400">Storage: {du.storage.toUpperCase()}</span>
                          </div>
                          <span className="text-xs font-mono text-neutral-500">
                            Scope: {du.scope}
                          </span>
                        </div>

                        {/* Definition Site */}
                        <div className="p-2.5 rounded-lg bg-neutral-950 border border-neutral-900 font-mono text-xs space-y-1">
                          <div className="text-[11px] text-blue-400 font-semibold uppercase">
                            [DEF] Definition Site @ {du.defAddress}
                          </div>
                          <div className="text-neutral-300">{du.defInstruction}</div>
                        </div>

                        {/* Use Sites */}
                        <div className="space-y-1.5">
                          <div className="text-[11px] font-mono text-amber-400 font-semibold uppercase">
                            [USE] Consumption Sites ({du.useAddresses.length})
                          </div>
                          {du.useAddresses.map((addr, uIdx) => (
                            <div
                              key={uIdx}
                              className="p-2 rounded bg-neutral-950/70 border border-neutral-900 font-mono text-xs flex items-center justify-between"
                            >
                              <span className="text-neutral-300">{du.useInstructions[uIdx]}</span>
                              <span className="text-neutral-500 text-[11px]">{addr}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-neutral-500 p-8 text-center">
                    No definition-use chains registered for this path.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tab 3: AI Root Cause Analysis */}
          {activeTab === 'ai' && (
            <div className="flex-1 overflow-auto p-6 bg-neutral-950">
              <div className="max-w-4xl mx-auto space-y-4">
                <div className="flex items-center justify-between border-b border-neutral-900 pb-3">
                  <div>
                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                      <Sparkles className="w-4 h-4 text-indigo-400" />
                      <span>AI Data Flow & Taint Vulnerability Assessment</span>
                    </h3>
                    <p className="text-xs text-neutral-400">
                      Automated root cause explanation, exploitability evaluation, and hardened C remediation.
                    </p>
                  </div>
                  <button
                    onClick={handleRunAiAnalysis}
                    disabled={isAiLoading}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 transition-colors"
                  >
                    {isAiLoading ? 'Synthesizing...' : 'Regenerate Analysis'}
                  </button>
                </div>

                {isAiLoading ? (
                  <div className="p-12 text-center space-y-3">
                    <div className="w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto" />
                    <p className="text-xs text-neutral-400 font-mono">
                      Querying Gemini 3.8 Flash for static taint root cause diagnosis...
                    </p>
                  </div>
                ) : aiAnalysis ? (
                  <div className="p-6 rounded-xl bg-neutral-900/60 border border-neutral-800 font-sans text-xs text-neutral-300 leading-relaxed whitespace-pre-wrap">
                    {aiAnalysis}
                  </div>
                ) : (
                  <div className="p-12 text-center space-y-3 bg-neutral-900/30 rounded-xl border border-neutral-900">
                    <Sparkles className="w-8 h-8 text-indigo-400/60 mx-auto" />
                    <p className="text-xs text-neutral-400">
                      Click the "AI Vulnerability Diagnosis" button above to run Gemini analysis on this taint path.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Right Side: Selected Node Inspector & Sanitization Health Check */}
        <div className="w-full lg:w-80 border-t lg:border-t-0 bg-neutral-950/80 p-5 flex flex-col space-y-5 overflow-y-auto">
          <div>
            <h3 className="text-xs font-bold text-neutral-400 uppercase tracking-wider mb-3">
              Node Inspector
            </h3>

            {selectedNode ? (
              <div className="p-4 rounded-xl bg-neutral-900/80 border border-neutral-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-800 text-neutral-300 border border-neutral-700 uppercase font-bold">
                    {selectedNode.type}
                  </span>
                  <span className="font-mono text-xs text-indigo-400">
                    {selectedNode.instructionAddress}
                  </span>
                </div>

                <div className="font-mono text-xs font-semibold text-white">
                  {selectedNode.label}
                </div>

                <p className="text-xs text-neutral-400 leading-relaxed">
                  {selectedNode.description}
                </p>

                {selectedNode.codeSnippet && (
                  <div className="relative group">
                    <div className="p-2.5 rounded bg-neutral-950 border border-neutral-800 font-mono text-[11px] text-neutral-300 overflow-x-auto">
                      {selectedNode.codeSnippet}
                    </div>
                    <button
                      onClick={() => handleCopyCode(selectedNode.codeSnippet!)}
                      className="absolute top-1.5 right-1.5 p-1 rounded bg-neutral-800 text-neutral-400 hover:text-white"
                      title="Copy code"
                    >
                      {copiedCode ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                )}

                <div className="pt-2 border-t border-neutral-800 space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-neutral-500">Tainted:</span>
                    <span className={selectedNode.isTainted ? 'text-red-400 font-semibold' : 'text-emerald-400 font-semibold'}>
                      {selectedNode.isTainted ? 'YES' : 'NO'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-neutral-500">Taint Level:</span>
                    <span className="font-mono text-neutral-300 uppercase">
                      {selectedNode.taintLevel}
                    </span>
                  </div>
                  {selectedNode.variableName && (
                    <div className="flex items-center justify-between">
                      <span className="text-neutral-500">Bound Variable:</span>
                      <span className="font-mono text-neutral-200">
                        {selectedNode.variableName}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-xs text-neutral-500">Select a node from the graph to inspect.</div>
            )}
          </div>

          {/* Sanitizer Health Assessment */}
          {activePath && (
            <div className="p-4 rounded-xl bg-neutral-900/60 border border-neutral-800 space-y-3">
              <h4 className="text-xs font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span>Sanitization Health Check</span>
              </h4>

              <div className="space-y-2 text-xs">
                <div className="flex items-start gap-2">
                  {activePath.sanitization === 'sanitized' ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <div className="font-medium text-neutral-200">Upper Boundary Verification</div>
                    <div className="text-[11px] text-neutral-400">
                      {activePath.sanitization === 'sanitized'
                        ? 'Input length strictly bounded prior to copy.'
                        : 'Missing bounds verification before critical sink.'}
                    </div>
                  </div>
                </div>

                <div className="flex items-start gap-2">
                  {activePath.sanitization === 'sanitized' ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <div className="font-medium text-neutral-200">Format String & Injection Guard</div>
                    <div className="text-[11px] text-neutral-400">
                      {activePath.sink.type === 'format_string' || activePath.sink.type === 'system_exec'
                        ? 'Direct unformatted string invocation detected.'
                        : 'No direct shell or format specifier risk.'}
                    </div>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-neutral-800">
                <div className="text-[11px] text-neutral-400 font-semibold mb-1">
                  Remediation Recommendation:
                </div>
                <p className="text-[11px] text-neutral-300 leading-relaxed font-sans">
                  {activePath.remediationAdvice}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
