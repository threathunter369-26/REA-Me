import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Artifact,
  AnalysisResult,
  VexArchitecture,
  VexIRSB,
  VexStatement,
  VexTaintStep,
} from '../types/reverseEngineering';
import {
  vexIrService,
  GUEST_REGISTER_MAP,
  OFFSET_TO_REGISTER_MAP,
  VexOptimizationResult,
} from '../services/vexIrService';
import {
  Binary as BinaryIcon,
  Cpu,
  Layers,
  Play,
  Pause,
  RotateCcw,
  SkipForward,
  SkipBack,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Sparkles,
  Copy,
  Check,
  Code,
  ArrowRight,
  Split,
  Settings,
  Filter,
  Eye,
  RefreshCw,
  Terminal,
  Zap,
} from 'lucide-react';

interface VexIrTaintViewProps {
  artifact: Artifact;
  analysis?: AnalysisResult;
  onNavigateToDataFlow?: () => void;
}

export const VexIrTaintView: React.FC<VexIrTaintViewProps> = ({
  artifact,
  analysis,
  onNavigateToDataFlow,
}) => {
  // Available blocks
  const presetBlocks = useMemo(() => vexIrService.getPresetIrsbBlocks(), []);
  const [selectedBlockId, setSelectedBlockId] = useState<string>(presetBlocks[0]?.id || '');
  const [activeTab, setActiveTab] = useState<'taint' | 'converter' | 'optimizer' | 'ai'>('taint');

  // Architecture selection
  const [architecture, setArchitecture] = useState<VexArchitecture>('amd64');

  // Custom Assembly Lifter State
  const [customAsm, setCustomAsm] = useState<string>(
    `push rbp\nmov rbp, rsp\nsub rsp, 0x40\nmov [rbp-0x38], rdi\nmov rax, [rbp-0x38]\nmov edx, [rax+4]\nmov rsi, [rax+8]\nlea rdi, [rbp-0x30]\ncall memcpy\nmov eax, 0\nleave\nret`
  );
  const [isCustomMode, setIsCustomMode] = useState<boolean>(false);
  const [customIrsb, setCustomIrsb] = useState<VexIRSB | null>(null);

  // Active IRSB
  const activeIrsb = useMemo(() => {
    if (isCustomMode && customIrsb) return customIrsb;
    const found = presetBlocks.find((b) => b.id === selectedBlockId);
    return found || presetBlocks[0];
  }, [selectedBlockId, presetBlocks, isCustomMode, customIrsb]);

  // Taint analysis state
  const [initialRegisters, setInitialRegisters] = useState<string[]>(['rsi', 'rdi']);
  const [initialTemps, setInitialTemps] = useState<string[]>(['t5']);
  const [taintSteps, setTaintSteps] = useState<VexTaintStep[]>([]);
  const [currentStepIdx, setCurrentStepIdx] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playSpeed, setPlaySpeed] = useState<number>(750); // ms
  const [selectedStmtIndex, setSelectedStmtIndex] = useState<number | null>(null);

  // Optimization state
  const [optimizationResult, setOptimizationResult] = useState<VexOptimizationResult | null>(null);

  // AI Verification state
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  // Filter & Search
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [showOnlyTainted, setShowOnlyTainted] = useState<boolean>(false);

  // Initialize/Recalculate Taint steps when active IRSB or seeds change
  useEffect(() => {
    if (!activeIrsb) return;
    const steps = vexIrService.runTaintAnalysis(activeIrsb, initialRegisters, initialTemps);
    setTaintSteps(steps);
    setCurrentStepIdx(0);
    setSelectedStmtIndex(0);
    const opt = vexIrService.optimizeVexIRSB(activeIrsb);
    setOptimizationResult(opt);
    setArchitecture(activeIrsb.architecture);
  }, [activeIrsb, initialRegisters, initialTemps]);

  // Stepper auto-play timer
  const playTimerRef = useRef<NodeJS.Timeout | null>(null);
  useEffect(() => {
    if (isPlaying) {
      playTimerRef.current = setInterval(() => {
        setCurrentStepIdx((prev) => {
          if (prev >= taintSteps.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          const next = prev + 1;
          setSelectedStmtIndex(next);
          return next;
        });
      }, playSpeed);
    } else if (playTimerRef.current) {
      clearInterval(playTimerRef.current);
    }
    return () => {
      if (playTimerRef.current) clearInterval(playTimerRef.current);
    };
  }, [isPlaying, taintSteps.length, playSpeed]);

  const currentStep = taintSteps[currentStepIdx] || taintSteps[0];

  // Lift custom assembly handler
  const handleLiftCustomAsm = () => {
    try {
      const lifted = vexIrService.liftAssemblyToVex(customAsm, architecture, '0x00401000');
      setCustomIrsb(lifted);
      setIsCustomMode(true);
      setActiveTab('converter');
    } catch (err) {
      console.error('Lifting error:', err);
    }
  };

  // AI Taint Verification request
  const handleRunAiTaintVerify = async () => {
    setIsAiLoading(true);
    setAiReport(null);
    try {
      const alert = currentStep?.alert || activeIrsb.vulnerabilitiesDetected?.[0];
      const res = await fetch('/api/ai/vex-taint-verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          irsbName: activeIrsb.name,
          architecture: activeIrsb.architecture,
          taintedRegisters: Object.keys(currentStep?.taintedRegisters || {}),
          taintedTemps: Object.keys(currentStep?.taintedTemps || {}),
          alert,
          statementsSnippet: activeIrsb.statements
            .slice(0, 15)
            .map((s) => `${s.lineNum} | ${s.tag} ${s.temp ? `${s.temp} = ` : ''}${s.expression || s.sourceExpr || s.rawAsm || ''}`)
            .join('\n'),
        }),
      });

      const data = await res.json();
      setAiReport(data.verification || 'Verification completed.');
      setActiveTab('ai');
    } catch (err: any) {
      setAiReport(`Verification error: ${err.message}`);
    } finally {
      setIsAiLoading(false);
    }
  };

  // Copy IRSB text
  const handleCopyIrsb = () => {
    if (!activeIrsb) return;
    const formatted = vexIrService.formatIrsbToValgrindText(activeIrsb);
    navigator.clipboard.writeText(formatted);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  // Toggle seed register
  const toggleSeedRegister = (reg: string) => {
    setInitialRegisters((prev) =>
      prev.includes(reg) ? prev.filter((r) => r !== reg) : [...prev, reg]
    );
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-neutral-950 text-neutral-100 overflow-hidden font-sans">
      {/* Top Header */}
      <div className="border-b border-neutral-800 bg-neutral-900/80 px-6 py-4 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-600/20 border border-indigo-500/30 text-indigo-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold text-white tracking-wide">
                VEX-IR Converter & Dynamic Taint Engine
              </h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-indigo-900/60 text-indigo-300 border border-indigo-700/50">
                Valgrind / Angr Spec
              </span>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-rose-900/40 text-rose-300 border border-rose-700/50">
                SSA Taint Lattice
              </span>
            </div>
            <p className="text-xs text-neutral-400 mt-0.5">
              Machine code intermediate representation lifting, register-offset tracking & mathematical taint propagation
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {onNavigateToDataFlow && (
            <button
              onClick={onNavigateToDataFlow}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-300 border border-neutral-700 transition-colors"
            >
              <Layers className="w-3.5 h-3.5 text-rose-400" />
              <span>Full Data Flow Graph</span>
            </button>
          )}

          <button
            onClick={handleCopyIrsb}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-300 border border-neutral-700 transition-colors"
            title="Copy Valgrind IRSB text"
          >
            {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedCode ? 'Copied' : 'Export VEX'}</span>
          </button>

          <button
            onClick={handleRunAiTaintVerify}
            disabled={isAiLoading}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white shadow-lg shadow-indigo-500/20 transition-all disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>{isAiLoading ? 'Verifying...' : 'AI Exploit Verifier'}</span>
          </button>
        </div>
      </div>

      {/* Preset Selector & Sub-Navigation */}
      <div className="border-b border-neutral-800 bg-neutral-900/40 px-6 py-2.5 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-neutral-400">Target IRSB:</span>
          <select
            value={isCustomMode ? 'custom' : selectedBlockId}
            onChange={(e) => {
              if (e.target.value === 'custom') {
                setIsCustomMode(true);
              } else {
                setIsCustomMode(false);
                setSelectedBlockId(e.target.value);
              }
            }}
            className="bg-neutral-950 border border-neutral-700 rounded-lg px-3 py-1 text-xs text-neutral-200 focus:outline-none focus:border-indigo-500 font-mono"
          >
            {presetBlocks.map((b) => (
              <option key={b.id} value={b.id}>
                {b.name} [{b.architecture.toUpperCase()}] ({b.entryAddress})
              </option>
            ))}
            <option value="custom">⚡ [Custom User Assembly Testbench]</option>
          </select>

          <div className="h-4 w-[1px] bg-neutral-800" />

          <span className="text-xs font-medium text-neutral-400">Architecture:</span>
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-neutral-800 text-indigo-300 border border-neutral-700">
            {activeIrsb.architecture.toUpperCase()}
          </span>

          <span className="text-xs text-neutral-500">
            {activeIrsb.statements.length} VEX stmts &bull; {activeIrsb.temps.length} SSA temps &bull; {activeIrsb.sizeBytes} bytes
          </span>
        </div>

        {/* View Tabs */}
        <div className="flex items-center gap-1 bg-neutral-950 p-1 rounded-lg border border-neutral-800">
          <button
            onClick={() => setActiveTab('taint')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'taint'
                ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Taint Stepper</span>
          </button>

          <button
            onClick={() => setActiveTab('converter')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'converter'
                ? 'bg-indigo-950/80 text-indigo-300 border border-indigo-800/60 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            <Split className="w-3.5 h-3.5 text-indigo-400" />
            <span>Assembly Lifter</span>
          </button>

          <button
            onClick={() => setActiveTab('optimizer')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'optimizer'
                ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            <Zap className="w-3.5 h-3.5 text-emerald-400" />
            <span>SSA Optimizer</span>
          </button>

          <button
            onClick={() => setActiveTab('ai')}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'ai'
                ? 'bg-purple-950/80 text-purple-300 border border-purple-800/60 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
            <span>AI Verification</span>
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-hidden flex flex-col">
        {/* TAB 1: TAINT PROPAGATION STEPPER */}
        {activeTab === 'taint' && (
          <div className="flex-1 flex flex-col overflow-hidden">
            {/* Stepper Controls Bar */}
            <div className="border-b border-neutral-800/80 bg-neutral-900/60 px-6 py-2.5 flex flex-wrap items-center justify-between gap-4 shrink-0">
              {/* Playback buttons */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setCurrentStepIdx(0);
                    setSelectedStmtIndex(0);
                    setIsPlaying(false);
                  }}
                  className="p-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-300 transition-colors"
                  title="Reset to Entry"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                </button>

                <button
                  onClick={() => {
                    setCurrentStepIdx((prev) => Math.max(0, prev - 1));
                    setSelectedStmtIndex((prev) => Math.max(0, (prev || 0) - 1));
                  }}
                  disabled={currentStepIdx === 0}
                  className="p-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-300 disabled:opacity-40 transition-colors"
                  title="Step Back"
                >
                  <SkipBack className="w-3.5 h-3.5" />
                </button>

                <button
                  onClick={() => setIsPlaying(!isPlaying)}
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold transition-colors ${
                    isPlaying
                      ? 'bg-amber-600 hover:bg-amber-500 text-white'
                      : 'bg-rose-600 hover:bg-rose-500 text-white'
                  }`}
                >
                  {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{isPlaying ? 'Pause' : 'Play Taint Flow'}</span>
                </button>

                <button
                  onClick={() => {
                    setCurrentStepIdx((prev) => Math.min(taintSteps.length - 1, prev + 1));
                    setSelectedStmtIndex((prev) => Math.min(taintSteps.length - 1, (prev || 0) + 1));
                  }}
                  disabled={currentStepIdx >= taintSteps.length - 1}
                  className="p-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-300 disabled:opacity-40 transition-colors"
                  title="Step Forward"
                >
                  <SkipForward className="w-3.5 h-3.5" />
                </button>

                <div className="h-4 w-[1px] bg-neutral-800 mx-1" />

                <span className="text-xs text-neutral-400 font-mono">
                  Statement <span className="text-white font-bold">{currentStepIdx + 1}</span> of{' '}
                  <span className="text-neutral-300">{taintSteps.length}</span>
                </span>

                <select
                  value={playSpeed}
                  onChange={(e) => setPlaySpeed(Number(e.target.value))}
                  className="bg-neutral-950 border border-neutral-800 text-[11px] text-neutral-300 rounded px-2 py-0.5 ml-2"
                >
                  <option value={1200}>0.8x Speed</option>
                  <option value={750}>1.0x Speed</option>
                  <option value={350}>2.0x Fast</option>
                </select>
              </div>

              {/* Taint Seeds Config */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-neutral-400">Untrusted Seeds:</span>
                {(['rsi', 'rdi', 'rdx', 'rax', 'x0', 'x1'] as const).map((reg) => (
                  <button
                    key={reg}
                    onClick={() => toggleSeedRegister(reg)}
                    className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors ${
                      initialRegisters.includes(reg)
                        ? 'bg-rose-900/60 text-rose-300 border border-rose-700/60 font-bold'
                        : 'bg-neutral-950 text-neutral-500 border border-neutral-800 hover:text-neutral-300'
                    }`}
                  >
                    %{reg}
                  </button>
                ))}

                <button
                  onClick={() => setShowOnlyTainted(!showOnlyTainted)}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded text-xs border transition-colors ${
                    showOnlyTainted
                      ? 'bg-rose-950/60 border-rose-700/80 text-rose-300 font-medium'
                      : 'bg-neutral-950 border-neutral-800 text-neutral-400'
                  }`}
                >
                  <Filter className="w-3 h-3" />
                  <span>Only Tainted</span>
                </button>
              </div>
            </div>

            {/* Alert Banner if triggered at this step */}
            {currentStep?.alert && (
              <div className="bg-rose-950/70 border-b border-rose-800/80 px-6 py-2.5 flex items-center justify-between gap-4 animate-pulse">
                <div className="flex items-center gap-3">
                  <div className="p-1.5 rounded-lg bg-rose-600 text-white">
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-rose-200 uppercase tracking-wide">
                        {currentStep.alert.title}
                      </span>
                      <span className="px-1.5 py-0.2 bg-rose-900 border border-rose-700 rounded text-[10px] font-mono text-rose-300">
                        {currentStep.alert.cwe}
                      </span>
                    </div>
                    <p className="text-xs text-rose-300/90 mt-0.5">{currentStep.alert.message}</p>
                  </div>
                </div>

                <button
                  onClick={handleRunAiTaintVerify}
                  className="px-3 py-1 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition-colors shrink-0"
                >
                  Verify Exploit Primitive
                </button>
              </div>
            )}

            {/* Split Workspace: Left Statements Listing, Right State Inspector */}
            <div className="flex-1 flex overflow-hidden">
              {/* Left Panel: VEX Statements List */}
              <div className="flex-1 border-r border-neutral-800 overflow-y-auto p-4 font-mono text-xs space-y-1 bg-neutral-950">
                {/* IRSB Temps Header */}
                <div className="mb-3 p-2.5 rounded-lg bg-neutral-900/60 border border-neutral-800 text-[11px] text-neutral-400">
                  <div className="text-neutral-500 font-semibold mb-1">SSA TEMPORARY VARIABLE REGISTRATION:</div>
                  <div className="flex flex-wrap gap-2">
                    {activeIrsb.temps.map((t) => {
                      const isTainted = currentStep?.taintedTemps[t.id];
                      return (
                        <span
                          key={t.id}
                          className={`px-1.5 py-0.5 rounded text-[10px] ${
                            isTainted
                              ? 'bg-rose-900/50 text-rose-300 border border-rose-700/60 font-bold'
                              : 'bg-neutral-950 text-neutral-400 border border-neutral-800'
                          }`}
                        >
                          {t.id}:{t.type}
                        </span>
                      );
                    })}
                  </div>
                </div>

                {/* Statements List */}
                {activeIrsb.statements.map((stmt, idx) => {
                  const isCurrent = idx === currentStepIdx;
                  const isPast = idx <= currentStepIdx;
                  const stepAtIdx = taintSteps[idx];
                  const isTaintedStmt = stepAtIdx?.statement?.isTainted;
                  const hasAlert = stepAtIdx?.alert !== undefined;

                  if (showOnlyTainted && !isTaintedStmt) {
                    return null;
                  }

                  let tagColor = 'text-cyan-400';
                  if (stmt.tag === 'IMark') tagColor = 'text-sky-400';
                  else if (stmt.tag === 'WrTmp') tagColor = 'text-emerald-400';
                  else if (stmt.tag === 'Put') tagColor = 'text-indigo-400';
                  else if (stmt.tag === 'Store') tagColor = 'text-amber-400';
                  else if (stmt.tag === 'Exit') tagColor = 'text-rose-400';

                  return (
                    <div
                      key={stmt.id}
                      onClick={() => {
                        setCurrentStepIdx(idx);
                        setSelectedStmtIndex(idx);
                      }}
                      className={`px-3 py-2 rounded-lg cursor-pointer transition-all flex items-start gap-3 ${
                        isCurrent
                          ? 'bg-indigo-950/70 border border-indigo-500 shadow-md ring-1 ring-indigo-500/50'
                          : isTaintedStmt && isPast
                          ? 'bg-rose-950/20 border border-rose-800/40 hover:bg-rose-950/30'
                          : 'hover:bg-neutral-900/60 border border-transparent'
                      }`}
                    >
                      {/* Step index & Indicator */}
                      <div className="flex items-center gap-1.5 w-14 shrink-0 text-neutral-500">
                        {isCurrent ? (
                          <div className="w-2 h-2 rounded-full bg-indigo-400 animate-ping" />
                        ) : isTaintedStmt && isPast ? (
                          <div className="w-2 h-2 rounded-full bg-rose-500" />
                        ) : (
                          <div className="w-2 h-2 rounded-full bg-neutral-800" />
                        )}
                        <span>{idx.toString().padStart(2, '0')}</span>
                      </div>

                      {/* Content */}
                      <div className="flex-1 overflow-x-auto">
                        <div className="flex items-center gap-2">
                          <span className={`font-bold ${tagColor}`}>[{stmt.tag}]</span>
                          {stmt.tag === 'IMark' && (
                            <span className="text-neutral-300">
                              IMark({stmt.instructionAddress}, len={stmt.instructionLength}) &mdash;{' '}
                              <span className="text-yellow-300 font-semibold">{stmt.rawAsm}</span>
                            </span>
                          )}

                          {stmt.tag === 'WrTmp' && (
                            <span>
                              <span className="text-emerald-300 font-semibold">{stmt.temp}</span>
                              <span className="text-neutral-400"> = </span>
                              <span className="text-neutral-200">{stmt.expression}</span>
                            </span>
                          )}

                          {stmt.tag === 'Put' && (
                            <span>
                              <span className="text-indigo-300 font-semibold">
                                PUT(offset={stmt.targetOffset} /* {stmt.targetRegister} */)
                              </span>
                              <span className="text-neutral-400"> = </span>
                              <span className="text-neutral-200">{stmt.sourceExpr}</span>
                            </span>
                          )}

                          {stmt.tag === 'Store' && (
                            <span>
                              <span className="text-amber-300 font-semibold">
                                STle({stmt.storeAddrExpr})
                              </span>
                              <span className="text-neutral-400"> = </span>
                              <span className="text-neutral-200">{stmt.storeDataExpr}</span>
                            </span>
                          )}

                          {stmt.tag === 'Exit' && (
                            <span>
                              <span className="text-rose-300 font-semibold">
                                if ({stmt.guardExpr}) Exit to {stmt.exitTarget}
                              </span>
                            </span>
                          )}

                          {stmt.comment && (
                            <span className="text-neutral-500 italic text-[11px] ml-2">
                              /* {stmt.comment} */
                            </span>
                          )}
                        </div>

                        {/* Statement Taint Note */}
                        {isPast && isTaintedStmt && (
                          <div className="text-[11px] text-rose-400 mt-1 flex items-center gap-1.5 font-sans">
                            <ShieldAlert className="w-3 h-3 text-rose-400" />
                            <span>
                              {stmt.taintReason || 'Operates on untrusted tainted variable'}
                            </span>
                          </div>
                        )}
                      </div>

                      {/* Taint Badge */}
                      {isPast && (
                        <div className="shrink-0">
                          {hasAlert ? (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white uppercase animate-pulse">
                              ALERT
                            </span>
                          ) : isTaintedStmt ? (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-rose-900/60 text-rose-300 border border-rose-700/60">
                              TAINTED
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 rounded text-[10px] text-neutral-600">
                              CLEAN
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Right Panel: Live Dynamic State & Taint Lattice */}
              <div className="w-96 flex flex-col bg-neutral-900/40 overflow-y-auto p-4 space-y-4">
                {/* Active Statement Inspector */}
                <div className="p-3 rounded-xl bg-neutral-900/80 border border-neutral-800">
                  <div className="text-xs font-bold text-white flex items-center justify-between mb-2">
                    <span>Active Statement Semantics</span>
                    <span className="text-[10px] text-neutral-400 font-mono">
                      Idx {currentStepIdx}
                    </span>
                  </div>
                  <div className="text-xs font-mono text-neutral-300 bg-neutral-950 p-2 rounded border border-neutral-800">
                    <div className="text-indigo-400 font-bold mb-1">
                      {currentStep?.statement.tag}
                    </div>
                    <div>{currentStep?.statement.expression || currentStep?.statement.sourceExpr || currentStep?.statement.rawAsm}</div>
                  </div>
                </div>

                {/* Tainted Guest Registers Table */}
                <div className="p-3 rounded-xl bg-neutral-900/80 border border-neutral-800">
                  <div className="text-xs font-bold text-white flex items-center justify-between mb-2">
                    <span className="flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Guest Registers Taint State</span>
                    </span>
                    <span className="text-[10px] font-mono text-rose-400">
                      {Object.keys(currentStep?.taintedRegisters || {}).length} Tainted
                    </span>
                  </div>

                  <div className="space-y-1.5 max-h-40 overflow-y-auto">
                    {Object.entries(currentStep?.taintedRegisters || {}).length === 0 ? (
                      <div className="text-xs text-neutral-500 italic py-1">No tainted guest registers at this step</div>
                    ) : (
                      Object.entries(currentStep.taintedRegisters).map(([reg, info]) => (
                        <div
                          key={reg}
                          className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-rose-950/30 border border-rose-800/40 text-xs font-mono"
                        >
                          <span className="text-rose-300 font-bold">%{reg}</span>
                          <span className="text-[11px] text-neutral-400 truncate max-w-[150px]">
                            {info.origin}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Tainted SSA Temporaries Table */}
                <div className="p-3 rounded-xl bg-neutral-900/80 border border-neutral-800">
                  <div className="text-xs font-bold text-white flex items-center justify-between mb-2">
                    <span className="flex items-center gap-1.5">
                      <Code className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Tainted SSA Temporaries</span>
                    </span>
                    <span className="text-[10px] font-mono text-rose-400">
                      {Object.keys(currentStep?.taintedTemps || {}).length} Tainted
                    </span>
                  </div>

                  <div className="space-y-1.5 max-h-40 overflow-y-auto">
                    {Object.entries(currentStep?.taintedTemps || {}).length === 0 ? (
                      <div className="text-xs text-neutral-500 italic py-1">No tainted temporaries yet</div>
                    ) : (
                      Object.entries(currentStep.taintedTemps).map(([tmp, info]) => (
                        <div
                          key={tmp}
                          className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-neutral-950 border border-neutral-800 text-xs font-mono"
                        >
                          <span className="text-emerald-400 font-bold">{tmp}</span>
                          <span className="text-[10px] text-rose-400 bg-rose-950/50 px-1.5 py-0.5 rounded border border-rose-800/40">
                            {info.tag}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Memory Write State */}
                <div className="p-3 rounded-xl bg-neutral-900/80 border border-neutral-800">
                  <div className="text-xs font-bold text-white flex items-center justify-between mb-2">
                    <span className="flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-amber-400" />
                      <span>Tainted Memory Slots</span>
                    </span>
                    <span className="text-[10px] font-mono text-amber-400">
                      {currentStep?.taintedMemory.length || 0} Written
                    </span>
                  </div>

                  <div className="space-y-1.5">
                    {currentStep?.taintedMemory.length === 0 ? (
                      <div className="text-xs text-neutral-500 italic py-1">No memory writes performed</div>
                    ) : (
                      currentStep?.taintedMemory.map((mem, i) => (
                        <div
                          key={i}
                          className="p-2 rounded-lg bg-neutral-950 border border-amber-900/40 text-xs font-mono"
                        >
                          <div className="text-amber-300 font-semibold">{mem.addressOrOffset}</div>
                          <div className="text-[10px] text-neutral-400 mt-0.5">{mem.origin}</div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: ASSEMBLY LIFTER & DUAL-PANE VIEW */}
        {activeTab === 'converter' && (
          <div className="flex-1 flex overflow-hidden">
            {/* Left Pane: Machine Code Assembly Editor / Input */}
            <div className="w-1/2 border-r border-neutral-800 flex flex-col bg-neutral-950">
              <div className="border-b border-neutral-800 bg-neutral-900/60 px-4 py-2.5 flex items-center justify-between shrink-0">
                <span className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-yellow-400" />
                  <span>Assembly Input & Machine Instructions</span>
                </span>
                <div className="flex items-center gap-2">
                  <select
                    value={architecture}
                    onChange={(e) => setArchitecture(e.target.value as VexArchitecture)}
                    className="bg-neutral-950 border border-neutral-700 text-xs text-neutral-300 rounded px-2 py-0.5"
                  >
                    <option value="amd64">AMD64 (x86_64)</option>
                    <option value="x86">x86 (IA-32)</option>
                    <option value="arm64">AArch64 (ARM64)</option>
                    <option value="arm">ARMv7</option>
                    <option value="mips32">MIPS32</option>
                  </select>

                  <button
                    onClick={handleLiftCustomAsm}
                    className="flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors"
                  >
                    <Cpu className="w-3.5 h-3.5" />
                    <span>Lift to VEX</span>
                  </button>
                </div>
              </div>

              <div className="flex-1 p-4 overflow-y-auto">
                <textarea
                  value={customAsm}
                  onChange={(e) => setCustomAsm(e.target.value)}
                  placeholder="Enter assembly instructions here, one per line..."
                  className="w-full h-full bg-neutral-900/60 border border-neutral-800 rounded-xl p-4 font-mono text-xs text-neutral-200 focus:outline-none focus:border-indigo-500 resize-none"
                  rows={20}
                />
              </div>

              {/* Quick Presets Drawer */}
              <div className="border-t border-neutral-800 p-3 bg-neutral-900/40 flex items-center gap-2 text-xs">
                <span className="text-neutral-500 text-[11px] font-medium">Snippets:</span>
                <button
                  onClick={() => {
                    setArchitecture('amd64');
                    setCustomAsm(
                      `push rbp\nmov rbp, rsp\nsub rsp, 0x50\nmov [rbp-0x48], rdi\nmov [rbp-0x50], rsi\nmov rax, [rbp-0x50]\nmov edx, [rax+0x04]\nmov rsi, [rax+0x08]\nlea rdi, [rbp-0x40]\ncall memcpy\nmov eax, 0\nleave\nret`
                    );
                  }}
                  className="px-2 py-0.5 rounded bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-[11px]"
                >
                  x86_64 Stack Overflow
                </button>
                <button
                  onClick={() => {
                    setArchitecture('arm64');
                    setCustomAsm(
                      `ldr x0, [x1, #16]\nldr x2, [x3, #0]\neor x4, x0, x2\nstr x4, [x5, x6, lsl #3]\nadd x6, x6, #1\nret`
                    );
                  }}
                  className="px-2 py-0.5 rounded bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-[11px]"
                >
                  ARM64 Crypto Loop
                </button>
                <button
                  onClick={() => {
                    setArchitecture('mips32');
                    setCustomAsm(
                      `addiu $sp, $sp, -40\nsw $ra, 36($sp)\nlw $a0, 16($a1)\njal sendto\nnop`
                    );
                  }}
                  className="px-2 py-0.5 rounded bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-[11px]"
                >
                  MIPS32 Socket Send
                </button>
              </div>
            </div>

            {/* Right Pane: Lifted Valgrind IRSB */}
            <div className="w-1/2 flex flex-col bg-neutral-950 overflow-hidden">
              <div className="border-b border-neutral-800 bg-neutral-900/60 px-4 py-2.5 flex items-center justify-between shrink-0">
                <span className="text-xs font-bold text-white flex items-center gap-1.5">
                  <BinaryIcon className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Lifted Valgrind / Angr VEX IRSB</span>
                </span>
                <span className="text-[11px] font-mono text-neutral-400">
                  {activeIrsb.statements.length} IR Statements
                </span>
              </div>

              <div className="flex-1 p-4 overflow-y-auto font-mono text-xs text-neutral-300 bg-neutral-950">
                <pre className="whitespace-pre-wrap leading-relaxed">
                  {vexIrService.formatIrsbToValgrindText(activeIrsb)}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: SSA & MICROCODE OPTIMIZER */}
        {activeTab === 'optimizer' && optimizationResult && (
          <div className="flex-1 flex flex-col overflow-hidden p-6 space-y-6">
            {/* Optimization Stats Banner */}
            <div className="grid grid-cols-4 gap-4 shrink-0">
              <div className="p-4 rounded-xl bg-neutral-900/80 border border-neutral-800">
                <div className="text-xs text-neutral-400">Original Statements</div>
                <div className="text-xl font-bold text-white mt-1">
                  {optimizationResult.originalStatementCount}
                </div>
              </div>

              <div className="p-4 rounded-xl bg-neutral-900/80 border border-neutral-800">
                <div className="text-xs text-neutral-400">Optimized Statements</div>
                <div className="text-xl font-bold text-emerald-400 mt-1">
                  {optimizationResult.optimizedStatementCount}
                </div>
              </div>

              <div className="p-4 rounded-xl bg-neutral-900/80 border border-neutral-800">
                <div className="text-xs text-neutral-400">Dead Temps Eliminated</div>
                <div className="text-xl font-bold text-rose-400 mt-1">
                  {optimizationResult.deadTempsEliminated.length}
                </div>
              </div>

              <div className="p-4 rounded-xl bg-neutral-900/80 border border-neutral-800">
                <div className="text-xs text-neutral-400">Constants Folded</div>
                <div className="text-xl font-bold text-indigo-400 mt-1">
                  {optimizationResult.constantsFoldedCount}
                </div>
              </div>
            </div>

            {/* Split Comparison View */}
            <div className="flex-1 flex gap-4 overflow-hidden">
              <div className="w-1/2 flex flex-col rounded-xl border border-neutral-800 bg-neutral-900/40 overflow-hidden">
                <div className="px-4 py-2.5 bg-neutral-900/80 border-b border-neutral-800 text-xs font-bold text-white">
                  Raw Unoptimized VEX-IR
                </div>
                <div className="flex-1 p-4 overflow-y-auto font-mono text-xs text-neutral-300 bg-neutral-950">
                  <pre className="whitespace-pre-wrap">
                    {vexIrService.formatIrsbToValgrindText(activeIrsb)}
                  </pre>
                </div>
              </div>

              <div className="w-1/2 flex flex-col rounded-xl border border-emerald-900/50 bg-neutral-900/40 overflow-hidden">
                <div className="px-4 py-2.5 bg-emerald-950/40 border-b border-emerald-900/50 text-xs font-bold text-emerald-300 flex items-center justify-between">
                  <span>Optimized Single Static Assignment (SSA) IRSB</span>
                  <span className="text-[10px] text-emerald-400 font-mono">DCE & Constant Folding Enabled</span>
                </div>
                <div className="flex-1 p-4 overflow-y-auto font-mono text-xs text-emerald-200/90 bg-neutral-950">
                  <pre className="whitespace-pre-wrap">
                    {vexIrService.formatIrsbToValgrindText(optimizationResult.optimizedIrsb)}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: AI VERIFICATION & EXPLOIT REPORT */}
        {activeTab === 'ai' && (
          <div className="flex-1 flex flex-col p-6 overflow-y-auto space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-purple-400" />
                  <span>Gemini 3.8 Flash Formal VEX Taint & Exploit Verification</span>
                </h3>
                <p className="text-xs text-neutral-400 mt-0.5">
                  Symbolic constraint satisfiability, exploit primitive weaponization & binary mitigation analysis
                </p>
              </div>

              <button
                onClick={handleRunAiTaintVerify}
                disabled={isAiLoading}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isAiLoading ? 'animate-spin' : ''}`} />
                <span>Re-verify Trace</span>
              </button>
            </div>

            {isAiLoading ? (
              <div className="flex-1 flex flex-col items-center justify-center py-20 text-center space-y-3">
                <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
                <div className="text-sm font-medium text-neutral-300">
                  Analyzing VEX-IR SSA Taint Equations with Gemini 3.8 Flash...
                </div>
                <div className="text-xs text-neutral-500 max-w-md">
                  Formulating symbolic constraints, checking for write-what-where conditions and validating register control
                </div>
              </div>
            ) : aiReport ? (
              <div className="p-6 rounded-xl bg-neutral-900/60 border border-purple-900/40 text-neutral-200 leading-relaxed font-sans text-xs whitespace-pre-wrap">
                {aiReport}
              </div>
            ) : (
              <div className="p-12 text-center rounded-xl border border-neutral-800 bg-neutral-900/20 text-neutral-500 text-xs">
                Click &quot;AI Exploit Verifier&quot; to synthesize formal symbolic analysis on this VEX trace.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
