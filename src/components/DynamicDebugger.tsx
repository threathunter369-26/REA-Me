import React, { useState } from 'react';
import {
  Play,
  Pause,
  RotateCcw,
  StepForward,
  CornerDownRight,
  ShieldAlert,
  Cpu,
  Layers,
  Circle,
  Eye,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import {
  Artifact,
  AnalysisResult,
  FunctionInfo,
  AsmInstruction,
  CpuRegisters,
  Breakpoint,
  StackFrameEntry,
} from '../types/reverseEngineering';
import { dynamicDebuggerService } from '../services/dynamicDebuggerService';

interface DynamicDebuggerProps {
  artifact: Artifact;
  analysis: AnalysisResult;
}

export const DynamicDebugger: React.FC<DynamicDebuggerProps> = ({
  artifact,
  analysis,
}) => {
  const targetFunction: FunctionInfo = analysis.functions[0];
  const instructions: AsmInstruction[] = targetFunction?.assemblyInstructions?.length
    ? targetFunction.assemblyInstructions
    : [
        { address: '0x00001000', bytes: '55', mnemonic: 'push', operands: 'rbp', comment: 'Initialize stack frame' },
        { address: '0x00001001', bytes: '48 89 E5', mnemonic: 'mov', operands: 'rbp, rsp' },
        { address: '0x00001004', bytes: '48 83 EC 30', mnemonic: 'sub', operands: 'rsp, 0x30' },
        { address: '0x00001008', bytes: '31 C9', mnemonic: 'xor', operands: 'ecx, ecx' },
        { address: '0x0000100A', bytes: '85 C0', mnemonic: 'test', operands: 'eax, eax' },
        { address: '0x0000100C', bytes: 'E8 40 01 00 00', mnemonic: 'call', operands: '0x00001150', isJumpOrCall: true },
      ];

  const [currentInsIndex, setCurrentInsIndex] = useState<number>(0);
  const [registers, setRegisters] = useState<CpuRegisters>(() =>
    dynamicDebuggerService.getInitialRegisters(targetFunction)
  );
  const [breakpoints, setBreakpoints] = useState<Breakpoint[]>([
    {
      id: 'bp-01',
      address: instructions[0]?.address || '0x00001000',
      functionName: targetFunction?.name || 'entry',
      enabled: true,
      hitCount: 1,
    },
  ]);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [stackEntries, setStackEntries] = useState<StackFrameEntry[]>(() =>
    dynamicDebuggerService.getStackEntries(registers.rsp, registers.rbp, targetFunction)
  );

  const currentInstruction = instructions[currentInsIndex] || instructions[0];

  const handleStepInto = () => {
    const result = dynamicDebuggerService.stepInstruction(
      instructions,
      currentInsIndex,
      registers
    );
    setCurrentInsIndex(result.nextIndex);
    setRegisters(result.updatedRegisters);
    setStackEntries(
      dynamicDebuggerService.getStackEntries(
        result.updatedRegisters.rsp,
        result.updatedRegisters.rbp,
        targetFunction
      )
    );
  };

  const handleRunContinue = () => {
    setIsRunning(true);
    let step = 0;
    const interval = setInterval(() => {
      step++;
      handleStepInto();
      if (step >= 5) {
        clearInterval(interval);
        setIsRunning(false);
      }
    }, 300);
  };

  const handleReset = () => {
    setCurrentInsIndex(0);
    const initialRegs = dynamicDebuggerService.getInitialRegisters(targetFunction);
    setRegisters(initialRegs);
    setStackEntries(
      dynamicDebuggerService.getStackEntries(initialRegs.rsp, initialRegs.rbp, targetFunction)
    );
    setIsRunning(false);
  };

  const toggleBreakpoint = (address: string) => {
    setBreakpoints(prev => {
      const exists = prev.find(b => b.address === address);
      if (exists) {
        return prev.filter(b => b.address !== address);
      } else {
        return [
          ...prev,
          {
            id: `bp-${Date.now()}`,
            address,
            enabled: true,
            hitCount: 0,
          },
        ];
      }
    });
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-neutral-950 text-neutral-200 overflow-hidden font-mono select-none">
      {/* Debugger Control Toolbar */}
      <div className="px-6 py-3 border-b border-neutral-900 bg-neutral-950/90 flex flex-wrap items-center justify-between gap-4 font-sans">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-indigo-950 border border-indigo-800/60 text-indigo-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <div className="text-sm font-semibold text-white flex items-center gap-2">
              <span>Dynamic Emulation Debugger</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/40">
                SANDBOX ISOLATED
              </span>
            </div>
            <p className="text-xs text-neutral-400 font-sans">
              Instruction-level CPU stepping and register/stack inspection in non-executing virtual sandbox.
            </p>
          </div>
        </div>

        {/* Debugger Action Buttons */}
        <div className="flex items-center gap-1.5 font-mono text-xs">
          <button
            onClick={handleRunContinue}
            disabled={isRunning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition-colors disabled:opacity-40"
            title="Continue Execution (F9)"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Continue</span>
          </button>

          <button
            onClick={handleStepInto}
            disabled={isRunning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold transition-colors disabled:opacity-40"
            title="Step Instruction (F11)"
          >
            <CornerDownRight className="w-3.5 h-3.5" />
            <span>Step Into</span>
          </button>

          <button
            onClick={handleStepInto}
            disabled={isRunning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-neutral-800 hover:bg-neutral-700 text-neutral-200 font-semibold transition-colors disabled:opacity-40"
            title="Step Over (F10)"
          >
            <StepForward className="w-3.5 h-3.5" />
            <span>Step Over</span>
          </button>

          <button
            onClick={handleReset}
            className="p-1.5 rounded-lg border border-neutral-800 bg-neutral-900 hover:bg-neutral-800 text-neutral-400 hover:text-white transition-colors"
            title="Restart Debug Session (Ctrl+Shift+F5)"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Debugger Grid */}
      <div className="flex-1 grid grid-cols-12 gap-0 overflow-hidden divide-x divide-neutral-900">
        {/* Left Column: Disassembly Execution Trace (7 cols) */}
        <div className="col-span-12 lg:col-span-7 flex flex-col h-full bg-neutral-950 overflow-hidden">
          <div className="px-4 py-2 border-b border-neutral-900 bg-neutral-900/40 flex items-center justify-between text-xs font-sans text-neutral-400">
            <span className="font-semibold text-neutral-200">
              Disassembly Trace: {targetFunction?.name || 'entrypoint'}
            </span>
            <span className="font-mono text-cyan-400">RIP: {currentInstruction?.address}</span>
          </div>

          <div className="flex-1 overflow-auto p-4 space-y-0.5 text-xs">
            {instructions.map((ins, idx) => {
              const isCurrentRip = idx === currentInsIndex;
              const hasBp = breakpoints.some(b => b.address === ins.address);

              return (
                <div
                  key={idx}
                  className={`flex items-center py-1 px-2 rounded cursor-pointer transition-colors ${
                    isCurrentRip
                      ? 'bg-indigo-950/80 border-l-2 border-indigo-500 text-white font-bold'
                      : 'hover:bg-neutral-900/60 text-neutral-300'
                  }`}
                >
                  {/* Breakpoint toggle circle */}
                  <button
                    onClick={() => toggleBreakpoint(ins.address)}
                    className="w-5 flex items-center justify-center shrink-0"
                    title="Toggle Breakpoint"
                  >
                    {hasBp ? (
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
                    ) : (
                      <span className="w-2.5 h-2.5 rounded-full bg-transparent group-hover:bg-neutral-800" />
                    )}
                  </button>

                  {/* Current RIP Cursor Icon */}
                  <span className="w-5 text-indigo-400 shrink-0 text-center font-bold">
                    {isCurrentRip ? '▶' : ''}
                  </span>

                  {/* Address */}
                  <span className="w-24 text-cyan-400/90 shrink-0">{ins.address}</span>

                  {/* Machine Bytes */}
                  <span className="w-28 text-neutral-500 shrink-0">{ins.bytes}</span>

                  {/* Mnemonic */}
                  <span className="w-16 text-amber-400 font-bold shrink-0">{ins.mnemonic}</span>

                  {/* Operands */}
                  <span className="flex-1 text-neutral-200 truncate">{ins.operands}</span>

                  {/* Comment */}
                  {ins.comment && (
                    <span className="text-neutral-500 italic text-[11px] shrink-0 font-sans">
                      // {ins.comment}
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Active Function Call Hierarchy */}
          <div className="p-3 border-t border-neutral-900 bg-neutral-900/30 text-[11px] font-sans flex items-center justify-between text-neutral-400">
            <div>
              Active Frame: <span className="font-mono text-indigo-300">{targetFunction?.name}</span>{' '}
              (Complexity: {targetFunction?.cyclomaticComplexity || 1})
            </div>
            <div className="font-mono text-neutral-500">
              Breakpoints: {breakpoints.length} active
            </div>
          </div>
        </div>

        {/* Right Column: Registers & Call Stack (5 cols) */}
        <div className="col-span-12 lg:col-span-5 flex flex-col h-full bg-neutral-950 overflow-hidden divide-y divide-neutral-900">
          {/* Registers Box */}
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="px-4 py-2 bg-neutral-900/40 border-b border-neutral-900 flex items-center justify-between text-xs font-sans text-neutral-400">
              <span className="font-semibold text-neutral-200">CPU 64-Bit Registers</span>
              <span className="text-[10px] text-neutral-500">AMD64 / x86_64</span>
            </div>

            <div className="flex-1 overflow-auto p-4 space-y-1 text-xs">
              <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                {[
                  { name: 'RAX', val: registers.rax, role: 'Accumulator / Return' },
                  { name: 'RBX', val: registers.rbx, role: 'Base register' },
                  { name: 'RCX', val: registers.rcx, role: 'Counter / Arg 4' },
                  { name: 'RDX', val: registers.rdx, role: 'Data / Arg 3' },
                  { name: 'RSI', val: registers.rsi, role: 'Source Index / Arg 2' },
                  { name: 'RDI', val: registers.rdi, role: 'Destination / Arg 1' },
                  { name: 'RBP', val: registers.rbp, role: 'Stack Frame Base' },
                  { name: 'RSP', val: registers.rsp, role: 'Stack Pointer' },
                  { name: 'R8 ', val: registers.r8, role: 'Arg 5' },
                  { name: 'R9 ', val: registers.r9, role: 'Arg 6' },
                  { name: 'R10', val: registers.r10, role: 'Caller saved' },
                  { name: 'RIP', val: registers.rip, role: 'Instruction Pointer' },
                ].map(reg => (
                  <div
                    key={reg.name}
                    className="flex items-center justify-between p-1 rounded hover:bg-neutral-900/60 transition-colors"
                  >
                    <span className="font-bold text-indigo-400">{reg.name}</span>
                    <span className="text-neutral-200 select-all font-mono text-[11px] truncate">
                      {reg.val}
                    </span>
                  </div>
                ))}
              </div>

              {/* Status Flags (EFLAGS / RFLAGS) */}
              <div className="mt-3 pt-2 border-t border-neutral-900 flex items-center justify-between text-[11px]">
                <span className="text-neutral-500 font-sans">Flags:</span>
                <div className="flex items-center gap-2">
                  {Object.entries(registers.flags).map(([k, v]) => (
                    <span
                      key={k}
                      className={`px-1.5 py-0.5 rounded uppercase font-bold text-[10px] ${
                        v ? 'bg-indigo-600 text-white' : 'bg-neutral-900 text-neutral-600'
                      }`}
                    >
                      {k}: {v ? '1' : '0'}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Call Stack & Stack Frame */}
          <div className="h-64 flex flex-col overflow-hidden bg-neutral-950">
            <div className="px-4 py-2 bg-neutral-900/40 border-b border-neutral-900 flex items-center justify-between text-xs font-sans text-neutral-400">
              <span className="font-semibold text-neutral-200">Call Stack & Memory Frame</span>
              <span className="text-[10px] font-mono text-cyan-400">RSP: {registers.rsp}</span>
            </div>

            <div className="flex-1 overflow-auto p-3 space-y-1 text-xs">
              {stackEntries.map((stk, i) => (
                <div
                  key={i}
                  className="p-2 rounded border border-neutral-850 bg-neutral-900/40 flex items-start justify-between text-[11px]"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-400 font-bold">{stk.offsetFromRsp}</span>
                      <span className="text-neutral-500">({stk.address})</span>
                    </div>
                    <div className="text-neutral-200 select-all font-mono">{stk.valueHex}</div>
                  </div>
                  <div className="text-right text-[10px] text-neutral-400 font-sans max-w-[140px] truncate">
                    {stk.resolvedSymbol || stk.description}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
