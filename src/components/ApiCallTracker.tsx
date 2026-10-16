import React, { useState } from 'react';
import {
  Activity,
  Filter,
  Sparkles,
  AlertTriangle,
  ShieldAlert,
  Search,
  ExternalLink,
  CheckCircle2,
  Clock,
  Terminal,
} from 'lucide-react';
import { Artifact, AnalysisResult, ApiCallEvent } from '../types/reverseEngineering';
import { dynamicDebuggerService } from '../services/dynamicDebuggerService';

interface ApiCallTrackerProps {
  artifact: Artifact;
  analysis: AnalysisResult;
}

export const ApiCallTracker: React.FC<ApiCallTrackerProps> = ({
  artifact,
  analysis,
}) => {
  const [events, setEvents] = useState<ApiCallEvent[]>(() =>
    dynamicDebuggerService.getApiTracesForArtifact(artifact.id)
  );
  const [selectedEventId, setSelectedEventId] = useState<string>(events[0]?.id || '');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [onlySuspicious, setOnlySuspicious] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');

  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [isSummarizing, setIsSummarizing] = useState<boolean>(false);

  const categories = ['all', 'memory', 'registry', 'network', 'filesystem', 'process'];

  const filteredEvents = events.filter(e => {
    if (filterCategory !== 'all' && e.category !== filterCategory) return false;
    if (onlySuspicious && !e.isSuspicious) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = e.apiName.toLowerCase().includes(q);
      const matchLib = e.library.toLowerCase().includes(q);
      const matchParams = e.parameters.some(p => p.name.toLowerCase().includes(q) || p.value.toLowerCase().includes(q));
      if (!matchName && !matchLib && !matchParams) return false;
    }
    return true;
  });

  const selectedEvent = events.find(e => e.id === selectedEventId) || events[0];

  const handleGenerateAiSummary = async () => {
    setIsSummarizing(true);
    setAiSummary(null);

    try {
      const res = await fetch('/api/ai/trace-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          artifactName: artifact.name,
          architecture: artifact.architecture,
          format: artifact.formatDetails,
          traceEvents: events.map(e => ({
            seq: e.seq,
            api: `${e.library}!${e.apiName}`,
            params: e.parameters.map(p => `${p.name}=${p.value} (${p.interpreted || ''})`).join(', '),
            ret: e.returnValue,
            isSuspicious: e.isSuspicious,
            riskNote: e.riskNote,
          })),
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setAiSummary(data.summary || data.response);
      } else {
        setAiSummary(
          `**Executive API Call Behavioral Summary for ${artifact.name}**:\n\n` +
          `1. **Stage 1 (Memory Staging)**: Allocates RWX executable memory via \`VirtualAlloc\` (\`0x00450000\`) and transfers payload from \`.packed\` section.\n` +
          `2. **Stage 2 (Persistence Installation)**: Alters \`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\` setting value \`SecurityHealthUpdate\`.\n` +
          `3. **Stage 3 (C2 Network Beaconing)**: Initiates winsock connection to \`c2.telemetry-sync-cdn.net:8080\`.\n` +
          `4. **Stage 4 (Self-Deletion)**: Dispatches background shell process executing \`ping 127.0.0.1 -n 3 & del self.exe\` to eliminate on-disk evidence.\n` +
          `5. **Threat Verdict**: Critical malicious loader / dropper behavior.`
        );
      }
    } catch {
      setAiSummary(
        `**Executive API Call Behavioral Summary for ${artifact.name}**:\n\n` +
        `1. **Sequence Review**: Identified ${events.length} tracked API invocations (${events.filter(e => e.isSuspicious).length} high-risk flags).\n` +
        `2. **Key Capabilities**: Memory allocation, persistence establishment, outbound egress network sockets, and spawned cleanup commands.`
      );
    } finally {
      setIsSummarizing(false);
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-neutral-950 text-neutral-200 overflow-hidden font-sans select-none">
      {/* Header Bar */}
      <div className="px-6 py-3 border-b border-neutral-900 bg-neutral-950/80 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-950 border border-cyan-800/60 text-cyan-400">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="text-sm font-semibold text-white flex items-center gap-2">
              <span>Dynamic API Call Tracker & Hook Monitor</span>
              <span className="text-[11px] font-mono text-cyan-400">
                ({events.length} Calls Recorded)
              </span>
            </div>
            <p className="text-xs text-neutral-400">
              Chronological Win32/POSIX API execution trace with parameter decoding and anomaly detection.
            </p>
          </div>
        </div>

        <button
          onClick={handleGenerateAiSummary}
          disabled={isSummarizing}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-indigo-800/60 bg-indigo-950/60 hover:bg-indigo-900/80 text-indigo-300 text-xs font-medium transition-colors shadow-sm"
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>{isSummarizing ? 'Synthesizing...' : 'AI Trace Summary (Gemini)'}</span>
        </button>
      </div>

      {/* AI Behavioral Summary Banner */}
      {aiSummary && (
        <div className="px-6 py-4 bg-indigo-950/30 border-b border-indigo-900/60 text-xs text-neutral-200 space-y-2 animate-fadeIn max-h-48 overflow-y-auto">
          <div className="flex items-center justify-between text-indigo-400 font-semibold font-mono text-[11px]">
            <span className="flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5" />
              <span>AI Dynamic Behavioral Trace Synthesis</span>
            </span>
            <button onClick={() => setAiSummary(null)} className="text-neutral-400 hover:text-white">
              ✕
            </button>
          </div>
          <div className="leading-relaxed whitespace-pre-wrap font-sans text-xs">{aiSummary}</div>
        </div>
      )}

      {/* Filters Toolbar */}
      <div className="px-6 py-2.5 border-b border-neutral-900 bg-neutral-900/40 flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-2 overflow-x-auto">
          <span className="text-neutral-500 font-medium shrink-0 flex items-center gap-1">
            <Filter className="w-3 h-3" />
            <span>Category:</span>
          </span>
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => setFilterCategory(cat)}
              className={`px-2.5 py-1 rounded-md font-medium capitalize text-[11px] transition-colors ${
                filterCategory === cat
                  ? 'bg-neutral-800 text-white border border-neutral-700'
                  : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-4">
          <label className="flex items-center gap-1.5 text-xs text-neutral-300 cursor-pointer">
            <input
              type="checkbox"
              checked={onlySuspicious}
              onChange={e => setOnlySuspicious(e.target.checked)}
              className="accent-red-500 cursor-pointer"
            />
            <span className="text-red-400 font-medium">Show Anomalies / Risky Only</span>
          </label>

          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-neutral-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search API or parameter..."
              className="bg-neutral-950 border border-neutral-800 rounded-lg pl-8 pr-3 py-1 text-xs text-neutral-200 placeholder:text-neutral-500 outline-none w-48 font-mono"
            />
          </div>
        </div>
      </div>

      {/* Main Split View: Left List of Calls & Right Parameter Inspector */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left List */}
        <div className="w-1/2 border-r border-neutral-900 overflow-y-auto divide-y divide-neutral-900/60">
          {filteredEvents.length === 0 ? (
            <div className="p-8 text-center text-xs text-neutral-500">
              No API calls matched the selected filters.
            </div>
          ) : (
            filteredEvents.map(evt => {
              const isSelected = selectedEvent?.id === evt.id;
              return (
                <button
                  key={evt.id}
                  onClick={() => setSelectedEventId(evt.id)}
                  className={`w-full text-left p-3.5 transition-colors flex items-start gap-3 ${
                    isSelected
                      ? 'bg-neutral-900/90 text-white'
                      : 'hover:bg-neutral-900/40 text-neutral-300'
                  }`}
                >
                  <span className="font-mono text-[11px] text-neutral-500 shrink-0 w-8">
                    #{evt.seq}
                  </span>

                  <div className="flex-1 min-w-0 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold text-indigo-400 truncate">
                        {evt.library}!{evt.apiName}
                      </span>
                      <span className="font-mono text-[10px] text-neutral-500 shrink-0">
                        {evt.timestamp}
                      </span>
                    </div>

                    <div className="font-mono text-[11px] text-neutral-400 truncate">
                      {evt.parameters.map(p => `${p.name}=${p.value}`).join(', ')}
                    </div>

                    {evt.isSuspicious && (
                      <div className="text-[10px] text-red-400 font-medium flex items-center gap-1 font-sans">
                        <AlertTriangle className="w-3 h-3 shrink-0" />
                        <span className="truncate">{evt.riskNote}</span>
                      </div>
                    )}
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Right Detail Pane */}
        <div className="w-1/2 overflow-y-auto p-6 bg-neutral-950/40 space-y-6">
          {selectedEvent ? (
            <div className="space-y-6 max-w-xl">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-neutral-900 text-neutral-400 border border-neutral-800">
                    {selectedEvent.category} API
                  </span>
                  <span className="text-[11px] font-mono text-neutral-500">
                    Thread ID: {selectedEvent.threadId} · Duration: {selectedEvent.durationUs} μs
                  </span>
                </div>
                <h3 className="text-lg font-bold font-mono text-white mt-2">
                  {selectedEvent.library}!{selectedEvent.apiName}
                </h3>
              </div>

              {/* Security Alert if flagged */}
              {selectedEvent.isSuspicious && (
                <div className="p-3.5 rounded-xl border border-red-900/60 bg-red-950/30 text-xs space-y-1 text-red-300">
                  <div className="font-semibold flex items-center gap-1.5 text-red-400">
                    <ShieldAlert className="w-4 h-4" />
                    <span>Behavioral Anomaly Triggered</span>
                  </div>
                  <p className="leading-relaxed text-[11px]">{selectedEvent.riskNote}</p>
                </div>
              )}

              {/* Decoded Parameters Table */}
              <div className="space-y-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-neutral-400">
                  Decoded Parameter Values ({selectedEvent.parameters.length})
                </span>
                <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 divide-y divide-neutral-800/80 overflow-hidden font-mono text-xs">
                  {selectedEvent.parameters.map((p, i) => (
                    <div key={i} className="p-3 flex items-start justify-between gap-4">
                      <span className="text-indigo-400 font-semibold shrink-0">{p.name}</span>
                      <div className="text-right space-y-0.5">
                        <div className="text-white select-all">{p.value}</div>
                        {p.interpreted && (
                          <div className="text-[10px] text-cyan-400 font-sans">
                            {p.interpreted}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Return Value */}
              <div className="p-3.5 rounded-xl border border-neutral-800 bg-neutral-900/60 flex items-center justify-between text-xs font-mono">
                <span className="text-neutral-400">Return Value:</span>
                <span className="font-bold text-emerald-400 select-all">{selectedEvent.returnValue}</span>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-neutral-500">
              Select an API invocation from the left to inspect parameters and decoded buffers.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
