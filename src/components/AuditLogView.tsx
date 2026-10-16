import React, { useState } from 'react';
import {
  Activity,
  ShieldCheck,
  Lock,
  Cpu,
  Server,
  AlertOctagon,
  CheckCircle2,
} from 'lucide-react';
import { AuditLog } from '../types/reverseEngineering';

export const AuditLogView: React.FC = () => {
  const [filter, setFilter] = useState<'all' | 'allowed' | 'quarantined'>('all');

  const auditEvents: AuditLog[] = [
    {
      id: 'aud-001',
      timestamp: '2026-10-16 09:12:04',
      user: 'threathunter369@gmail.com',
      action: 'ARTIFACT_UPLOAD',
      resource: '/bin/ls (ELF64)',
      status: 'allowed',
      ipAddress: '192.168.1.104',
      details: 'Magic bytes valid. Non-executing static analysis job scheduled.',
    },
    {
      id: 'aud-002',
      timestamp: '2026-10-16 09:12:06',
      user: 'agent-orchestrator-worker',
      action: 'GHIDRA_MCP_DECOMPILE',
      resource: 'fn_main (0x000043f0)',
      status: 'completed',
      ipAddress: 'worker-node-alpha-4',
      details: 'Headless decompiler bridge spawned in disposable cgroup container.',
    },
    {
      id: 'aud-003',
      timestamp: '2026-10-16 09:12:09',
      user: 'agent-orchestrator-worker',
      action: 'REVERSE_SKILL_AUDIT',
      resource: 'ls binary AST',
      status: 'completed',
      ipAddress: 'worker-node-alpha-4',
      details: 'Audited 42 imported symbols. Verified full RELRO and stack canary.',
    },
    {
      id: 'aud-004',
      timestamp: '2026-10-16 08:30:12',
      user: 'threathunter369@gmail.com',
      action: 'ARTIFACT_UPLOAD',
      resource: 'suspicious_loader.exe (PE32+)',
      status: 'quarantined',
      ipAddress: '192.168.1.104',
      details: 'High entropy .packed section (7.96). Dynamic execution blocked by policy.',
    },
    {
      id: 'aud-005',
      timestamp: '2026-10-16 08:30:15',
      user: 'agent-orchestrator-worker',
      action: 'SANDBOX_EGRESS_BLOCKED',
      resource: 'http://c2.telemetry-sync-cdn.net',
      status: 'denied',
      ipAddress: 'sandbox-egress-firewall',
      details: 'Blocked outbound network egress attempt from static extractor.',
    },
  ];

  const filtered = auditEvents.filter(a => {
    if (filter === 'all') return true;
    return a.status === filter;
  });

  return (
    <div className="flex-1 overflow-y-auto p-6 bg-neutral-950 text-neutral-200">
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-neutral-900 pb-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <h2 className="text-xl font-bold text-white tracking-tight">
                Enterprise Security & Audit Trail
              </h2>
            </div>
            <p className="text-xs text-neutral-400">
              Zero-trust worker isolation, egress firewalls, and immutable analysis audit events.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs">
            {['all', 'allowed', 'quarantined'].map(f => (
              <button
                key={f}
                onClick={() => setFilter(f as any)}
                className={`px-3 py-1.5 rounded-lg capitalize font-medium transition-colors ${
                  filter === f
                    ? 'bg-neutral-800 text-white border border-neutral-700'
                    : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* Worker Environment Security Posture Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-xl border border-neutral-800 bg-neutral-900/60 space-y-2">
            <div className="flex items-center gap-2 text-indigo-400 font-semibold">
              <Lock className="w-4 h-4" />
              <span>Non-Executing Isolation</span>
            </div>
            <p className="text-neutral-400 leading-relaxed text-[11px]">
              Uploaded binaries are analyzed strictly via static AST, Ghidra P-Code, and byte decoders. Zero arbitrary shell invocation.
            </p>
          </div>

          <div className="p-4 rounded-xl border border-neutral-800 bg-neutral-900/60 space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 font-semibold">
              <Server className="w-4 h-4" />
              <span>Strict Egress Firewall</span>
            </div>
            <p className="text-neutral-400 leading-relaxed text-[11px]">
              Analysis worker nodes enforce default-deny egress policies. C2 communication and network probes are dropped and logged.
            </p>
          </div>

          <div className="p-4 rounded-xl border border-neutral-800 bg-neutral-900/60 space-y-2">
            <div className="flex items-center gap-2 text-emerald-400 font-semibold">
              <Cpu className="w-4 h-4" />
              <span>Resource Quotas</span>
            </div>
            <p className="text-neutral-400 leading-relaxed text-[11px]">
              Enforced limits: 4 vCPU, 8 GB RAM, 60s per tool execution timeout. Disposable containers destroyed immediately post-job.
            </p>
          </div>
        </div>

        {/* Audit Log Table */}
        <div className="rounded-2xl border border-neutral-800 bg-neutral-900/40 overflow-hidden">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-neutral-800 bg-neutral-950/70 text-neutral-400 text-[11px]">
                <th className="py-2.5 px-4 font-medium">Timestamp</th>
                <th className="py-2.5 px-4 font-medium">User / Principal</th>
                <th className="py-2.5 px-4 font-medium">Action</th>
                <th className="py-2.5 px-4 font-medium">Target Resource</th>
                <th className="py-2.5 px-4 font-medium">Status</th>
                <th className="py-2.5 px-4 font-medium">Policy Note</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-900/60 font-mono text-[11px]">
              {filtered.map(a => (
                <tr key={a.id} className="hover:bg-neutral-900/40 transition-colors">
                  <td className="py-2.5 px-4 text-neutral-500 whitespace-nowrap">{a.timestamp}</td>
                  <td className="py-2.5 px-4 text-neutral-300 font-sans">{a.user}</td>
                  <td className="py-2.5 px-4 text-indigo-400 font-semibold">{a.action}</td>
                  <td className="py-2.5 px-4 text-neutral-300 font-sans">{a.resource}</td>
                  <td className="py-2.5 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-sans uppercase font-bold ${
                        a.status === 'allowed' || a.status === 'completed'
                          ? 'bg-emerald-950 text-emerald-300'
                          : a.status === 'quarantined'
                          ? 'bg-amber-950 text-amber-300'
                          : 'bg-red-950 text-red-300'
                      }`}
                    >
                      {a.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-neutral-400 font-sans text-xs">{a.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
