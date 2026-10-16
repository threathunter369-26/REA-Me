import React from 'react';
import {
  MessageSquarePlus,
  FolderOpen,
  Terminal,
  Calculator,
  Image as ImageIcon,
  Book,
  FileCode,
  Cpu,
  Layers,
  ShieldAlert,
  FileText,
  Activity,
  Upload,
  GitCompare,
  FileCheck,
  Shield,
  Unlock,
  Binary as BinaryIcon,
  Network,
  Database,
} from 'lucide-react';
import { Artifact } from '../types/reverseEngineering';

export type PlatformView =
  | 'chat'
  | 'workspace'
  | 'diff'
  | 'findings'
  | 'dataflow'
  | 'vexir'
  | 'debugger'
  | 'apitracker'
  | 'signatures'
  | 'yara'
  | 'mitre'
  | 'deob'
  | 'hex'
  | 'memory3d'
  | 'reports'
  | 'audit'
  | 'upload';

interface SidebarProps {
  artifacts: Artifact[];
  activeArtifactId: string | null;
  onSelectArtifact: (id: string) => void;
  onNewChat: () => void;
  onOpenFile: () => void;
  currentView: PlatformView;
  setCurrentView: (view: PlatformView) => void;
  recentChats: { id: string; title: string; artifactName: string; time: string }[];
  activeChatId: string | null;
  onSelectChat: (id: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  artifacts,
  activeArtifactId,
  onSelectArtifact,
  onNewChat,
  onOpenFile,
  currentView,
  setCurrentView,
  recentChats,
  activeChatId,
  onSelectChat,
}) => {
  const getIconForArtifact = (type: Artifact['iconType']) => {
    switch (type) {
      case 'binary':
        return <Terminal className="w-4 h-4 text-emerald-400" />;
      case 'app':
        return <Calculator className="w-4 h-4 text-amber-400" />;
      case 'shader':
        return <ImageIcon className="w-4 h-4 text-cyan-400" />;
      case 'model':
        return <Cpu className="w-4 h-4 text-purple-400" />;
      default:
        return <FileCode className="w-4 h-4 text-neutral-400" />;
    }
  };

  return (
    <aside className="w-64 md:w-72 bg-neutral-950 border-r border-neutral-900 flex flex-col h-full select-none text-neutral-300">
      {/* Top Action Items */}
      <div className="p-3 space-y-1">
        <button
          type="button"
          onClick={onNewChat}
          className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm text-neutral-300 hover:text-white hover:bg-neutral-900 transition-colors"
        >
          <div className="flex items-center gap-2.5">
            <MessageSquarePlus className="w-4 h-4 text-neutral-400" />
            <span className="font-medium">New chat</span>
          </div>
          <kbd className="text-[11px] font-mono text-neutral-500 bg-neutral-900 px-1.5 py-0.5 rounded border border-neutral-800">
            ⌘ N
          </kbd>
        </button>

        <button
          type="button"
          onClick={onOpenFile}
          className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm text-neutral-300 hover:text-white hover:bg-neutral-900 transition-colors"
        >
          <div className="flex items-center gap-2.5">
            <FolderOpen className="w-4 h-4 text-neutral-400" />
            <span className="font-medium">Open...</span>
          </div>
          <kbd className="text-[11px] font-mono text-neutral-500 bg-neutral-900 px-1.5 py-0.5 rounded border border-neutral-800">
            ⌘ O
          </kbd>
        </button>
      </div>

      {/* Projects List */}
      <div className="px-3 pt-3 pb-1">
        <div className="flex items-center justify-between text-xs px-3 mb-1 text-neutral-400">
          <span className="font-medium">Projects</span>
          <button
            type="button"
            onClick={() => setCurrentView('upload')}
            className="text-[11px] text-neutral-500 hover:text-neutral-300 transition-colors"
          >
            See all
          </button>
        </div>

        <div className="space-y-0.5 max-h-48 overflow-y-auto">
          {artifacts.map((art) => {
            const isSelected = activeArtifactId === art.id;
            return (
              <button
                key={art.id}
                type="button"
                onClick={() => onSelectArtifact(art.id)}
                className={`w-full flex items-start gap-2.5 px-3 py-2 rounded-xl text-left transition-colors ${
                  isSelected
                    ? 'bg-neutral-900 text-white'
                    : 'text-neutral-300 hover:bg-neutral-900/60 hover:text-white'
                }`}
              >
                <div className="mt-0.5 p-1 rounded-md bg-neutral-900/80 border border-neutral-800">
                  {getIconForArtifact(art.iconType)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium truncate">{art.name}</div>
                  <div className="text-[11px] text-neutral-500 truncate">
                    {art.chatCount === 1 ? '1 chat' : `${art.chatCount || 0} chats`} · {art.uploadedAt}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Chats Section */}
      <div className="flex-1 px-3 pt-3 pb-1 overflow-y-auto">
        <div className="text-xs px-3 mb-2 text-neutral-400 font-medium">Chats</div>
        {recentChats.length === 0 ? (
          <div className="px-3 py-4 text-xs text-neutral-500 leading-relaxed">
            No chats yet. Ask something to start one.
          </div>
        ) : (
          <div className="space-y-1">
            {recentChats.map((c) => (
              <button
                key={c.id}
                onClick={() => onSelectChat(c.id)}
                className={`w-full text-left px-3 py-2 rounded-lg text-xs truncate transition-colors ${
                  activeChatId === c.id
                    ? 'bg-neutral-900 text-white font-medium'
                    : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/50'
                }`}
              >
                <div className="truncate font-medium text-neutral-200">{c.title}</div>
                <div className="text-[10px] text-neutral-500 flex items-center justify-between mt-0.5">
                  <span>{c.artifactName}</span>
                  <span>{c.time}</span>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Platform Capabilities Navigation Footer */}
      <div className="p-3 border-t border-neutral-900 space-y-1 bg-neutral-950/60 text-xs">
        <div className="text-[11px] text-neutral-400 px-3 py-1 font-semibold">Workspace Views</div>
        
        <button
          onClick={() => setCurrentView('workspace')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'workspace' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Decompiler & CFG</span>
        </button>

        <button
          onClick={() => setCurrentView('diff')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'diff' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <GitCompare className="w-3.5 h-3.5 text-pink-400" />
          <span>Code Diffing</span>
        </button>

        <button
          onClick={() => setCurrentView('findings')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'findings' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
          <span>Vulnerabilities & AST</span>
        </button>

        <button
          onClick={() => setCurrentView('dataflow')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'dataflow' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <Network className="w-3.5 h-3.5 text-rose-400" />
          <span>Data Flow & Taint</span>
        </button>

        <button
          onClick={() => setCurrentView('vexir')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'vexir' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <BinaryIcon className="w-3.5 h-3.5 text-indigo-400" />
          <span>VEX-IR & Taint Engine</span>
        </button>

        <div className="pt-2 text-[11px] text-neutral-400 px-3 py-1 font-semibold">Dynamic & Sandbox Analysis</div>

        <button
          onClick={() => setCurrentView('debugger')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'debugger' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <Cpu className="w-3.5 h-3.5 text-indigo-400" />
          <span>Dynamic Debugger</span>
        </button>

        <button
          onClick={() => setCurrentView('apitracker')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'apitracker' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>API Call Tracker</span>
        </button>

        <div className="pt-2 text-[11px] text-neutral-400 px-3 py-1 font-semibold">Malware Forensics & Signatures</div>

        <button
          onClick={() => setCurrentView('signatures')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'signatures' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <Database className="w-3.5 h-3.5 text-purple-400" />
          <span>Signature Database</span>
        </button>

        <button
          onClick={() => setCurrentView('yara')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'yara' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span>YARA Pattern Engine</span>
        </button>

        <button
          onClick={() => setCurrentView('mitre')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'mitre' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <Shield className="w-3.5 h-3.5 text-purple-400" />
          <span>ATT&CK & Capa Matrix</span>
        </button>

        <button
          onClick={() => setCurrentView('deob')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'deob' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <Unlock className="w-3.5 h-3.5 text-cyan-400" />
          <span>String Deobfuscator</span>
        </button>

        <button
          onClick={() => setCurrentView('hex')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'hex' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <BinaryIcon className="w-3.5 h-3.5 text-amber-400" />
          <span>Hex Byte Inspector</span>
        </button>

        <button
          onClick={() => setCurrentView('memory3d')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'memory3d' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-indigo-400" />
          <span>3D Binary Memory Map</span>
        </button>

        <button
          onClick={() => setCurrentView('reports')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'reports' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <FileText className="w-3.5 h-3.5 text-amber-400" />
          <span>Technical Reports</span>
        </button>

        <button
          onClick={() => setCurrentView('audit')}
          className={`w-full flex items-center gap-2.5 px-3 py-1.5 rounded-lg transition-colors ${
            currentView === 'audit' ? 'bg-indigo-950/60 text-indigo-300 font-medium' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/60'
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-emerald-400" />
          <span>Audit Log & Isolation</span>
        </button>
      </div>
    </aside>
  );
};
