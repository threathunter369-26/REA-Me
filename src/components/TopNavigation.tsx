import React from 'react';
import { BrandLogo } from './BrandLogo';
import { Upload, Shield, ChevronRight } from 'lucide-react';

import { PlatformView } from './Sidebar';

interface TopNavigationProps {
  currentView: PlatformView;
  onNavigate: (view: PlatformView) => void;
  activeArtifactName?: string;
  onOpenUpload: () => void;
}

export const TopNavigation: React.FC<TopNavigationProps> = ({
  currentView,
  onNavigate,
  activeArtifactName,
  onOpenUpload,
}) => {
  return (
    <header className="h-14 border-b border-neutral-900 bg-neutral-950 px-6 flex items-center justify-between gap-8 select-none shrink-0 z-20">
      {/* Zone 1: Single text wordmark & breadcrumb */}
      <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
        <button
          onClick={() => onNavigate('chat')}
          className="flex items-center gap-2 hover:opacity-90 transition-opacity"
        >
          <BrandLogo size="sm" />
          <span className="text-base font-bold tracking-tight text-white font-sans">
            Eleven
          </span>
        </button>

        {activeArtifactName && (
          <div className="hidden sm:flex items-center gap-2 text-xs text-neutral-400 font-mono">
            <ChevronRight className="w-3.5 h-3.5 text-neutral-600" />
            <span className="text-neutral-200">{activeArtifactName}</span>
          </div>
        )}
      </div>

      {/* Zone 2: 4-5 single-line nav links */}
      <nav className="hidden md:flex items-center gap-6 text-xs font-medium text-neutral-400">
        <button
          onClick={() => onNavigate('chat')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'chat' ? 'text-white' : ''
          }`}
        >
          Assistant
        </button>

        <button
          onClick={() => onNavigate('workspace')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'workspace' ? 'text-white' : ''
          }`}
        >
          Decompiler & CFG
        </button>

        <button
          onClick={() => onNavigate('dataflow')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'dataflow' ? 'text-white' : ''
          }`}
        >
          Data Flow
        </button>

        <button
          onClick={() => onNavigate('vexir')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'vexir' ? 'text-white' : ''
          }`}
        >
          VEX-IR & Taint
        </button>

        <button
          onClick={() => onNavigate('debugger')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'debugger' ? 'text-white' : ''
          }`}
        >
          Debugger
        </button>

        <button
          onClick={() => onNavigate('apitracker')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'apitracker' ? 'text-white' : ''
          }`}
        >
          API Tracker
        </button>

        <button
          onClick={() => onNavigate('signatures')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'signatures' ? 'text-white' : ''
          }`}
        >
          Signatures DB
        </button>

        <button
          onClick={() => onNavigate('yara')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'yara' ? 'text-white' : ''
          }`}
        >
          YARA Engine
        </button>

        <button
          onClick={() => onNavigate('mitre')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'mitre' ? 'text-white' : ''
          }`}
        >
          ATT&CK Matrix
        </button>

        <button
          onClick={() => onNavigate('deob')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'deob' ? 'text-white' : ''
          }`}
        >
          Deobfuscator
        </button>

        <button
          onClick={() => onNavigate('diff')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'diff' ? 'text-white' : ''
          }`}
        >
          Code Diff
        </button>

        <button
          onClick={() => onNavigate('memory3d')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'memory3d' ? 'text-white' : ''
          }`}
        >
          3D Memory Map
        </button>

        <button
          onClick={() => onNavigate('reports')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'reports' ? 'text-white' : ''
          }`}
        >
          Reports & Export
        </button>

        <button
          onClick={() => onNavigate('audit')}
          className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${
            currentView === 'audit' ? 'text-white' : ''
          }`}
        >
          Sandbox Isolation
        </button>
      </nav>

      {/* Zone 3: 1 primary action */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onOpenUpload}
          className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 transition-colors shadow-sm whitespace-nowrap shrink-0"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload Binary</span>
        </button>
      </div>
    </header>
  );
};
