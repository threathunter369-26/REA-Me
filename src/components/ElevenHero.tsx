import React, { useState, useRef } from 'react';
import { BrandLogo } from './BrandLogo';
import {
  Plus,
  FileCode,
  Shield,
  ChevronDown,
  ArrowUp,
  Binary,
  Layers,
  Cpu,
  Sparkles,
  Paperclip,
  Check,
} from 'lucide-react';
import { ExecutionSafetyMode, AnalysisEngineId } from '../types/reverseEngineering';

interface ElevenHeroProps {
  onSelectPrompt: (promptText: string, suggestedArtifactId?: string) => void;
  onUploadFile: (file: File) => void;
  safetyMode: ExecutionSafetyMode;
  setSafetyMode: (mode: ExecutionSafetyMode) => void;
  selectedEngine: AnalysisEngineId | 'auto';
  setSelectedEngine: (engine: AnalysisEngineId | 'auto') => void;
  selectedModel: string;
  setSelectedModel: (model: string) => void;
  selectedPersona: string;
  setSelectedPersona: (persona: string) => void;
}

export const ElevenHero: React.FC<ElevenHeroProps> = ({
  onSelectPrompt,
  onUploadFile,
  safetyMode,
  setSafetyMode,
  selectedEngine,
  setSelectedEngine,
  selectedModel,
  setSelectedModel,
  selectedPersona,
  setSelectedPersona,
}) => {
  const [inputQuery, setInputQuery] = useState('');
  const [showSafetyDropdown, setShowSafetyDropdown] = useState(false);
  const [showEngineDropdown, setShowEngineDropdown] = useState(false);
  const [showModelDropdown, setShowModelDropdown] = useState(false);
  const [showPersonaDropdown, setShowPersonaDropdown] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSubmit = (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!inputQuery.trim()) return;
    onSelectPrompt(inputQuery.trim());
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onUploadFile(e.target.files[0]);
    }
  };

  const quickCards = [
    {
      id: 'card-bin-ls',
      icon: <Binary className="w-4 h-4 text-neutral-400" />,
      category: '01 Binary',
      title: 'What does /bin/ls do when it starts?',
      artifactId: 'art-bin-ls',
    },
    {
      id: 'card-notes',
      icon: <Layers className="w-4 h-4 text-neutral-400" />,
      category: 'App',
      title: 'How does Notes save attachments?',
      artifactId: 'art-dictionary-app',
    },
    {
      id: 'card-model',
      icon: <Cpu className="w-4 h-4 text-neutral-400" />,
      category: 'Model',
      title: 'Is this .pt file safe to load?',
      artifactId: 'art-model-pt',
    },
    {
      id: 'card-shader',
      icon: <Sparkles className="w-4 h-4 text-neutral-400" />,
      category: 'Shader',
      title: 'Why is this blur shader slow?',
      artifactId: 'art-photofilter-app',
    },
  ];

  return (
    <div className="flex-1 flex flex-col items-center justify-center px-4 py-12 max-w-4xl mx-auto w-full select-none">
      {/* Brand Icon & Heading */}
      <div className="flex flex-col items-center mb-8">
        <BrandLogo size="lg" className="mb-6" />
        <h1 className="text-3xl md:text-4xl font-semibold tracking-tight text-neutral-100 font-sans text-center">
          What should we take apart?
        </h1>
      </div>

      {/* Main Interactive Prompt Box */}
      <div className="w-full bg-neutral-900/90 border border-neutral-800 rounded-3xl p-3 shadow-2xl backdrop-blur-xl transition-all focus-within:border-neutral-700 focus-within:ring-1 focus-within:ring-indigo-500/30">
        <form onSubmit={handleSubmit} className="flex flex-col">
          <textarea
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                handleSubmit();
              }
            }}
            placeholder="Ask anything, or drop an app, binary, shader or model here"
            className="w-full bg-transparent text-neutral-200 placeholder:text-neutral-500 text-base md:text-lg resize-none outline-none px-4 pt-3 pb-6 min-h-[72px]"
            rows={2}
          />

          {/* Bottom Toolbar Controls */}
          <div className="flex flex-wrap items-center justify-between gap-2 px-2 pt-2 border-t border-neutral-800/60">
            {/* Left Controls: File Upload & Safety Badge */}
            <div className="flex items-center gap-1.5">
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                onChange={handleFileChange}
              />
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="w-8 h-8 rounded-full flex items-center justify-center text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors"
                title="Upload file (Binary, App, Shader, Model)"
              >
                <Plus className="w-4 h-4" />
              </button>

              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="w-8 h-8 rounded-full flex items-center justify-center text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors"
                title="Attach source or project"
              >
                <FileCode className="w-4 h-4" />
              </button>

              {/* Safety Mode Selector */}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowSafetyDropdown(!showSafetyDropdown)}
                  className="flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-full bg-neutral-800/80 border border-neutral-700/60 text-neutral-300 hover:bg-neutral-800 transition-colors"
                >
                  <Shield className="w-3.5 h-3.5 text-emerald-400" />
                  <span>
                    {safetyMode === 'sandbox-prompt'
                      ? 'Can run code: asks first'
                      : safetyMode === 'static-only'
                      ? 'Static analysis only'
                      : 'Isolated sandbox'}
                  </span>
                </button>

                {showSafetyDropdown && (
                  <div className="absolute left-0 bottom-full mb-2 w-64 bg-neutral-900 border border-neutral-800 rounded-xl shadow-2xl p-1 z-30 text-xs">
                    <button
                      type="button"
                      onClick={() => {
                        setSafetyMode('sandbox-prompt');
                        setShowSafetyDropdown(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg hover:bg-neutral-800 text-neutral-200 flex items-center justify-between"
                    >
                      <div>
                        <div className="font-medium">Can run code: asks first</div>
                        <div className="text-[11px] text-neutral-400">Prompts before executing any worker dynamic tool</div>
                      </div>
                      {safetyMode === 'sandbox-prompt' && <Check className="w-3.5 h-3.5 text-indigo-400 shrink-0" />}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setSafetyMode('static-only');
                        setShowSafetyDropdown(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg hover:bg-neutral-800 text-neutral-200 flex items-center justify-between"
                    >
                      <div>
                        <div className="font-medium">Static analysis only (Recommended)</div>
                        <div className="text-[11px] text-neutral-400">Disassembly and decompilation without executing</div>
                      </div>
                      {safetyMode === 'static-only' && <Check className="w-3.5 h-3.5 text-indigo-400 shrink-0" />}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setSafetyMode('isolated-sandbox');
                        setShowSafetyDropdown(false);
                      }}
                      className="w-full text-left px-3 py-2 rounded-lg hover:bg-neutral-800 text-neutral-200 flex items-center justify-between"
                    >
                      <div>
                        <div className="font-medium">Ephemeral sandbox worker</div>
                        <div className="text-[11px] text-neutral-400">Strict network isolation and time limits</div>
                      </div>
                      {safetyMode === 'isolated-sandbox' && <Check className="w-3.5 h-3.5 text-indigo-400 shrink-0" />}
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* Right Controls: Mode, Model, Persona, Submit */}
            <div className="flex items-center gap-2">
              {/* Engine Selector */}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowEngineDropdown(!showEngineDropdown)}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/80 rounded-md transition-colors"
                >
                  <span>✏️</span>
                  <span className="capitalize">{selectedEngine === 'auto' ? 'Auto' : selectedEngine}</span>
                  <ChevronDown className="w-3 h-3 text-neutral-500" />
                </button>

                {showEngineDropdown && (
                  <div className="absolute right-0 bottom-full mb-2 w-52 bg-neutral-900 border border-neutral-800 rounded-xl shadow-2xl p-1 z-30 text-xs">
                    {[
                      { id: 'auto', label: 'Auto (Orchestrated)' },
                      { id: 'ghidra-mcp', label: 'Ghidra MCP Decompiler' },
                      { id: 'rea-assistant', label: 'REA Assistant' },
                      { id: 'reverse-skill', label: 'Reverse-Skill AST' },
                      { id: 'eleven-static', label: 'Eleven Static Parser' },
                    ].map(opt => (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => {
                          setSelectedEngine(opt.id as any);
                          setShowEngineDropdown(false);
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-neutral-800 text-neutral-200 flex items-center justify-between"
                      >
                        <span>{opt.label}</span>
                        {selectedEngine === opt.id && <Check className="w-3.5 h-3.5 text-indigo-400" />}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Model Selector */}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowModelDropdown(!showModelDropdown)}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/80 rounded-md transition-colors"
                >
                  <span>{selectedModel}</span>
                  <ChevronDown className="w-3 h-3 text-neutral-500" />
                </button>

                {showModelDropdown && (
                  <div className="absolute right-0 bottom-full mb-2 w-48 bg-neutral-900 border border-neutral-800 rounded-xl shadow-2xl p-1 z-30 text-xs">
                    {['Deepseek Flash Medium', 'Gemini 2.5 Flash', 'Claude 3.7 Sonnet', 'GPT-4o Mini'].map(m => (
                      <button
                        key={m}
                        type="button"
                        onClick={() => {
                          setSelectedModel(m);
                          setShowModelDropdown(false);
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-neutral-800 text-neutral-200 flex items-center justify-between"
                      >
                        <span>{m}</span>
                        {selectedModel === m && <Check className="w-3.5 h-3.5 text-indigo-400" />}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Persona Selector */}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowPersonaDropdown(!showPersonaDropdown)}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/80 rounded-md transition-colors"
                >
                  <span className="text-amber-400">✳️</span>
                  <span>{selectedPersona}</span>
                  <ChevronDown className="w-3 h-3 text-neutral-500" />
                </button>

                {showPersonaDropdown && (
                  <div className="absolute right-0 bottom-full mb-2 w-48 bg-neutral-900 border border-neutral-800 rounded-xl shadow-2xl p-1 z-30 text-xs">
                    {['Aster', 'Reverse Engineer', 'Malware Analyst', 'Security Auditor'].map(p => (
                      <button
                        key={p}
                        type="button"
                        onClick={() => {
                          setSelectedPersona(p);
                          setShowPersonaDropdown(false);
                        }}
                        className="w-full text-left px-3 py-2 rounded-lg hover:bg-neutral-800 text-neutral-200 flex items-center justify-between"
                      >
                        <span>{p}</span>
                        {selectedPersona === p && <Check className="w-3.5 h-3.5 text-indigo-400" />}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={!inputQuery.trim()}
                className={`w-8 h-8 rounded-full flex items-center justify-center transition-all ${
                  inputQuery.trim()
                    ? 'bg-neutral-200 text-neutral-900 hover:bg-white'
                    : 'bg-neutral-800 text-neutral-500 cursor-not-allowed'
                }`}
                title="Send instruction to agent"
              >
                <ArrowUp className="w-4 h-4" />
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* 4 Suggestion Cards matching the screenshot */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 w-full mt-8">
        {quickCards.map((card) => (
          <button
            key={card.id}
            type="button"
            onClick={() => onSelectPrompt(card.title, card.artifactId)}
            className="flex flex-col items-start p-4 rounded-2xl bg-neutral-900/60 hover:bg-neutral-900/90 border border-neutral-800/80 hover:border-neutral-700/80 text-left transition-all group"
          >
            <div className="flex items-center gap-1.5 text-xs text-neutral-400 mb-2">
              {card.icon}
              <span className="font-medium">{card.category}</span>
            </div>
            <div className="text-sm md:text-base font-medium text-neutral-200 group-hover:text-white transition-colors">
              {card.title}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
};
