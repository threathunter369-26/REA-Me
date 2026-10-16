import React, { useState, useRef } from 'react';
import {
  Upload,
  X,
  FileCode,
  CheckCircle2,
  AlertCircle,
  Shield,
  Layers,
  Cpu,
  Terminal,
} from 'lucide-react';
import {
  Artifact,
  AnalysisProfile,
  AnalysisEngineId,
  ExecutionSafetyMode,
  TargetArchitecture,
} from '../types/reverseEngineering';
import { elevenStaticAdapter } from '../services/adapters/elevenStaticAdapter';

interface ArtifactUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCompleteUpload: (newArtifact: Artifact, rawBytes?: ArrayBuffer) => void;
}

export const ArtifactUploadModal: React.FC<ArtifactUploadModalProps> = ({
  isOpen,
  onClose,
  onCompleteUpload,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isHashing, setIsHashing] = useState(false);
  const [computedSha256, setComputedSha256] = useState<string>('');
  const [detectedFormat, setDetectedFormat] = useState<string>('');
  const [fileBytesBuffer, setFileBytesBuffer] = useState<ArrayBuffer | null>(null);

  // Configuration options
  const [profile, setProfile] = useState<AnalysisProfile>('standard');
  const [selectedEngines, setSelectedEngines] = useState<AnalysisEngineId[]>([
    'eleven-static',
    'ghidra-mcp',
    'rea-assistant',
    'reverse-skill',
  ]);
  const [safetyMode, setSafetyMode] = useState<ExecutionSafetyMode>('static-only');
  const [arch, setArch] = useState<TargetArchitecture>('x86_64');

  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const processFile = async (file: File) => {
    setSelectedFile(file);
    setIsHashing(true);
    setComputedSha256('');

    try {
      const buffer = await file.arrayBuffer();
      setFileBytesBuffer(buffer);

      // Compute genuine SHA-256 via browser Web Crypto API
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      setComputedSha256(hashHex);

      // Inspect binary format header
      const uint8 = new Uint8Array(buffer);
      const formatResult = elevenStaticAdapter.detectFormat(uint8);
      setDetectedFormat(formatResult.format);
      if (formatResult.arch !== 'universal') {
        setArch(formatResult.arch as TargetArchitecture);
      }
    } catch (err) {
      console.error('File parsing failed:', err);
    } finally {
      setIsHashing(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleStartAnalysis = () => {
    if (!selectedFile) return;

    const newArtifact: Artifact = {
      id: `art-${Date.now()}`,
      name: selectedFile.name,
      size: selectedFile.size,
      type: selectedFile.name.endsWith('.pt')
        ? 'model'
        : selectedFile.name.endsWith('.exe') || selectedFile.name.endsWith('.dll')
        ? 'pe'
        : selectedFile.name.endsWith('.metal') || selectedFile.name.endsWith('.spv')
        ? 'shader'
        : selectedFile.name.endsWith('.app')
        ? 'macho'
        : 'elf',
      formatDetails: detectedFormat || 'Compiled Binary Stream',
      architecture: arch,
      sha256: computedSha256 || 'calculating...',
      md5: '8f14e45fceea167a5a36dedd4bea2543',
      uploadedAt: 'Just now',
      status: 'analyzed',
      iconType: selectedFile.name.endsWith('.pt')
        ? 'model'
        : selectedFile.name.endsWith('.metal')
        ? 'shader'
        : selectedFile.name.endsWith('.app')
        ? 'app'
        : 'binary',
      description: `User-uploaded ${detectedFormat || 'binary artifact'} for AI-orchestrated reverse engineering.`,
    };

    onCompleteUpload(newArtifact, fileBytesBuffer || undefined);
    onClose();
  };

  const toggleEngine = (id: AnalysisEngineId) => {
    if (selectedEngines.includes(id)) {
      if (selectedEngines.length > 1) {
        setSelectedEngines(selectedEngines.filter(e => e !== id));
      }
    } else {
      setSelectedEngines([...selectedEngines, id]);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm select-none">
      <div className="bg-neutral-900 border border-neutral-800 rounded-3xl max-w-2xl w-full p-6 shadow-2xl space-y-6 text-neutral-200">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-neutral-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-indigo-950 border border-indigo-800/60 text-indigo-400">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">Upload Artifact for Analysis</h3>
              <p className="text-xs text-neutral-400">
                Non-executing environment. Supports ELF, PE, Mach-O, Shaders, PyTorch models.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Drag & Drop Box */}
        <div
          onDragOver={e => {
            e.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition-all ${
            dragActive
              ? 'border-indigo-500 bg-indigo-950/20'
              : 'border-neutral-700/80 hover:border-neutral-600 bg-neutral-950/50'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={e => e.target.files && e.target.files[0] && processFile(e.target.files[0])}
          />

          {selectedFile ? (
            <div className="space-y-2">
              <FileCode className="w-10 h-10 text-indigo-400 mx-auto" />
              <div className="font-semibold text-white">{selectedFile.name}</div>
              <div className="text-xs text-neutral-400">
                {(selectedFile.size / 1024).toFixed(1)} KB · {detectedFormat}
              </div>
              {computedSha256 && (
                <div className="text-[11px] font-mono text-cyan-400 truncate max-w-md mx-auto">
                  SHA-256: {computedSha256}
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              <Upload className="w-10 h-10 text-neutral-500 mx-auto" />
              <div className="text-sm font-medium text-neutral-200">
                Drag & drop binary, archive, or model file here
              </div>
              <div className="text-xs text-neutral-500">
                or click to browse from your workstation (up to 250 MB)
              </div>
            </div>
          )}
        </div>

        {/* Configuration Options */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {/* Analysis Profile */}
          <div className="space-y-1.5">
            <label className="text-neutral-400 font-medium">Analysis Profile</label>
            <select
              value={profile}
              onChange={e => setProfile(e.target.value as any)}
              className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-3 py-2 text-neutral-200 outline-none"
            >
              <option value="quick">Quick Scan (Headers & Strings)</option>
              <option value="standard">Standard (Ghidra Decompile + CFG)</option>
              <option value="deep">Deep Analysis (REA Semantic Synthesis)</option>
              <option value="security">Security Assessment (Reverse-Skill AST)</option>
            </select>
          </div>

          {/* Safety Mode */}
          <div className="space-y-1.5">
            <label className="text-neutral-400 font-medium">Execution Policy</label>
            <select
              value={safetyMode}
              onChange={e => setSafetyMode(e.target.value as any)}
              className="w-full bg-neutral-950 border border-neutral-800 rounded-xl px-3 py-2 text-neutral-200 outline-none"
            >
              <option value="static-only">Static analysis only (Guaranteed safe)</option>
              <option value="sandbox-prompt">Can run code: asks first</option>
              <option value="isolated-sandbox">Isolated worker sandbox</option>
            </select>
          </div>
        </div>

        {/* Engines Multi-select */}
        <div className="space-y-2 text-xs">
          <label className="text-neutral-400 font-medium">Enabled Reverse Engineering Engines</label>
          <div className="grid grid-cols-2 gap-2">
            {[
              { id: 'eleven-static', label: 'Eleven Native Static Parser' },
              { id: 'ghidra-mcp', label: 'Ghidra MCP Decompiler' },
              { id: 'rea-assistant', label: 'REA Semantic Assistant' },
              { id: 'reverse-skill', label: 'Reverse-Skill AST Auditor' },
            ].map(eng => {
              const isChecked = selectedEngines.includes(eng.id as any);
              return (
                <button
                  key={eng.id}
                  type="button"
                  onClick={() => toggleEngine(eng.id as any)}
                  className={`px-3 py-2 rounded-xl text-left border flex items-center justify-between transition-colors ${
                    isChecked
                      ? 'bg-neutral-800 border-indigo-500/60 text-white'
                      : 'bg-neutral-950 border-neutral-800 text-neutral-400'
                  }`}
                >
                  <span>{eng.label}</span>
                  {isChecked && <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400" />}
                </button>
              );
            })}
          </div>
        </div>

        {/* Actions Footer */}
        <div className="flex items-center justify-end gap-3 pt-2 border-t border-neutral-800">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium text-neutral-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!selectedFile || isHashing}
            onClick={handleStartAnalysis}
            className={`px-5 py-2 rounded-xl text-xs font-semibold transition-all ${
              selectedFile && !isHashing
                ? 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/30'
                : 'bg-neutral-800 text-neutral-500 cursor-not-allowed'
            }`}
          >
            {isHashing ? 'Hashing & Inspecting...' : 'Begin Orchestrated Analysis'}
          </button>
        </div>
      </div>
    </div>
  );
};
