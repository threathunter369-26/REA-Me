import React, { useState, useEffect } from 'react';
import {
  Artifact,
  AnalysisResult,
  SignatureRecord,
  SignatureMatchResult,
  SignatureType,
  SignatureCategory,
  TargetArchitecture,
} from '../types/reverseEngineering';
import { signatureService } from '../services/signatureService';
import {
  Database,
  Search,
  Plus,
  Play,
  Download,
  Upload,
  Sparkles,
  Trash2,
  Edit2,
  CheckCircle,
  AlertTriangle,
  ShieldAlert,
  RotateCcw,
  Code,
  Tag,
  Filter,
  Layers,
  FileCheck,
  Hash,
  Binary,
  X,
  Copy,
  Check,
} from 'lucide-react';

interface SignatureDatabaseViewProps {
  artifact: Artifact;
  analysis?: AnalysisResult;
}

export const SignatureDatabaseView: React.FC<SignatureDatabaseViewProps> = ({
  artifact,
  analysis,
}) => {
  const [signatures, setSignatures] = useState<SignatureRecord[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

  // Match Scanning State
  const [matches, setMatches] = useState<SignatureMatchResult[]>([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [hasScanned, setHasScanned] = useState<boolean>(false);

  // Modals
  const [isAddModalOpen, setIsAddModalOpen] = useState<boolean>(false);
  const [isAiModalOpen, setIsAiModalOpen] = useState<boolean>(false);
  const [isImportModalOpen, setIsImportModalOpen] = useState<boolean>(false);
  const [editingSig, setEditingSig] = useState<SignatureRecord | null>(null);

  // AI Generator Form
  const [aiSigType, setAiSigType] = useState<SignatureType>('flirt');
  const [aiSigName, setAiSigName] = useState<string>('custom_fn_signature');
  const [aiSigCategory, setAiSigCategory] = useState<SignatureCategory>('library');
  const [aiInstructions, setAiInstructions] = useState<string>(
    'Recognize x86_64 AVX2 memory copy and boundary checks with wildcarded offsets.'
  );
  const [aiGeneratedOutput, setAiGeneratedOutput] = useState<string | null>(null);
  const [isAiGenerating, setIsAiGenerating] = useState<boolean>(false);

  // Add/Edit Form State
  const [formName, setFormName] = useState<string>('');
  const [formType, setFormType] = useState<SignatureType>('flirt');
  const [formCategory, setFormCategory] = useState<SignatureCategory>('malware');
  const [formPattern, setFormPattern] = useState<string>('');
  const [formWildcardMask, setFormWildcardMask] = useState<string>('');
  const [formDescription, setFormDescription] = useState<string>('');
  const [formArch, setFormArch] = useState<TargetArchitecture | 'all'>('all');
  const [formSeverity, setFormSeverity] = useState<'critical' | 'high' | 'medium' | 'low' | 'info'>('medium');
  const [formConfidence, setFormConfidence] = useState<'exact' | 'heuristic' | 'fuzzy'>('exact');

  // Import Text
  const [importText, setImportText] = useState<string>('');
  const [importStatus, setImportStatus] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    loadSignatures();
  }, []);

  const loadSignatures = () => {
    const list = signatureService.getSignatures();
    setSignatures(list);
  };

  const handleToggleEnable = (id: string) => {
    signatureService.toggleSignature(id);
    loadSignatures();
  };

  const handleDelete = (id: string) => {
    if (confirm('Delete this signature from database?')) {
      signatureService.deleteSignature(id);
      loadSignatures();
    }
  };

  const handleOpenAddModal = () => {
    setEditingSig(null);
    setFormName('');
    setFormType('flirt');
    setFormCategory('library');
    setFormPattern('55 48 89 e5 48 83 ec ??');
    setFormWildcardMask('xxxxxxx?');
    setFormDescription('Recognizes standard x86_64 function prologue.');
    setFormArch('x86_64');
    setFormSeverity('medium');
    setFormConfidence('exact');
    setIsAddModalOpen(true);
  };

  const handleOpenEditModal = (sig: SignatureRecord) => {
    setEditingSig(sig);
    setFormName(sig.name);
    setFormType(sig.type);
    setFormCategory(sig.category);
    setFormPattern(sig.pattern);
    setFormWildcardMask(sig.wildcardMask || '');
    setFormDescription(sig.description);
    setFormArch(sig.targetArch);
    setFormSeverity(sig.severity);
    setFormConfidence(sig.confidence);
    setIsAddModalOpen(true);
  };

  const handleSaveSignature = () => {
    if (!formName.trim() || !formPattern.trim()) {
      alert('Signature name and pattern are required.');
      return;
    }

    if (editingSig) {
      signatureService.updateSignature(editingSig.id, {
        name: formName,
        type: formType,
        category: formCategory,
        pattern: formPattern,
        wildcardMask: formWildcardMask || undefined,
        description: formDescription,
        targetArch: formArch,
        severity: formSeverity,
        confidence: formConfidence,
      });
    } else {
      signatureService.addSignature({
        name: formName,
        type: formType,
        category: formCategory,
        pattern: formPattern,
        wildcardMask: formWildcardMask || undefined,
        description: formDescription,
        targetArch: formArch,
        severity: formSeverity,
        confidence: formConfidence,
        source: 'User Custom',
        version: '1.0',
        enabled: true,
      });
    }

    setIsAddModalOpen(false);
    loadSignatures();
  };

  const handleScanBinary = () => {
    setIsScanning(true);
    setTimeout(() => {
      const matchResults = signatureService.scanBinary(artifact, analysis);
      setMatches(matchResults);
      setIsScanning(false);
      setHasScanned(true);
      loadSignatures();
    }, 600);
  };

  const handleResetDefaults = () => {
    if (confirm('Reset signature database to factory default production rules?')) {
      signatureService.resetToDefaults();
      loadSignatures();
      setMatches([]);
      setHasScanned(false);
    }
  };

  const handleExportJson = () => {
    const jsonStr = signatureService.exportToJson();
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `eleven_signature_database_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportYara = () => {
    const yaraStr = signatureService.exportToYara();
    const blob = new Blob([yaraStr], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `eleven_ruleset_${Date.now()}.yar`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportJson = () => {
    if (!importText.trim()) return;
    const res = signatureService.importFromJson(importText);
    if (res.error) {
      setImportStatus(`Error: ${res.error}`);
    } else {
      setImportStatus(`Successfully imported ${res.importedCount} signatures!`);
      loadSignatures();
      setTimeout(() => {
        setIsImportModalOpen(false);
        setImportStatus(null);
        setImportText('');
      }, 1500);
    }
  };

  const handleGenerateAiSignature = async () => {
    setIsAiGenerating(true);
    setAiGeneratedOutput(null);
    try {
      const res = await fetch('/api/ai/generate-signature', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          signatureType: aiSigType,
          name: aiSigName,
          category: aiSigCategory,
          instructions: aiInstructions,
          architecture: artifact.architecture,
        }),
      });
      const data = await res.json();
      setAiGeneratedOutput(data.generatedContent || 'Generated pattern.');
    } catch (e: any) {
      setAiGeneratedOutput(`Failed to synthesize signature: ${e.message}`);
    } finally {
      setIsAiGenerating(false);
    }
  };

  const handleApplyAiSignature = () => {
    if (!aiGeneratedOutput) return;

    if (aiSigType === 'flirt') {
      const patternMatch = aiGeneratedOutput.match(/Pattern:\s*([^\n]+)/i);
      const maskMatch = aiGeneratedOutput.match(/Mask:\s*([^\n]+)/i);
      const pattern = patternMatch ? patternMatch[1].trim() : aiGeneratedOutput.slice(0, 64);
      const mask = maskMatch ? maskMatch[1].trim() : undefined;

      signatureService.addSignature({
        name: aiSigName,
        type: 'flirt',
        category: aiSigCategory,
        pattern,
        wildcardMask: mask,
        description: `AI-synthesized FLIRT signature for ${aiSigName}`,
        targetArch: artifact.architecture,
        severity: 'medium',
        confidence: 'exact',
        source: 'Eleven ThreatLab',
        version: '1.0',
        enabled: true,
      });
    } else {
      signatureService.addSignature({
        name: aiSigName,
        type: aiSigType,
        category: aiSigCategory,
        pattern: aiGeneratedOutput,
        description: `AI-synthesized ${aiSigType.toUpperCase()} rule for ${aiSigName}`,
        targetArch: artifact.architecture,
        severity: 'high',
        confidence: 'heuristic',
        source: 'Eleven ThreatLab',
        version: '1.0',
        enabled: true,
      });
    }

    setIsAiModalOpen(false);
    loadSignatures();
  };

  const handleCopyPattern = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  // Filtered signatures
  const filteredSignatures = signatures.filter((sig) => {
    const matchesSearch =
      searchQuery === '' ||
      sig.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      sig.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      sig.pattern.toLowerCase().includes(searchQuery.toLowerCase()) ||
      sig.category.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesType = selectedType === 'all' || sig.type === selectedType;
    const matchesCategory = selectedCategory === 'all' || sig.category === selectedCategory;
    const matchesSeverity = selectedSeverity === 'all' || sig.severity === selectedSeverity;

    return matchesSearch && matchesType && matchesCategory && matchesSeverity;
  });

  // Category counts
  const totalSigs = signatures.length;
  const flirtCount = signatures.filter((s) => s.type === 'flirt').length;
  const yaraCount = signatures.filter((s) => s.type === 'yara').length;
  const hashCount = signatures.filter((s) => s.type === 'hash').length;
  const byteCount = signatures.filter((s) => s.type === 'byte_pattern').length;
  const threatCount = signatures.filter((s) => s.type === 'threat_actor').length;

  return (
    <div className="flex-1 flex flex-col h-full bg-neutral-950 text-neutral-200 overflow-hidden select-none">
      {/* Top Header */}
      <div className="border-b border-neutral-900 bg-neutral-950 px-6 py-3 flex flex-wrap items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-purple-950/40 border border-purple-800/40 text-purple-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-white tracking-tight">
                Signature Database Management
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-neutral-900 text-neutral-400 border border-neutral-800">
                FLIRT · YARA · Hashes · Bytes
              </span>
            </div>
            <p className="text-xs text-neutral-400">
              Manage library recognition patterns, malware rule definitions, and match against target binary.
            </p>
          </div>
        </div>

        {/* Global Toolbar Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleScanBinary}
            disabled={isScanning}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors shadow-sm"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isScanning ? 'Scanning Target...' : 'Scan Active Binary'}</span>
          </button>

          <button
            onClick={() => setIsAiModalOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
            <span>AI Synthesizer</span>
          </button>

          <button
            onClick={handleOpenAddModal}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Signature</span>
          </button>

          <div className="h-4 w-px bg-neutral-800 mx-1" />

          <button
            onClick={handleExportJson}
            className="p-1.5 rounded-lg bg-neutral-900 hover:bg-neutral-800 text-neutral-400 hover:text-white border border-neutral-800"
            title="Export JSON"
          >
            <Download className="w-4 h-4" />
          </button>

          <button
            onClick={() => setIsImportModalOpen(true)}
            className="p-1.5 rounded-lg bg-neutral-900 hover:bg-neutral-800 text-neutral-400 hover:text-white border border-neutral-800"
            title="Import JSON"
          >
            <Upload className="w-4 h-4" />
          </button>

          <button
            onClick={handleResetDefaults}
            className="p-1.5 rounded-lg bg-neutral-900 hover:bg-neutral-800 text-neutral-400 hover:text-white border border-neutral-800"
            title="Reset Defaults"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Stats Summary Cards Bar */}
      <div className="bg-neutral-900/30 border-b border-neutral-900 px-6 py-2.5 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 text-xs">
        <div className="flex items-center gap-2 font-mono">
          <span className="text-neutral-500">Total:</span>
          <span className="font-bold text-white">{totalSigs}</span>
        </div>
        <div className="flex items-center gap-2 font-mono">
          <span className="text-neutral-500">FLIRT Libs:</span>
          <span className="font-bold text-indigo-400">{flirtCount}</span>
        </div>
        <div className="flex items-center gap-2 font-mono">
          <span className="text-neutral-500">YARA Rules:</span>
          <span className="font-bold text-emerald-400">{yaraCount}</span>
        </div>
        <div className="flex items-center gap-2 font-mono">
          <span className="text-neutral-500">Hashes:</span>
          <span className="font-bold text-cyan-400">{hashCount}</span>
        </div>
        <div className="flex items-center gap-2 font-mono">
          <span className="text-neutral-500">Byte Patterns:</span>
          <span className="font-bold text-amber-400">{byteCount}</span>
        </div>
        <div className="flex items-center gap-2 font-mono">
          <span className="text-neutral-500">Threat Actors:</span>
          <span className="font-bold text-red-400">{threatCount}</span>
        </div>
      </div>

      {/* Scan Results Match Banner if scanned */}
      {hasScanned && (
        <div className="bg-indigo-950/30 border-b border-indigo-900/40 px-6 py-3 flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold text-indigo-300">
              <CheckCircle className="w-4 h-4 text-indigo-400" />
              <span>
                Binary Scan Complete: {matches.length} Signature Matches Identified on {artifact.name}
              </span>
            </div>
            <button
              onClick={() => setHasScanned(false)}
              className="text-xs text-neutral-400 hover:text-white"
            >
              Dismiss
            </button>
          </div>

          {matches.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 mt-1">
              {matches.map((m, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-lg bg-neutral-900/90 border border-neutral-800 text-xs space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white truncate">{m.signatureName}</span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                        m.severity === 'critical'
                          ? 'bg-red-950/60 text-red-400 border-red-800'
                          : m.severity === 'high'
                          ? 'bg-amber-950/60 text-amber-400 border-amber-800'
                          : 'bg-indigo-950/60 text-indigo-400 border-indigo-800'
                      }`}
                    >
                      {m.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-neutral-400 flex items-center justify-between">
                    <span>Offset: {m.offset}</span>
                    {m.matchedFunction && <span>Fn: {m.matchedFunction}</span>}
                  </div>
                  <div className="text-[11px] text-neutral-300 font-mono truncate">{m.snippet}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Search & Filter Bar */}
      <div className="p-4 border-b border-neutral-900 bg-neutral-950/70 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 flex-1 max-w-md bg-neutral-900 px-3 py-1.5 rounded-lg border border-neutral-800">
          <Search className="w-4 h-4 text-neutral-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search signatures by name, pattern, description..."
            className="w-full bg-transparent text-neutral-200 placeholder-neutral-500 focus:outline-none"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Type Filter */}
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="bg-neutral-900 border border-neutral-800 rounded-lg px-2.5 py-1.5 text-neutral-300 focus:outline-none"
          >
            <option value="all">All Types</option>
            <option value="flirt">FLIRT Library</option>
            <option value="yara">YARA Rules</option>
            <option value="hash">Known Hashes</option>
            <option value="byte_pattern">Byte Patterns</option>
            <option value="threat_actor">Threat Actor</option>
          </select>

          {/* Category Filter */}
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-neutral-900 border border-neutral-800 rounded-lg px-2.5 py-1.5 text-neutral-300 focus:outline-none"
          >
            <option value="all">All Categories</option>
            <option value="malware">Malware</option>
            <option value="crypto">Crypto</option>
            <option value="packer">Packer</option>
            <option value="c2">C2 Communications</option>
            <option value="injection">Process Injection</option>
            <option value="library">Library Runtime</option>
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="bg-neutral-900 border border-neutral-800 rounded-lg px-2.5 py-1.5 text-neutral-300 focus:outline-none"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      {/* Main Signature List Table / Cards */}
      <div className="flex-1 overflow-y-auto p-6 space-y-3">
        {filteredSignatures.length === 0 ? (
          <div className="p-12 text-center text-xs text-neutral-500">
            No signatures match your search or filter criteria.
          </div>
        ) : (
          filteredSignatures.map((sig) => {
            let typeColor = 'text-indigo-400 bg-indigo-950/40 border-indigo-800/40';
            if (sig.type === 'yara') typeColor = 'text-emerald-400 bg-emerald-950/40 border-emerald-800/40';
            if (sig.type === 'hash') typeColor = 'text-cyan-400 bg-cyan-950/40 border-cyan-800/40';
            if (sig.type === 'byte_pattern') typeColor = 'text-amber-400 bg-amber-950/40 border-amber-800/40';
            if (sig.type === 'threat_actor') typeColor = 'text-red-400 bg-red-950/40 border-red-800/40';

            return (
              <div
                key={sig.id}
                className={`p-4 rounded-xl border transition-all ${
                  sig.enabled
                    ? 'bg-neutral-900/60 border-neutral-800 hover:border-neutral-700'
                    : 'bg-neutral-950 border-neutral-900/60 opacity-60'
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-3 mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${typeColor}`}>
                      {sig.type}
                    </span>
                    <h3 className="text-sm font-semibold text-white font-mono">{sig.name}</h3>
                    <span className="text-[10px] font-mono text-neutral-400 px-2 py-0.5 rounded bg-neutral-950 border border-neutral-800">
                      {sig.category}
                    </span>
                    <span className="text-[10px] font-mono text-neutral-500">
                      Arch: {sig.targetArch}
                    </span>
                  </div>

                  {/* Actions & Switch */}
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono text-neutral-400 mr-2">
                      Hits: <strong className="text-neutral-200">{sig.hitCount || 0}</strong>
                    </span>

                    <button
                      onClick={() => handleToggleEnable(sig.id)}
                      className={`px-2 py-0.5 rounded text-xs font-mono border transition-colors ${
                        sig.enabled
                          ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
                          : 'bg-neutral-900 text-neutral-500 border-neutral-800'
                      }`}
                    >
                      {sig.enabled ? 'ENABLED' : 'DISABLED'}
                    </button>

                    <button
                      onClick={() => handleOpenEditModal(sig)}
                      className="p-1.5 rounded-lg bg-neutral-900 text-neutral-400 hover:text-white border border-neutral-800"
                      title="Edit Signature"
                    >
                      <Edit2 className="w-3.5 h-3.5" />
                    </button>

                    <button
                      onClick={() => handleDelete(sig.id)}
                      className="p-1.5 rounded-lg bg-neutral-900 text-neutral-400 hover:text-red-400 border border-neutral-800"
                      title="Delete Signature"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <p className="text-xs text-neutral-400 mb-2 leading-relaxed">
                  {sig.description}
                </p>

                {/* Pattern Code Preview */}
                <div className="relative group mt-2">
                  <div className="p-2.5 rounded-lg bg-neutral-950 border border-neutral-800/80 font-mono text-xs text-neutral-300 overflow-x-auto whitespace-pre">
                    {sig.pattern}
                  </div>
                  <button
                    onClick={() => handleCopyPattern(sig.id, sig.pattern)}
                    className="absolute top-2 right-2 p-1 rounded bg-neutral-800 text-neutral-400 hover:text-white"
                    title="Copy pattern"
                  >
                    {copiedId === sig.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>

                {sig.wildcardMask && (
                  <div className="mt-1.5 text-[11px] font-mono text-neutral-400 flex items-center gap-2">
                    <span className="text-neutral-500">Wildcard Mask:</span>
                    <span className="text-indigo-300">{sig.wildcardMask}</span>
                  </div>
                )}

                <div className="flex items-center justify-between text-[11px] text-neutral-500 font-mono mt-2 pt-2 border-t border-neutral-850">
                  <span>Source: {sig.source} · v{sig.version}</span>
                  <span>Updated: {sig.lastUpdated}</span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Modal: Add / Edit Signature */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-neutral-900 border border-neutral-800 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-neutral-800 flex items-center justify-between">
              <h3 className="text-sm font-bold text-white">
                {editingSig ? 'Edit Signature Record' : 'Create New Signature Definition'}
              </h3>
              <button
                onClick={() => setIsAddModalOpen(false)}
                className="text-neutral-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4 overflow-y-auto text-xs flex-1">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-neutral-400 mb-1 font-medium">Signature Name</label>
                  <input
                    type="text"
                    value={formName}
                    onChange={(e) => setFormName(e.target.value)}
                    placeholder="e.g. glibc_memcpy_avx2"
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block text-neutral-400 mb-1 font-medium">Signature Type</label>
                  <select
                    value={formType}
                    onChange={(e) => setFormType(e.target.value as SignatureType)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white focus:outline-none"
                  >
                    <option value="flirt">FLIRT Library Signature</option>
                    <option value="yara">YARA Rule</option>
                    <option value="hash">Known Hash IOC</option>
                    <option value="byte_pattern">Raw Byte Pattern</option>
                    <option value="threat_actor">Threat Actor Attribution</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-neutral-400 mb-1 font-medium">Category</label>
                  <select
                    value={formCategory}
                    onChange={(e) => setFormCategory(e.target.value as SignatureCategory)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white focus:outline-none"
                  >
                    <option value="library">Library Runtime</option>
                    <option value="malware">Malware</option>
                    <option value="crypto">Cryptography</option>
                    <option value="packer">Packer / Obfuscator</option>
                    <option value="c2">Command & Control</option>
                    <option value="injection">Process Injection</option>
                  </select>
                </div>

                <div>
                  <label className="block text-neutral-400 mb-1 font-medium">Target Architecture</label>
                  <select
                    value={formArch}
                    onChange={(e) => setFormArch(e.target.value as any)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white focus:outline-none"
                  >
                    <option value="all">Universal / All</option>
                    <option value="x86_64">x86_64</option>
                    <option value="aarch64">aarch64 (ARM64)</option>
                    <option value="armv7">armv7</option>
                  </select>
                </div>

                <div>
                  <label className="block text-neutral-400 mb-1 font-medium">Severity</label>
                  <select
                    value={formSeverity}
                    onChange={(e) => setFormSeverity(e.target.value as any)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white focus:outline-none"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-neutral-400 mb-1 font-medium">Description</label>
                <input
                  type="text"
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  placeholder="Explain pattern significance or compiler provenance..."
                  className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-neutral-400 mb-1 font-medium">
                  Pattern Definition (Hex bytes with ?? wildcards, Hash, or YARA code)
                </label>
                <textarea
                  value={formPattern}
                  onChange={(e) => setFormPattern(e.target.value)}
                  rows={formType === 'yara' ? 8 : 3}
                  placeholder="55 48 89 e5 48 83 ec ?? 48 8b 45 ??..."
                  className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white font-mono focus:outline-none"
                />
              </div>

              {formType === 'flirt' && (
                <div>
                  <label className="block text-neutral-400 mb-1 font-medium">
                    Wildcard Mask (x = fixed opcode, ? = variable displacement)
                  </label>
                  <input
                    type="text"
                    value={formWildcardMask}
                    onChange={(e) => setFormWildcardMask(e.target.value)}
                    placeholder="xxxxxxx?xxxx?..."
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white font-mono focus:outline-none"
                  />
                </div>
              )}
            </div>

            <div className="p-4 border-t border-neutral-800 flex items-center justify-end gap-3 bg-neutral-950">
              <button
                onClick={() => setIsAddModalOpen(false)}
                className="px-4 py-2 rounded-lg text-xs text-neutral-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveSignature}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors"
              >
                {editingSig ? 'Save Changes' : 'Create Signature'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: AI Signature Synthesizer */}
      {isAiModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-neutral-900 border border-neutral-800 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-neutral-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-indigo-400" />
                <h3 className="text-sm font-bold text-white">
                  AI Signature Synthesizer (Gemini 3.8 Flash)
                </h3>
              </div>
              <button
                onClick={() => setIsAiModalOpen(false)}
                className="text-neutral-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4 overflow-y-auto text-xs flex-1">
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-neutral-400 mb-1 font-medium">Signature Type</label>
                  <select
                    value={aiSigType}
                    onChange={(e) => setAiSigType(e.target.value as SignatureType)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white focus:outline-none"
                  >
                    <option value="flirt">FLIRT Pattern + Mask</option>
                    <option value="yara">YARA Rule</option>
                    <option value="byte_pattern">Byte Pattern</option>
                  </select>
                </div>
                <div>
                  <label className="block text-neutral-400 mb-1 font-medium">Name</label>
                  <input
                    type="text"
                    value={aiSigName}
                    onChange={(e) => setAiSigName(e.target.value)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-neutral-400 mb-1 font-medium">Category</label>
                  <select
                    value={aiSigCategory}
                    onChange={(e) => setAiSigCategory(e.target.value as SignatureCategory)}
                    className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white focus:outline-none"
                  >
                    <option value="library">Library Runtime</option>
                    <option value="malware">Malware</option>
                    <option value="crypto">Cryptography</option>
                    <option value="packer">Packer</option>
                    <option value="injection">Process Injection</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-neutral-400 mb-1 font-medium">
                  Function or Assembly Instructions Context
                </label>
                <textarea
                  value={aiInstructions}
                  onChange={(e) => setAiInstructions(e.target.value)}
                  rows={4}
                  className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-3 py-2 text-white font-mono focus:outline-none"
                />
              </div>

              <button
                onClick={handleGenerateAiSignature}
                disabled={isAiGenerating}
                className="w-full py-2.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors flex items-center justify-center gap-2"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{isAiGenerating ? 'Synthesizing with Gemini...' : 'Synthesize Pattern'}</span>
              </button>

              {aiGeneratedOutput && (
                <div className="space-y-2 pt-2 border-t border-neutral-800">
                  <div className="flex items-center justify-between text-neutral-400 font-medium">
                    <span>Generated Signature Output</span>
                    <button
                      onClick={() => navigator.clipboard.writeText(aiGeneratedOutput)}
                      className="text-neutral-400 hover:text-white flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" />
                      <span>Copy</span>
                    </button>
                  </div>
                  <pre className="p-3 rounded-lg bg-neutral-950 border border-neutral-800 font-mono text-xs text-neutral-200 whitespace-pre-wrap max-h-48 overflow-y-auto">
                    {aiGeneratedOutput}
                  </pre>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-neutral-800 flex items-center justify-end gap-3 bg-neutral-950">
              <button
                onClick={() => setIsAiModalOpen(false)}
                className="px-4 py-2 rounded-lg text-xs text-neutral-400 hover:text-white"
              >
                Close
              </button>
              {aiGeneratedOutput && (
                <button
                  onClick={handleApplyAiSignature}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white transition-colors"
                >
                  Save to Database
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Modal: Import Signatures */}
      {isImportModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-neutral-900 border border-neutral-800 rounded-2xl w-full max-w-xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-neutral-800 flex items-center justify-between">
              <h3 className="text-sm font-bold text-white">Import Signatures (JSON Array)</h3>
              <button
                onClick={() => setIsImportModalOpen(false)}
                className="text-neutral-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-3 overflow-y-auto text-xs flex-1">
              <p className="text-neutral-400">
                Paste an exported JSON array of signature objects. Each entry must specify at least `name`, `type`, and `pattern`.
              </p>
              <textarea
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                rows={10}
                placeholder='[ { "name": "my_sig", "type": "flirt", "pattern": "55 48 89..." } ]'
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg p-3 text-white font-mono focus:outline-none"
              />
              {importStatus && (
                <div
                  className={`p-2 rounded font-mono text-xs ${
                    importStatus.startsWith('Error')
                      ? 'bg-red-950/40 text-red-300'
                      : 'bg-emerald-950/40 text-emerald-300'
                  }`}
                >
                  {importStatus}
                </div>
              )}
            </div>

            <div className="p-4 border-t border-neutral-800 flex items-center justify-end gap-3 bg-neutral-950">
              <button
                onClick={() => setIsImportModalOpen(false)}
                className="px-4 py-2 rounded-lg text-xs text-neutral-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleImportJson}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors"
              >
                Import
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
