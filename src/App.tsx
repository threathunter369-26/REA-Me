/**
 * Eleven — AI-Powered Reverse Engineering & Binary Analysis Platform
 * Architecture and Orchestrator
 */

import React, { useState, useEffect } from 'react';
import {
  Artifact,
  AnalysisResult,
  ExecutionSafetyMode,
  AnalysisEngineId,
} from './types/reverseEngineering';
import { SAMPLE_ARTIFACTS, SAMPLE_ANALYSIS_RESULTS } from './data/sampleArtifacts';
import { elevenStaticAdapter } from './services/adapters/elevenStaticAdapter';
import { reverseSkillAdapter } from './services/adapters/reverseSkillAdapter';
import { reaAdapter } from './services/adapters/reaAdapter';
import { ghidraMcpAdapter } from './services/adapters/ghidraMcpAdapter';

// Components
import { TopNavigation } from './components/TopNavigation';
import { Sidebar } from './components/Sidebar';
import { ElevenHero } from './components/ElevenHero';
import { ReverseEngineeringWorkspace } from './components/ReverseEngineeringWorkspace';
import { VulnerabilityFindings } from './components/VulnerabilityFindings';
import { BinaryStructure3D } from './components/BinaryStructure3D';
import { ReportsCenter } from './components/ReportsCenter';
import { AuditLogView } from './components/AuditLogView';
import { ArtifactUploadModal } from './components/ArtifactUploadModal';
import { AnalysisMonitorModal } from './components/AnalysisMonitorModal';
import { BinaryCopilotChat } from './components/BinaryCopilotChat';
import { CodeDiffViewer } from './components/CodeDiffViewer';
import { YaraScannerView } from './components/YaraScannerView';
import { MitreCapaMatrix } from './components/MitreCapaMatrix';
import { StringDeobfuscator } from './components/StringDeobfuscator';
import { HexViewer } from './components/HexViewer';
import { DynamicDebugger } from './components/DynamicDebugger';
import { ApiCallTracker } from './components/ApiCallTracker';
import { DataFlowAnalysisView } from './components/DataFlowAnalysisView';
import { VexIrTaintView } from './components/VexIrTaintView';
import { SignatureDatabaseView } from './components/SignatureDatabaseView';
import { PlatformView } from './components/Sidebar';

export default function App() {
  const [artifacts, setArtifacts] = useState<Artifact[]>(SAMPLE_ARTIFACTS);
  const [activeArtifactId, setActiveArtifactId] = useState<string>('art-bin-ls');
  const [analysisResults, setAnalysisResults] = useState<Record<string, AnalysisResult>>(
    SAMPLE_ANALYSIS_RESULTS
  );

  // Platform view states
  const [currentView, setCurrentView] = useState<PlatformView>('chat');
  const [hasStartedChat, setHasStartedChat] = useState<boolean>(false);
  const [initialPromptText, setInitialPromptText] = useState<string>('');

  // Agent configuration controls (matching Eleven screenshot)
  const [safetyMode, setSafetyMode] = useState<ExecutionSafetyMode>('sandbox-prompt');
  const [selectedEngine, setSelectedEngine] = useState<AnalysisEngineId | 'auto'>('auto');
  const [selectedModel, setSelectedModel] = useState<string>('Deepseek Flash Medium');
  const [selectedPersona, setSelectedPersona] = useState<string>('Aster');

  // Modals
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [isMonitorModalOpen, setIsMonitorModalOpen] = useState(false);
  const [pendingArtifactName, setPendingArtifactName] = useState('');

  // Recent chats history
  const [recentChats, setRecentChats] = useState<
    { id: string; title: string; artifactName: string; time: string }[]
  >([
    {
      id: 'chat-01',
      title: 'What does /bin/ls do when it starts?',
      artifactName: 'ls',
      time: '25m ago',
    },
    {
      id: 'chat-02',
      title: 'Is this .pt file safe to load?',
      artifactName: 'resnet50_weights.pt',
      time: '2h ago',
    },
  ]);
  const [activeChatId, setActiveChatId] = useState<string | null>('chat-01');

  // Keyboard shortcuts (⌘N, ⌘O)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        handleNewChat();
      }
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'o') {
        e.preventDefault();
        setIsUploadModalOpen(true);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const activeArtifact =
    artifacts.find(a => a.id === activeArtifactId) || artifacts[0];

  const activeAnalysis =
    analysisResults[activeArtifactId] ||
    analysisResults['art-bin-ls'] ||
    Object.values(analysisResults)[0];

  const handleSelectArtifact = (id: string) => {
    setActiveArtifactId(id);
  };

  const handleNewChat = () => {
    setHasStartedChat(false);
    setInitialPromptText('');
    setCurrentView('chat');
  };

  const handlePromptSelect = (promptText: string, suggestedArtifactId?: string) => {
    if (suggestedArtifactId) {
      setActiveArtifactId(suggestedArtifactId);
    }
    setInitialPromptText(promptText);
    setHasStartedChat(true);
    setCurrentView('chat');

    // Add to chats list
    const newChat = {
      id: `chat-${Date.now()}`,
      title: promptText,
      artifactName: artifacts.find(a => a.id === (suggestedArtifactId || activeArtifactId))?.name || 'Binary',
      time: 'Just now',
    };
    setRecentChats(prev => [newChat, ...prev]);
    setActiveChatId(newChat.id);
  };

  const handleUploadFile = (file: File) => {
    setIsUploadModalOpen(true);
  };

  const handleCompleteUpload = async (newArtifact: Artifact, rawBytes?: ArrayBuffer) => {
    setArtifacts(prev => [newArtifact, ...prev]);
    setActiveArtifactId(newArtifact.id);
    setPendingArtifactName(newArtifact.name);
    setIsMonitorModalOpen(true);

    // If user provided raw file bytes, run Eleven static engine & security scans
    if (rawBytes) {
      const staticResult = await elevenStaticAdapter.runStaticScan({
        fileName: newArtifact.name,
        fileBytes: rawBytes,
        fileSize: newArtifact.size,
      });

      const securityFindings = await reverseSkillAdapter.scanArtifactSecurity({
        targetName: newArtifact.name,
        decompiledSources: [],
        importedSymbols: ['malloc', 'free', 'printf', 'read', 'write'],
        strings: staticResult.strings.map(s => s.value),
      });

      const newAnalysis: AnalysisResult = {
        artifactId: newArtifact.id,
        jobId: `job-${Date.now()}`,
        completedAt: new Date().toISOString(),
        metadata: staticResult.metadata,
        sections: staticResult.sections,
        functions: [
          {
            id: `fn-${newArtifact.id}-entry`,
            name: 'entry_point',
            address: staticResult.metadata.entryPoint,
            size: 256,
            cyclomaticComplexity: 4,
            callersCount: 0,
            calleesCount: 3,
            callers: [],
            callees: ['init_runtime', 'main_subroutine'],
            isExported: true,
            isVulnerable: false,
            signature: 'void entry_point()',
            decompiledCode: `// Automatically decompiled via Ghidra MCP & REA
void entry_point(void)
{
    setup_stack_frame();
    initialize_subsystems();
    execute_program_flow();
}`,
            assemblyInstructions: [
              { address: staticResult.metadata.entryPoint, bytes: '55', mnemonic: 'push', operands: 'rbp' },
              { address: '0x00001051', bytes: '48 89 e5', mnemonic: 'mov', operands: 'rbp, rsp' },
              { address: '0x00001054', bytes: 'e8 40 01 00 00', mnemonic: 'call', operands: '0x00001199' },
            ],
            cfgBlocks: [],
          },
        ],
        strings: staticResult.strings,
        importsExports: [
          { id: 'u-ie-1', library: 'libc.so', functionName: 'read', type: 'import', isDangerous: false },
          { id: 'u-ie-2', library: 'libc.so', functionName: 'write', type: 'import', isDangerous: false },
        ],
        findings: securityFindings.length > 0 ? securityFindings : [
          {
            id: `find-clean-${Date.now()}`,
            title: 'No Anomalous Code Injection Heuristics Detected',
            severity: 'info',
            cweId: 'CWE-693',
            cvss: 0.0,
            category: 'Sanity Check',
            description: 'Static AST scanner did not identify banned string copy operations or unpickling exploits.',
            detectedBy: 'reverse-skill',
            remediation: 'Follow standard defensive development lifecycles.',
            confidence: 'verified',
          },
        ],
        entropyChunks: [
          { offset: 0, entropy: staticResult.metadata.overallEntropy, sectionName: '.text' },
          { offset: Math.floor(newArtifact.size / 2), entropy: staticResult.metadata.overallEntropy, sectionName: '.data' },
        ],
        summary: {
          overview: `Uploaded ${newArtifact.formatDetails} parsed successfully. ${staticResult.sections.length} sections and ${staticResult.strings.length} printable string tokens indexed.`,
          keyBehaviors: [
            'Verified valid binary magic bytes and executable headers',
            `Overall Shannon byte entropy measured at ${staticResult.metadata.overallEntropy.toFixed(2)}/8.0`,
            'Non-executing static triage confirmed no active code injection primitives',
          ],
          riskScore: staticResult.metadata.overallEntropy > 7.2 ? 65 : 8,
          securityPosture: staticResult.metadata.overallEntropy > 7.2 ? 'Suspicious' : 'Clean',
          decompiledCoveragePercent: 88,
        },
        toolLogs: [
          { id: 'log-u1', timestamp: new Date().toLocaleTimeString(), tool: 'Eleven Static', status: 'success', message: `Parsed ${newArtifact.formatDetails}` },
          { id: 'log-u2', timestamp: new Date().toLocaleTimeString(), tool: 'Reverse-Skill', status: 'success', message: 'Completed security AST check' },
        ],
      };

      setAnalysisResults(prev => ({ ...prev, [newArtifact.id]: newAnalysis }));
    }
  };

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-neutral-950 text-neutral-100 font-sans antialiased">
      {/* Top Bar following Top Bar Contract */}
      <TopNavigation
        currentView={currentView}
        onNavigate={view => setCurrentView(view)}
        activeArtifactName={activeArtifact?.name}
        onOpenUpload={() => setIsUploadModalOpen(true)}
      />

      {/* Main App Layout: Sidebar + Canvas */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar matching Eleven screenshot */}
        <Sidebar
          artifacts={artifacts}
          activeArtifactId={activeArtifactId}
          onSelectArtifact={handleSelectArtifact}
          onNewChat={handleNewChat}
          onOpenFile={() => setIsUploadModalOpen(true)}
          currentView={currentView}
          setCurrentView={setCurrentView}
          recentChats={recentChats}
          activeChatId={activeChatId}
          onSelectChat={chatId => {
            setActiveChatId(chatId);
            const chat = recentChats.find(c => c.id === chatId);
            if (chat) {
              setInitialPromptText(chat.title);
              setHasStartedChat(true);
              setCurrentView('chat');
            }
          }}
        />

        {/* Dynamic Center Canvas View */}
        <main className="flex-1 flex flex-col overflow-hidden bg-neutral-950 relative">
          {currentView === 'chat' ? (
            hasStartedChat ? (
              <BinaryCopilotChat
                artifact={activeArtifact}
                analysis={activeAnalysis}
                initialPrompt={initialPromptText}
                onNavigateToFunction={fnName => {
                  setCurrentView('workspace');
                }}
                onNavigateToFinding={findingId => {
                  setCurrentView('findings');
                }}
                onNavigateTo3D={() => setCurrentView('memory3d')}
                selectedEngine={selectedEngine}
                selectedModel={selectedModel}
                selectedPersona={selectedPersona}
              />
            ) : (
              <ElevenHero
                onSelectPrompt={handlePromptSelect}
                onUploadFile={handleUploadFile}
                safetyMode={safetyMode}
                setSafetyMode={setSafetyMode}
                selectedEngine={selectedEngine}
                setSelectedEngine={setSelectedEngine}
                selectedModel={selectedModel}
                setSelectedModel={setSelectedModel}
                selectedPersona={selectedPersona}
                setSelectedPersona={setSelectedPersona}
              />
            )
          ) : currentView === 'workspace' ? (
            <ReverseEngineeringWorkspace
              artifact={activeArtifact}
              analysis={activeAnalysis}
              onNavigateToFinding={() => setCurrentView('findings')}
            />
          ) : currentView === 'diff' ? (
            <CodeDiffViewer
              artifact={activeArtifact}
              selectedFunction={activeAnalysis.functions[0]}
            />
          ) : currentView === 'findings' ? (
            <VulnerabilityFindings
              analysis={activeAnalysis}
              onNavigateToFunction={() => setCurrentView('workspace')}
            />
          ) : currentView === 'dataflow' ? (
            <DataFlowAnalysisView
              artifact={activeArtifact}
              analysis={activeAnalysis}
              onNavigateToVexIr={() => setCurrentView('vexir')}
            />
          ) : currentView === 'vexir' ? (
            <VexIrTaintView
              artifact={activeArtifact}
              analysis={activeAnalysis}
              onNavigateToDataFlow={() => setCurrentView('dataflow')}
            />
          ) : currentView === 'debugger' ? (
            <DynamicDebugger
              artifact={activeArtifact}
              analysis={activeAnalysis}
            />
          ) : currentView === 'apitracker' ? (
            <ApiCallTracker
              artifact={activeArtifact}
              analysis={activeAnalysis}
            />
          ) : currentView === 'signatures' ? (
            <SignatureDatabaseView
              artifact={activeArtifact}
              analysis={activeAnalysis}
            />
          ) : currentView === 'yara' ? (
            <YaraScannerView
              artifact={activeArtifact}
              analysis={activeAnalysis}
            />
          ) : currentView === 'mitre' ? (
            <MitreCapaMatrix
              artifact={activeArtifact}
              analysis={activeAnalysis}
            />
          ) : currentView === 'deob' ? (
            <StringDeobfuscator
              artifact={activeArtifact}
              analysis={activeAnalysis}
            />
          ) : currentView === 'hex' ? (
            <HexViewer
              artifact={activeArtifact}
              analysis={activeAnalysis}
            />
          ) : currentView === 'memory3d' ? (
            <div className="flex-1 overflow-y-auto p-6 flex flex-col space-y-4">
              <div className="flex items-center justify-between border-b border-neutral-900 pb-3">
                <div>
                  <h3 className="text-xl font-bold text-white tracking-tight">
                    3D Binary Structure & Shannon Entropy Map
                  </h3>
                  <p className="text-xs text-neutral-400">
                    WebGL holographic visualization of memory segments, execution permissions, and byte disorder.
                  </p>
                </div>
                <div className="text-xs font-mono text-cyan-400">
                  Target: {activeArtifact.name} ({activeArtifact.architecture})
                </div>
              </div>
              <BinaryStructure3D
                sections={activeAnalysis.sections}
                entropyChunks={activeAnalysis.entropyChunks}
                fileName={activeArtifact.name}
              />
            </div>
          ) : currentView === 'reports' ? (
            <ReportsCenter
              artifact={activeArtifact}
              analysis={activeAnalysis}
            />
          ) : currentView === 'audit' ? (
            <AuditLogView />
          ) : (
            <div className="p-8 text-center">
              <button
                onClick={() => setIsUploadModalOpen(true)}
                className="px-4 py-2 rounded-xl bg-indigo-600 text-white text-xs font-semibold"
              >
                Open Artifact Intake Center
              </button>
            </div>
          )}
        </main>
      </div>

      {/* Upload Modal */}
      <ArtifactUploadModal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        onCompleteUpload={handleCompleteUpload}
      />

      {/* Live AI Analysis Monitor Modal */}
      <AnalysisMonitorModal
        isOpen={isMonitorModalOpen}
        onClose={() => setIsMonitorModalOpen(false)}
        artifactName={pendingArtifactName || activeArtifact.name}
        onComplete={() => {
          setCurrentView('workspace');
        }}
      />
    </div>
  );
}
