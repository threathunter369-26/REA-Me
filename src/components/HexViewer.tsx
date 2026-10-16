import React, { useState } from 'react';
import {
  Binary,
  Search,
  Layers,
  ArrowRight,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { Artifact, AnalysisResult } from '../types/reverseEngineering';
import { malwareAnalysisService } from '../services/malwareAnalysisService';

interface HexViewerProps {
  artifact: Artifact;
  analysis: AnalysisResult;
}

export const HexViewer: React.FC<HexViewerProps> = ({
  artifact,
  analysis,
}) => {
  const [currentOffset, setCurrentOffset] = useState<number>(0x1000);
  const [searchQuery, setSearchQuery] = useState('');
  const [hoveredByte, setHoveredByte] = useState<{ offset: string; hex: string; dec: number; char: string } | null>(null);

  const hexRows = malwareAnalysisService.generateHexDump(currentOffset, 256);

  const handleNextPage = () => {
    setCurrentOffset(prev => prev + 256);
  };

  const handlePrevPage = () => {
    setCurrentOffset(prev => Math.max(0, prev - 256));
  };

  const handleJumpToSection = (sectionVirtualAddress: string) => {
    const parsed = parseInt(sectionVirtualAddress, 16);
    if (!isNaN(parsed)) {
      setCurrentOffset(parsed);
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-neutral-950 text-neutral-200 overflow-hidden font-mono select-none">
      {/* Hex Toolbar */}
      <div className="px-6 py-3 border-b border-neutral-900 bg-neutral-950/80 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-neutral-900 border border-neutral-800 text-neutral-300">
            <Binary className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <div className="text-sm font-semibold text-white font-sans flex items-center gap-2">
              <span>Hexadecimal Memory & Byte Inspector</span>
              <span className="text-[11px] text-neutral-400">({artifact.name})</span>
            </div>
            <p className="text-xs text-neutral-400 font-sans">
              Byte-level forensic analysis with section jumpers and ASCII correlation.
            </p>
          </div>
        </div>

        {/* Section Jumpers & Offset Controls */}
        <div className="flex items-center gap-2 text-xs">
          <div className="flex items-center gap-1 bg-neutral-900 px-2 py-1 rounded-lg border border-neutral-800">
            <span className="text-neutral-500 font-sans text-[11px]">Sections:</span>
            {analysis.sections.map(s => (
              <button
                key={s.name}
                onClick={() => handleJumpToSection(s.virtualAddress)}
                className="px-2 py-0.5 rounded bg-neutral-950 hover:bg-neutral-800 text-neutral-300 hover:text-white transition-colors text-[10px]"
              >
                {s.name}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 bg-neutral-900 p-1 rounded-lg border border-neutral-800">
            <button
              onClick={handlePrevPage}
              disabled={currentOffset === 0}
              className="p-1 rounded hover:bg-neutral-800 text-neutral-400 hover:text-white disabled:opacity-40"
              title="Previous 256 bytes"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2 text-[11px] text-cyan-400">
              0x{currentOffset.toString(16).padStart(8, '0').toUpperCase()}
            </span>
            <button
              onClick={handleNextPage}
              className="p-1 rounded hover:bg-neutral-800 text-neutral-400 hover:text-white"
              title="Next 256 bytes"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Hex Dump Grid Stage */}
      <div className="flex-1 overflow-auto p-6 bg-neutral-950 text-xs">
        <div className="max-w-4xl mx-auto rounded-xl border border-neutral-850 bg-neutral-900/30 p-4 space-y-1 shadow-2xl">
          {/* Header Row */}
          <div className="flex items-center pb-2 border-b border-neutral-800 text-neutral-500 text-[11px]">
            <span className="w-28 shrink-0">Offset (RVA)</span>
            <div className="flex-1 grid grid-cols-16 gap-1.5 text-center font-bold">
              {['00','01','02','03','04','05','06','07','08','09','0A','0B','0C','0D','0E','0F'].map(h => (
                <span key={h}>{h}</span>
              ))}
            </div>
            <span className="w-36 text-center shrink-0 border-l border-neutral-800 ml-4 pl-4">
              Decoded ASCII
            </span>
          </div>

          {/* Byte Rows */}
          {hexRows.map((row, rowIdx) => (
            <div
              key={rowIdx}
              className="flex items-center hover:bg-neutral-900/80 py-0.5 rounded px-1 transition-colors"
            >
              <span className="w-28 text-cyan-400/80 shrink-0 select-all">{row.offset}</span>

              {/* 16 Hex Bytes */}
              <div className="flex-1 grid grid-cols-16 gap-1.5 text-center">
                {row.hex.map((b, byteIdx) => {
                  const dec = parseInt(b, 16);
                  const isNull = b === '00';
                  const isAscii = dec >= 32 && dec <= 126;
                  return (
                    <span
                      key={byteIdx}
                      onMouseEnter={() =>
                        setHoveredByte({
                          offset: `${row.offset}+0x${byteIdx.toString(16)}`,
                          hex: b,
                          dec,
                          char: isAscii ? String.fromCharCode(dec) : '.',
                        })
                      }
                      className={`cursor-crosshair rounded py-0.2 hover:bg-indigo-600 hover:text-white transition-colors ${
                        isNull ? 'text-neutral-600' : isAscii ? 'text-neutral-200' : 'text-amber-400'
                      }`}
                    >
                      {b}
                    </span>
                  );
                })}
              </div>

              {/* ASCII Output */}
              <span className="w-36 text-neutral-400 tracking-wider shrink-0 border-l border-neutral-850 ml-4 pl-4 select-all">
                {row.ascii}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Footer Byte Inspector Drawer */}
      <div className="px-6 py-2 border-t border-neutral-900 bg-neutral-950/90 flex items-center justify-between text-xs text-neutral-400 font-sans">
        <div className="flex items-center gap-6 font-mono text-[11px]">
          {hoveredByte ? (
            <>
              <div>
                Location: <span className="text-cyan-400">{hoveredByte.offset}</span>
              </div>
              <div>
                Hex: <span className="text-amber-400">0x{hoveredByte.hex}</span>
              </div>
              <div>
                Dec: <span className="text-neutral-200">{hoveredByte.dec}</span>
              </div>
              <div>
                ASCII: <span className="text-emerald-400 font-bold">{hoveredByte.char}</span>
              </div>
            </>
          ) : (
            <span>Hover any byte to inspect relative offset, binary bitmask, and ASCII representation.</span>
          )}
        </div>

        <div className="text-[11px] text-neutral-500">
          Showing 256 bytes per window · Total File Size: {(artifact.size / 1024).toFixed(1)} KB
        </div>
      </div>
    </div>
  );
};
