import React from 'react';

interface BrandLogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showText?: boolean;
  className?: string;
}

export const BrandLogo: React.FC<BrandLogoProps> = ({
  size = 'md',
  showText = false,
  className = '',
}) => {
  const sizeMap = {
    sm: 'w-6 h-6',
    md: 'w-9 h-9',
    lg: 'w-14 h-14',
    xl: 'w-20 h-20',
  };

  const barWidthMap = {
    sm: 'w-[3px] h-3.5',
    md: 'w-[4px] h-5',
    lg: 'w-[6px] h-8',
    xl: 'w-[9px] h-12',
  };

  const barGapMap = {
    sm: 'gap-1',
    md: 'gap-1.5',
    lg: 'gap-2.5',
    xl: 'gap-3.5',
  };

  return (
    <div className={`flex items-center gap-2.5 select-none ${className}`}>
      {/* Signature Eleven Rounded Gradient Squircle */}
      <div
        className={`${sizeMap[size]} relative rounded-2xl flex items-center justify-center shadow-lg transition-transform hover:scale-105 overflow-hidden`}
        style={{
          background: 'linear-gradient(135deg, #1d4ed8 0%, #2563eb 20%, #7c3aed 55%, #c026d3 85%, #ec4899 100%)',
          boxShadow: '0 8px 24px -4px rgba(124, 58, 237, 0.4), inset 0 1px 1px rgba(255, 255, 255, 0.4)',
        }}
      >
        {/* Subtle glass reflection highlight */}
        <div className="absolute inset-0 bg-gradient-to-b from-white/20 via-transparent to-black/20 pointer-events-none" />

        {/* The Eleven vertical bars */}
        <div className={`relative flex items-center ${barGapMap[size]}`}>
          <div
            className={`${barWidthMap[size]} rounded-full bg-white shadow-[0_0_8px_rgba(255,255,255,0.8)]`}
          />
          <div
            className={`${barWidthMap[size]} rounded-full bg-white shadow-[0_0_8px_rgba(255,255,255,0.8)]`}
          />
        </div>
      </div>

      {showText && (
        <div className="flex flex-col">
          <span className="font-bold tracking-tight text-white font-sans text-base leading-tight">
            Eleven
          </span>
          <span className="text-[11px] text-neutral-400 font-medium tracking-wide">
            Reverse Engineering
          </span>
        </div>
      )}
    </div>
  );
};
