import React from 'react';
import { ShieldCheck, Lock } from 'lucide-react';

interface LegalBannerProps {
  authorizedScope?: string;
  authorizedBy?: string;
}

export const LegalBanner: React.FC<LegalBannerProps> = ({
  authorizedScope = '*.payments.lab.internal',
  authorizedBy = 'Authorized SecOps Team',
}) => {
  return (
    <div className="bg-slate-950/90 border-b border-cyan-950/60 px-4 py-2 text-xs text-slate-300">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>
            <strong className="text-cyan-300">Defensive Authorization Scope:</strong> Security finding ingestion and attack-path analysis are strictly restricted to authorized assets ({authorizedScope}).
          </span>
        </div>
        <div className="flex items-center space-x-2 text-slate-400 font-mono text-[11px]">
          <Lock className="w-3 h-3 text-emerald-400" />
          <span>Signed Off: {authorizedBy}</span>
        </div>
      </div>
    </div>
  );
};
