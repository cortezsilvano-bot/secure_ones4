import React, { useState } from 'react';
import { Finding } from '../types';
import { ChevronDown, ChevronUp, Wrench, FileCode2, ShieldAlert, ShieldCheck, Info } from 'lucide-react';

export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  const getSeverityIcon = () => {
    if (finding.status === 'resolved') return <ShieldCheck className="w-4 h-4 mr-1.5" />;
    switch (finding.severity) {
      case 'Critical':
      case 'Warning':
        return <ShieldAlert className="w-4 h-4 mr-1.5" />;
      case 'Attention':
        return <Info className="w-4 h-4 mr-1.5" />;
      case 'Safe':
        return <ShieldCheck className="w-4 h-4 mr-1.5" />;
      default:
        return <Info className="w-4 h-4 mr-1.5" />;
    }
  };

  const getSeverityColor = () => {
    if (finding.status === 'resolved') return 'text-emerald-500';
    switch (finding.severity) {
      case 'Critical': return 'text-rose-500';
      case 'Warning': return 'text-amber-500';
      case 'Attention': return 'text-blue-400';
      case 'Safe': return 'text-emerald-500';
      default: return 'text-slate-400';
    }
  };

  const getStatusBadgeStyles = () => {
    if (finding.status === 'resolved') return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
    if (finding.status === 'dismissed') return 'text-slate-400 bg-slate-400/10 border-slate-400/20';
    if (finding.status === 'allowlisted') return 'text-purple-400 bg-purple-400/10 border-purple-400/20';
    
    // Status is 'open', determine color based on severity
    switch (finding.severity) {
      case 'Critical': return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
      case 'Warning': return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
      case 'Attention': return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
      case 'Safe': return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
      default: return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
    }
  };

  return (
    <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5 hover:bg-slate-800/50 transition-colors">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`flex items-center font-semibold text-sm tracking-wide ${getSeverityColor()}`}>
            {getSeverityIcon()}
            {finding.severity}
          </div>
          <span className="text-slate-600 text-sm">•</span>
          <span className="text-slate-300 text-sm font-medium">{finding.category}</span>
          <span className="text-slate-600 text-sm">•</span>
          <span className="text-slate-500 text-xs font-mono">ID: {finding.id}</span>
        </div>
        <div className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border uppercase tracking-wider ${getStatusBadgeStyles()}`}>
          {finding.status}
        </div>
      </div>

      <h3 className="text-lg font-medium text-slate-200 mb-1">{finding.what_happened}</h3>
      <p className="text-slate-400 text-sm mb-4">{finding.why_it_matters}</p>

      {finding.recommended_action && finding.status === 'open' && (
        <div className="flex items-center gap-4 mt-4 p-4 bg-slate-900/50 rounded-lg border border-slate-700/30">
          <div className="flex-1">
            <h4 className="text-xs uppercase tracking-wider text-slate-500 mb-1">Recommended Action</h4>
            <p className="text-sm text-slate-300">{finding.recommended_action}</p>
          </div>
          {finding.auto_fix && (
            <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors">
              <Wrench className="w-4 h-4" />
              Auto-fix
            </button>
          )}
        </div>
      )}

      {finding.evidence && finding.evidence.length > 0 && (
        <div className="mt-4 pt-4 border-t border-slate-700/50">
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
          >
            <FileCode2 className="w-4 h-4" />
            {expanded ? 'Hide evidence' : 'View raw evidence'}
            {expanded ? <ChevronUp className="w-4 h-4 ml-1" /> : <ChevronDown className="w-4 h-4 ml-1" />}
          </button>

          {expanded && (
            <div className="mt-3 bg-slate-950 rounded-lg p-4 border border-slate-800 font-mono text-xs text-slate-400 overflow-x-auto leading-relaxed">
              {finding.evidence.map((line, i) => (
                <div key={i} className="whitespace-pre">{line}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
