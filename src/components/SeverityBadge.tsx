import React from 'react';
import { Severity } from '../types';
import { AlertCircle, CheckCircle2, Info, AlertTriangle } from 'lucide-react';

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export function SeverityBadge({ severity, className = '' }: SeverityBadgeProps) {
  const getSeverityStyles = (severity: Severity) => {
    switch (severity) {
      case 'Safe':
        return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
      case 'Attention':
        return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
      case 'Warning':
        return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
      case 'Critical':
        return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
    }
  };

  const getSeverityIcon = (severity: Severity) => {
    switch (severity) {
      case 'Safe':
        return <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />;
      case 'Attention':
        return <Info className="w-3.5 h-3.5 mr-1.5" />;
      case 'Warning':
        return <AlertTriangle className="w-3.5 h-3.5 mr-1.5" />;
      case 'Critical':
        return <AlertCircle className="w-3.5 h-3.5 mr-1.5" />;
    }
  };

  return (
    <div className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${getSeverityStyles(severity)} ${className}`}>
      {getSeverityIcon(severity)}
      {severity}
    </div>
  );
}

export function SeverityIcon({ severity, className = '' }: { severity: Severity, className?: string }) {
   switch (severity) {
      case 'Safe':
        return <CheckCircle2 className={`text-emerald-500 ${className}`} />;
      case 'Attention':
        return <Info className={`text-blue-400 ${className}`} />;
      case 'Warning':
        return <AlertTriangle className={`text-amber-500 ${className}`} />;
      case 'Critical':
        return <AlertCircle className={`text-rose-500 ${className}`} />;
    }
}
