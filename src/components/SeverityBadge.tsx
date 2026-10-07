import React from 'react';
import { AlertCircle, CheckCircle2, HelpCircle, Info, AlertTriangle } from 'lucide-react';

import type { DisplaySeverity } from '../types';

interface SeverityBadgeProps {
  severity: DisplaySeverity;
  /** Overrides the severity name as the badge's text. */
  label?: string;
  className?: string;
}

const STYLES: Record<DisplaySeverity, string> = {
  Safe: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20',
  Attention: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
  Warning: 'text-amber-500 bg-amber-500/10 border-amber-500/20',
  Critical: 'text-rose-500 bg-rose-500/10 border-rose-500/20',
  // Deliberately grey, not green: an unknown must never read as reassuring.
  Unknown: 'text-slate-400 bg-slate-400/10 border-slate-400/20',
};

const ICON_COLORS: Record<DisplaySeverity, string> = {
  Safe: 'text-emerald-500',
  Attention: 'text-blue-400',
  Warning: 'text-amber-500',
  Critical: 'text-rose-500',
  Unknown: 'text-slate-400',
};

const ICONS: Record<DisplaySeverity, typeof CheckCircle2> = {
  Safe: CheckCircle2,
  Attention: Info,
  Warning: AlertTriangle,
  Critical: AlertCircle,
  Unknown: HelpCircle,
};

export function SeverityBadge({ severity, label, className = '' }: SeverityBadgeProps) {
  const Icon = ICONS[severity];

  return (
    <div
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${STYLES[severity]} ${className}`}
    >
      <Icon className="w-3.5 h-3.5 mr-1.5 shrink-0" />
      {label ?? severity}
    </div>
  );
}

export function SeverityIcon({
  severity,
  className = '',
}: {
  severity: DisplaySeverity;
  className?: string;
}) {
  const Icon = ICONS[severity];
  return <Icon className={`${ICON_COLORS[severity]} ${className}`} />;
}
