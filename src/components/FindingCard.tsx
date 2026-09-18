import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileCode2,
  Info,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from 'lucide-react';

import type { Confidence, Finding, FixRisk, Severity } from '../types';

const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: 'text-rose-500',
  Warning: 'text-amber-500',
  Attention: 'text-blue-400',
  Safe: 'text-emerald-500',
};

const STATUS_BADGE: Record<string, string> = {
  resolved: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20',
  dismissed: 'text-slate-400 bg-slate-400/10 border-slate-400/20',
  allowlisted: 'text-purple-400 bg-purple-400/10 border-purple-400/20',
};

const CONFIDENCE_LABEL: Record<Confidence, string> = {
  confirmed: 'Confirmed',
  likely: 'Likely',
  potential: 'Potential',
};

const FIX_RISK_NOTE: Record<FixRisk, string> = {
  safe: 'Reversible, with no side effects beyond this setting.',
  caution: 'Changes system configuration. A restore point is taken first.',
  manual: 'SENTRY will not change this for you.',
};

function severityIcon(finding: Finding) {
  if (finding.status === 'resolved') return ShieldCheck;
  switch (finding.severity) {
    case 'Critical':
    case 'Warning':
      return ShieldAlert;
    case 'Safe':
      return ShieldCheck;
    default:
      return Info;
  }
}

export function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  const Icon = severityIcon(finding);
  const color = finding.status === 'resolved' ? 'text-emerald-500' : SEVERITY_COLOR[finding.severity];
  const statusStyle =
    STATUS_BADGE[finding.status] ??
    `${SEVERITY_COLOR[finding.severity]} bg-slate-400/10 border-slate-700/50`;

  return (
    <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5 hover:bg-slate-800/50 transition-colors">
      <div className="flex items-start justify-between mb-4 gap-4">
        <div className="flex items-center gap-3 flex-wrap min-w-0">
          <div className={`flex items-center font-semibold text-sm tracking-wide ${color}`}>
            <Icon className="w-4 h-4 mr-1.5 shrink-0" />
            {finding.severity}
          </div>
          <span className="text-slate-600 text-sm">&bull;</span>
          <span className="text-slate-300 text-sm font-medium">{finding.category}</span>
          <span className="text-slate-600 text-sm">&bull;</span>
          {/* The rule id, not a decorative ticket number: it identifies the
              exact check in the rule set that produced this. */}
          <span className="text-slate-500 text-xs font-mono">{finding.ruleId}</span>
          <span className="text-slate-600 text-sm">&bull;</span>
          <span className="text-slate-500 text-xs">
            {CONFIDENCE_LABEL[finding.confidence]}
          </span>
        </div>
        <div
          className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border uppercase tracking-wider shrink-0 ${statusStyle}`}
        >
          {finding.status}
        </div>
      </div>

      <h3 className="text-lg font-medium text-slate-200 mb-1">{finding.title}</h3>
      <p className="text-slate-300 text-sm mb-2">{finding.whatHappened}</p>
      <p className="text-slate-400 text-sm mb-4">{finding.whyItMatters}</p>

      {finding.affectedAsset && (
        <p className="text-slate-500 text-xs mb-4">
          Affects: <span className="font-mono text-slate-400">{finding.affectedAsset}</span>
        </p>
      )}

      {finding.remediation && finding.status === 'open' && (
        <div className="flex items-center gap-4 mt-4 p-4 bg-slate-900/50 rounded-lg border border-slate-700/30">
          <div className="flex-1 min-w-0">
            <h4 className="text-xs uppercase tracking-wider text-slate-500 mb-1">
              Recommended action
            </h4>
            <p className="text-sm text-slate-300">{finding.remediation}</p>
            {finding.autoFixRisk && (
              <p className="text-xs text-slate-500 mt-1.5">{FIX_RISK_NOTE[finding.autoFixRisk]}</p>
            )}
          </div>
          {finding.autoFix && (
            <button
              disabled
              title="Automatic fixes arrive in a later version."
              className="flex items-center gap-2 px-4 py-2 bg-slate-800 text-slate-500 border border-slate-700 rounded-lg text-sm font-medium cursor-not-allowed shrink-0"
            >
              <Wrench className="w-4 h-4" />
              Auto-fix
            </button>
          )}
        </div>
      )}

      {finding.evidence.length > 0 && (
        <div className="mt-4 pt-4 border-t border-slate-700/50">
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
          >
            <FileCode2 className="w-4 h-4" />
            {expanded ? 'Hide evidence' : 'View raw evidence'}
            {expanded ? (
              <ChevronUp className="w-4 h-4 ml-1" />
            ) : (
              <ChevronDown className="w-4 h-4 ml-1" />
            )}
          </button>

          {expanded && (
            <div className="mt-3 bg-slate-950 rounded-lg p-4 border border-slate-800 font-mono text-xs text-slate-400 overflow-x-auto leading-relaxed">
              {finding.evidence.map((line, i) => (
                <div key={i} className="whitespace-pre">
                  {line}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {finding.references.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-3">
          {finding.references.map((url) => (
            <a
              key={url}
              href={url}
              target="_blank"
              rel="noreferrer noopener"
              className="text-xs text-blue-400 hover:text-blue-300 inline-flex items-center gap-1"
            >
              <ExternalLink className="w-3 h-3" />
              {url}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
