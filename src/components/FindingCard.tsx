import React, { useState } from 'react';
import {
  Check,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileCode2,
  Info,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from 'lucide-react';

import { applyFix, openHelpTarget } from '../services/ipc';
import type { Confidence, Finding, FixResult, FixRisk, HelpTarget, Severity } from '../types';

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

// Describes what pressing "Fix this" will do, so it is only ever shown beside
// that button. Printed under advice SENTRY cannot act on, "reversible, with no
// side effects" describes a fix that does not exist.
const FIX_RISK_NOTE: Record<FixRisk, string> = {
  safe: 'Reversible, with no side effects beyond this setting.',
  caution: 'Changes system configuration. A restore point is taken first.',
};

const HELP_LABEL: Record<HelpTarget, string> = {
  virus_protection_settings: 'Open virus protection settings',
  current_threats: 'Open current threats',
  protection_updates: 'Open protection updates',
  firewall_and_network: 'Open firewall settings',
  windows_update: 'Open Windows Update',
  remote_desktop: 'Open Remote Desktop settings',
  windows_features: 'Open Windows Features',
  user_account_control: 'Open User Account Control',
  network_status: 'Open network settings',
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

export function FindingCard({
  finding,
  onFixed,
}: {
  finding: Finding;
  /** Called after a successful fix so the caller can re-scan. */
  onFixed?: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [fixing, setFixing] = useState(false);
  const [result, setResult] = useState<FixResult | null>(null);
  const [helpError, setHelpError] = useState<string | null>(null);

  const openHelp = async () => {
    if (!finding.helpTarget) return;
    setHelpError(null);
    try {
      await openHelpTarget(finding.helpTarget);
    } catch (e) {
      setHelpError(e instanceof Error ? e.message : String(e));
    }
  };

  const runFix = async () => {
    if (!finding.fixAction) return;
    setFixing(true);
    setResult(null);
    try {
      const outcome = await applyFix(finding.fixAction, finding.id);
      setResult(outcome);
      if (outcome.succeeded) onFixed?.();
    } catch (e) {
      setResult({
        succeeded: false,
        detail: e instanceof Error ? e.message : String(e),
        undoHint: null,
        needsAdmin: false,
      });
    } finally {
      setFixing(false);
    }
  };

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
        <div className="flex items-start gap-4 mt-4 p-4 bg-slate-900/50 rounded-lg border border-slate-700/30">
          <div className="flex-1 min-w-0">
            <h4 className="text-xs uppercase tracking-wider text-slate-500 mb-1">
              Recommended action
            </h4>
            <p className="text-sm text-slate-300">{finding.remediation}</p>

            {/* The risk note describes the button beside it, so it is tied to
                the button's existence. */}
            {finding.fixAction && finding.autoFixRisk && (
              <p className="text-xs text-slate-500 mt-1.5">{FIX_RISK_NOTE[finding.autoFixRisk]}</p>
            )}

            {/* Said plainly rather than left to be inferred from a missing
                button. Most findings are this kind, and silence here reads as
                a fix that failed to load. */}
            {!finding.fixAction && (
              <p className="text-xs text-slate-500 mt-1.5">
                SENTRY will not change this for you
                {finding.helpTarget ? ' — the button opens the Windows page where you can.' : '.'}
              </p>
            )}
          </div>

          <div className="flex flex-col items-stretch gap-2 shrink-0">
            {/* Only shown when a real action backs it: `fixAction` is set by the
                backend and cannot name a fix that does not exist. */}
            {finding.fixAction && !result?.succeeded && (
              <button
                onClick={runFix}
                disabled={fixing}
                className="flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/40 disabled:cursor-not-allowed text-white rounded-lg text-sm font-medium transition-colors"
              >
                {fixing ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Wrench className="w-4 h-4" />
                )}
                {fixing ? 'Fixing...' : 'Fix this'}
              </button>
            )}

            {/* Takes the user to the page the advice above names. Opening a
                settings page is not a change, so it is styled as secondary and
                needs no confirmation. */}
            {finding.helpTarget && (
              <button
                onClick={openHelp}
                className="flex items-center justify-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-sm font-medium transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
                {HELP_LABEL[finding.helpTarget]}
              </button>
            )}
          </div>
        </div>
      )}

      {helpError && (
        <div className="mt-3 p-3 rounded-lg border bg-rose-500/10 border-rose-500/20 text-sm flex items-start gap-2">
          <Info className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
          <p className="text-slate-300">{helpError}</p>
        </div>
      )}

      {result && (
        <div
          className={`mt-3 p-3 rounded-lg border text-sm flex items-start gap-2 ${
            result.succeeded
              ? 'bg-emerald-500/10 border-emerald-500/20'
              : result.needsAdmin
                ? 'bg-amber-500/10 border-amber-500/20'
                : 'bg-rose-500/10 border-rose-500/20'
          }`}
        >
          {result.succeeded ? (
            <Check className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
          ) : (
            <Info
              className={`w-4 h-4 shrink-0 mt-0.5 ${
                result.needsAdmin ? 'text-amber-500' : 'text-rose-500'
              }`}
            />
          )}
          <div className="min-w-0">
            <p className="text-slate-300">{result.detail}</p>
            {result.succeeded && result.undoHint && (
              <p className="text-slate-500 text-xs mt-1">
                To undo: <span className="font-mono">{result.undoHint}</span>
              </p>
            )}
            {result.succeeded && (
              <p className="text-slate-500 text-xs mt-1">
                Run a scan to confirm the change took effect.
              </p>
            )}
          </div>
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
