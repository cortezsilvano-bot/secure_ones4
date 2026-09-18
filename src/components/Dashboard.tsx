import React from 'react';
import { Check, Loader2, Minus, Play, Shield, ShieldAlert } from 'lucide-react';

import type { ScanState } from '../hooks/useScan';
import type { Coverage, Finding } from '../types';
import { formatTimestamp, isKnown } from '../types';
import { CircularProgress } from './CircularProgress';
import { OverviewGrid } from './OverviewGrid';
import { RouterPanel } from './RouterPanel';
import { SeverityBadge } from './SeverityBadge';
import { VulnerabilityFeedPanel } from './VulnerabilityFeedPanel';

const COVERAGE_LABEL: Record<Coverage, string> = {
  complete: 'Complete',
  partial: 'Partially complete',
  incomplete: 'Incomplete',
};

const COVERAGE_STYLE: Record<Coverage, string> = {
  complete: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20',
  partial: 'text-amber-500 bg-amber-500/10 border-amber-500/20',
  incomplete: 'text-slate-400 bg-slate-400/10 border-slate-400/20',
};

export function Dashboard({ scan }: { scan: ScanState }) {
  const { dashboard, scanning, error, rescan } = scan;

  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-8">
      <div className="max-w-6xl mx-auto space-y-8">
        <div className="flex items-end justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-white mb-1">SENTRY</h1>
            <p className="text-slate-400 text-sm">Your home security at a glance</p>
          </div>
          <div className="flex items-center gap-6">
            <div className="text-right">
              <div className="text-xs text-slate-500 mb-0.5">Last scan</div>
              <div className="text-sm text-slate-300">
                {formatTimestamp(dashboard?.scannedAt ?? null)}
              </div>
            </div>
            <button
              onClick={rescan}
              disabled={scanning}
              className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/40 disabled:cursor-not-allowed text-white px-5 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors"
            >
              {scanning ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Shield className="w-4 h-4" />
              )}
              {scanning ? 'Scanning...' : 'Scan now'}
            </button>
          </div>
        </div>

        {error && (
          <div className="bg-rose-500/10 border border-rose-500/20 rounded-xl p-4 flex items-start gap-3">
            <ShieldAlert className="w-5 h-5 text-rose-500 shrink-0 mt-0.5" />
            <div>
              <h3 className="text-rose-400 font-medium text-sm mb-1">The scan could not run</h3>
              <p className="text-slate-400 text-sm">{error}</p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-12 gap-6">
          <div className="col-span-4 bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6 flex flex-col">
            <h2 className="text-slate-200 font-medium mb-6">Home Security Score</h2>
            <div className="flex items-center gap-6 flex-1">
              <CircularProgress score={dashboard?.score.score ?? null} coverage={dashboard?.score.coverage} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-3">
                  {dashboard ? (
                    <div
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${COVERAGE_STYLE[dashboard.score.coverage]}`}
                    >
                      {COVERAGE_LABEL[dashboard.score.coverage]}
                    </div>
                  ) : (
                    <SeverityBadge severity="Unknown" label="Scanning" />
                  )}
                </div>
                <p className="text-sm text-slate-300 mb-3">{scoreSummary(dashboard)}</p>
                {dashboard && dashboard.score.lines.length > 0 && (
                  <div className="text-xs text-slate-500 space-y-1">
                    {dashboard.score.lines.slice(0, 3).map((line) => (
                      <p key={line.findingId} className="truncate">
                        <span className="text-rose-400 font-mono">{line.delta}</span> {line.reason}
                      </p>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="col-span-8">
            <h2 className="text-slate-200 font-medium mb-4">Things worth checking</h2>
            <ThingsWorthChecking findings={dashboard?.findings ?? []} scanning={scanning} />
          </div>
        </div>

        <div className="grid grid-cols-12 gap-6">
          <div className="col-span-8 space-y-4">
            <h2 className="text-slate-200 font-medium">Security overview</h2>
            <OverviewGrid tiles={dashboard?.tiles ?? []} />
          </div>

          <div className="col-span-4 space-y-4">
            <h2 className="text-slate-200 font-medium">Scan coverage</h2>
            <CoveragePanel scan={scan} />
            <VulnerabilityFeedPanel onRefreshed={rescan} />
            <RouterPanel />
          </div>
        </div>
      </div>
    </div>
  );
}

function scoreSummary(dashboard: ScanState['dashboard']): string {
  if (!dashboard) return 'Running the first scan...';

  const { score, coverage, modulesReporting, modulesTotal } = dashboard.score;

  if (score === null) {
    return `No checks completed, so there is no score to give. ${modulesReporting} of ${modulesTotal} areas reported.`;
  }
  if (coverage === 'partial') {
    return `Based on the ${modulesReporting} of ${modulesTotal} areas that reported. The rest have not been checked.`;
  }
  return score >= 80
    ? 'Your PC and home network look healthy.'
    : 'Some things need your attention.';
}

function ThingsWorthChecking({ findings, scanning }: { findings: Finding[]; scanning: boolean }) {
  if (findings.length === 0) {
    return (
      <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6 h-[216px] flex flex-col items-center justify-center text-center">
        {scanning ? (
          <>
            <Loader2 className="w-8 h-8 text-slate-600 animate-spin mb-3" />
            <p className="text-slate-400 text-sm">Checking...</p>
          </>
        ) : (
          <>
            <div className="w-12 h-12 bg-emerald-500/10 rounded-full flex items-center justify-center border border-emerald-500/20 mb-3">
              <Check className="w-6 h-6 text-emerald-500" />
            </div>
            <h3 className="text-white font-medium mb-1">Nothing needs your attention</h3>
            <p className="text-slate-400 text-sm max-w-md">
              No problems were found in the areas that were checked. See scan coverage for what was
              not looked at.
            </p>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-3 gap-4 min-h-[216px]">
      {findings.slice(0, 3).map((finding, idx) => (
        <div
          key={finding.id}
          className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-5 flex flex-col"
        >
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center border border-slate-700 text-slate-300 text-sm">
              {idx + 1}
            </div>
          </div>
          <h3 className="text-slate-200 font-medium text-sm mb-2">{finding.title}</h3>
          <p className="text-slate-400 text-xs flex-1 line-clamp-4">{finding.whyItMatters}</p>
          <div className="flex items-center justify-between mt-4">
            <SeverityBadge severity={finding.severity} />
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * The honest counterpart to the score: which areas actually reported, and which
 * did not. Every module appears, so a gap is impossible to miss.
 */
function CoveragePanel({ scan }: { scan: ScanState }) {
  const { dashboard, scanning, rescan } = scan;
  const tiles = dashboard?.tiles ?? [];
  const reporting = tiles.filter((t) => isKnown(t.status));

  return (
    <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6">
      <div className="mb-6">
        <div className="text-3xl font-semibold text-white mb-1">
          {reporting.length}
          <span className="text-slate-500 text-xl"> / {tiles.length || 9}</span>
        </div>
        <p className="text-slate-400 text-sm">areas checked</p>
      </div>

      {dashboard?.programsInstalled != null && (
        <p className="text-slate-500 text-xs mb-4 -mt-4">
          {dashboard.programsInstalled} programs installed
        </p>
      )}

      <div className="space-y-2.5 mb-6">
        {tiles.map((tile) => {
          const known = isKnown(tile.status);
          return (
            <div key={tile.id} className="flex items-center gap-2 text-sm">
              {known ? (
                <Check className="w-4 h-4 text-emerald-500 shrink-0" />
              ) : (
                <Minus className="w-4 h-4 text-slate-600 shrink-0" />
              )}
              <span className={known ? 'text-slate-300' : 'text-slate-500'}>{tile.title}</span>
              {!known && (
                <span className="text-slate-600 text-xs ml-auto">
                  {tile.status.state === 'not_scanned' ? 'not built yet' : 'unavailable'}
                </span>
              )}
            </div>
          );
        })}
      </div>

      <button
        onClick={rescan}
        disabled={scanning}
        className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/40 disabled:cursor-not-allowed text-white px-4 py-2.5 rounded-lg text-sm font-medium flex items-center justify-center gap-2 transition-colors"
      >
        {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
        {scanning ? 'Scanning...' : 'Run another scan'}
      </button>
    </div>
  );
}
