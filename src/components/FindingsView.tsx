import React from 'react';
import { Check, Loader2 } from 'lucide-react';

import type { ScanState } from '../hooks/useScan';
import { isKnown } from '../types';
import { FindingCard } from './FindingCard';

export function FindingsView({ scan }: { scan: ScanState }) {
  const { dashboard, scanning } = scan;
  const findings = dashboard?.findings ?? [];
  const gaps = dashboard?.score.gaps ?? [];

  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-white mb-2">Findings</h1>
          <p className="text-slate-400">
            Review and resolve security alerts across your network.
          </p>
        </div>

        {scanning && findings.length === 0 ? (
          <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-12 flex flex-col items-center text-center">
            <Loader2 className="w-8 h-8 text-slate-600 animate-spin mb-3" />
            <p className="text-slate-400 text-sm">Scanning...</p>
          </div>
        ) : findings.length === 0 ? (
          <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-12 flex flex-col items-center text-center">
            <div className="w-12 h-12 bg-emerald-500/10 rounded-full flex items-center justify-center border border-emerald-500/20 mb-4">
              <Check className="w-6 h-6 text-emerald-500" />
            </div>
            <h3 className="text-white font-medium mb-1">No findings</h3>
            <p className="text-slate-400 text-sm max-w-md">
              Nothing was flagged in the areas that were checked.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </div>
        )}

        {/* Stated on every findings view, empty or not: an absence of findings
            is only meaningful alongside what was never looked at. */}
        {gaps.length > 0 && dashboard && (
          <div className="mt-6 bg-slate-900/50 border border-slate-800 rounded-xl p-5">
            <h3 className="text-slate-300 text-sm font-medium mb-2">
              {dashboard.tiles.filter((t) => !isKnown(t.status)).length} areas were not checked
            </h3>
            <p className="text-slate-500 text-sm">
              This list covers only what SENTRY could inspect. Not yet checked: {gaps.join(', ')}.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
