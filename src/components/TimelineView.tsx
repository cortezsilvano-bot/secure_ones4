import React, { useEffect, useState } from 'react';
import { AlertCircle, AlertTriangle, CheckCircle2, Info, Loader2, Monitor, Search } from 'lucide-react';

import { getTimeline } from '../services/ipc';
import type { TimelineEntry } from '../types';
import { formatTimestamp } from '../types';

const KIND_ICON = {
  scan_completed: Search,
  finding_opened: AlertTriangle,
  finding_resolved: CheckCircle2,
  device_seen: Monitor,
} as const;

const SEVERITY_COLOR: Record<string, string> = {
  Critical: 'text-rose-500',
  Warning: 'text-amber-500',
  Attention: 'text-blue-400',
  Safe: 'text-emerald-500',
};

export function TimelineView() {
  const [entries, setEntries] = useState<TimelineEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    getTimeline(150).then((result) => {
      if (!alive) return;
      setEntries(result);
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-8">
      <div className="max-w-3xl mx-auto">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-white mb-2">Timeline</h1>
          <p className="text-slate-400">
            Everything SENTRY has noticed, newest first.
          </p>
        </div>

        {loading && (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 text-slate-600 animate-spin" />
          </div>
        )}

        {!loading && entries.length === 0 && (
          <div className="bg-slate-800/30 border border-slate-700/50 border-dashed rounded-xl p-8 text-center">
            <Info className="w-8 h-8 text-slate-600 mx-auto mb-3" />
            <h3 className="text-slate-300 font-medium mb-1">Nothing yet</h3>
            <p className="text-slate-500 text-sm">
              Run a scan and this will fill with what changed and when.
            </p>
          </div>
        )}

        {entries.length > 0 && (
          <div className="relative">
            {/* The spine. */}
            <div className="absolute left-[15px] top-2 bottom-2 w-px bg-slate-800" />

            <div className="space-y-1">
              {entries.map((entry, i) => (
                <Entry key={`${entry.occurredAt}-${entry.kind}-${i}`} entry={entry} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Entry({ entry }: { entry: TimelineEntry }) {
  const Icon = KIND_ICON[entry.kind] ?? Info;

  const color =
    entry.kind === 'finding_resolved'
      ? 'text-emerald-500'
      : entry.severity
        ? (SEVERITY_COLOR[entry.severity] ?? 'text-slate-400')
        : 'text-slate-500';

  return (
    <div className="flex gap-4 py-2.5 group">
      <div className="relative shrink-0">
        <div className="w-8 h-8 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center">
          <Icon className={`w-4 h-4 ${color}`} />
        </div>
      </div>

      <div className="flex-1 min-w-0 pt-1">
        <div className="flex items-baseline justify-between gap-3">
          <span className="text-slate-200 text-sm">{entry.title}</span>
          <span className="text-slate-600 text-xs shrink-0">
            {formatTimestamp(entry.occurredAt)}
          </span>
        </div>
        {entry.detail && <div className="text-slate-500 text-xs mt-0.5">{entry.detail}</div>}
      </div>
    </div>
  );
}

/** Exported for the History view, which shares the severity palette. */
export { SEVERITY_COLOR };
