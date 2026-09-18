import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Info, Loader2 } from 'lucide-react';

import { getScanHistory } from '../services/ipc';
import type { ScanRecord } from '../types';
import { formatTimestamp } from '../types';

/**
 * The single series colour, validated against this app's surface (#020617) for
 * lightness, chroma and 3:1 contrast. One series, so the title names it and
 * there is no legend.
 */
const SERIES = '#3987e5';

export function HistoryView() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    getScanHistory(60).then((result) => {
      if (!alive) return;
      setRecords(result);
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  // Oldest first for plotting; the API returns newest first.
  const scored = useMemo(
    () => records.filter((r) => r.score !== null).slice().reverse(),
    [records],
  );

  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-8">
      <div className="max-w-3xl mx-auto">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-white mb-2">History</h1>
          <p className="text-slate-400">How your security score has moved over time.</p>
        </div>

        {loading && (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 text-slate-600 animate-spin" />
          </div>
        )}

        {!loading && records.length === 0 && (
          <div className="bg-slate-800/30 border border-slate-700/50 border-dashed rounded-xl p-8 text-center">
            <Info className="w-8 h-8 text-slate-600 mx-auto mb-3" />
            <h3 className="text-slate-300 font-medium mb-1">No scans recorded yet</h3>
            <p className="text-slate-500 text-sm">Run a scan and it will appear here.</p>
          </div>
        )}

        {scored.length > 0 && <ScoreChart records={scored} />}

        {records.length > 0 && <ScanTable records={records} />}
      </div>
    </div>
  );
}

function ScoreChart({ records }: { records: ScanRecord[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const width = 640;
  const height = 200;
  const pad = { top: 16, right: 16, bottom: 28, left: 34 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;

  // Always 0-100: the score's domain is fixed, and rescaling to the data range
  // would exaggerate small movements into dramatic swings.
  const x = (i: number) =>
    pad.left + (records.length === 1 ? plotW / 2 : (i / (records.length - 1)) * plotW);
  const y = (score: number) => pad.top + plotH - (score / 100) * plotH;

  const path = records
    .map((r, i) => `${i === 0 ? 'M' : 'L'} ${x(i).toFixed(1)} ${y(r.score!).toFixed(1)}`)
    .join(' ');

  const latest = records[records.length - 1];

  // The crosshair finds the X: snap to the nearest point rather than requiring
  // the pointer to land on a 2px line.
  const onMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    const px = ((e.clientX - rect.left) / rect.width) * width;
    const ratio = (px - pad.left) / plotW;
    const index = Math.round(ratio * (records.length - 1));
    setHover(Math.max(0, Math.min(records.length - 1, index)));
  };

  const active = hover !== null ? records[hover] : null;

  return (
    <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5 mb-4">
      <div className="flex items-baseline justify-between mb-1">
        <h2 className="text-slate-200 font-medium">Security score</h2>
        <span className="text-slate-500 text-xs">{records.length} scans</span>
      </div>

      {/* Hero number: the current value, in text tokens with the status named
          in words beside it rather than carried by colour alone. */}
      <div className="flex items-baseline gap-2 mb-4">
        <span className="text-3xl font-semibold text-white tabular-nums">{latest.score}</span>
        <span className="text-slate-500 text-sm">/ 100 now</span>
      </div>

      <svg
        ref={svgRef}
        viewBox={`0 0 ${width} ${height}`}
        className="w-full touch-none"
        role="img"
        aria-label={`Security score over the last ${records.length} scans, currently ${latest.score} out of 100`}
        onPointerMove={onMove}
        onPointerLeave={() => setHover(null)}
      >
        {/* Recessive grid. */}
        {[0, 25, 50, 75, 100].map((tick) => (
          <g key={tick}>
            <line
              x1={pad.left}
              x2={width - pad.right}
              y1={y(tick)}
              y2={y(tick)}
              stroke="#1e293b"
              strokeWidth="1"
            />
            <text
              x={pad.left - 8}
              y={y(tick) + 3}
              textAnchor="end"
              className="fill-slate-600"
              fontSize="9"
            >
              {tick}
            </text>
          </g>
        ))}

        <path d={path} fill="none" stroke={SERIES} strokeWidth="2" strokeLinejoin="round" />

        {/* Markers, sized to be aimable. A surface ring keeps them legible
            where the line doubles back on itself. */}
        {records.map((r, i) => (
          <circle
            key={i}
            cx={x(i)}
            cy={y(r.score!)}
            r={hover === i ? 5 : 4}
            fill={SERIES}
            stroke="#020617"
            strokeWidth="2"
          />
        ))}

        {active && hover !== null && (
          <line
            x1={x(hover)}
            x2={x(hover)}
            y1={pad.top}
            y2={pad.top + plotH}
            stroke="#334155"
            strokeWidth="1"
          />
        )}
      </svg>

      {/* Tooltip as HTML rather than SVG text: value leads, label follows. */}
      <div className="h-10 mt-1">
        {active ? (
          <div className="flex items-baseline gap-2">
            <span className="text-slate-200 text-sm font-semibold tabular-nums">
              {active.score}
            </span>
            <span className="text-slate-500 text-xs">
              {formatTimestamp(active.startedAt)}
              {active.modulesReporting != null && active.modulesTotal != null && (
                <> &middot; {active.modulesReporting} of {active.modulesTotal} areas checked</>
              )}
              {active.findings != null && <> &middot; {active.findings} findings</>}
            </span>
          </div>
        ) : (
          <span className="text-slate-600 text-xs">Hover the chart for a scan's details.</span>
        )}
      </div>
    </div>
  );
}

/** The table view: every value reachable without hovering. */
function ScanTable({ records }: { records: ScanRecord[] }) {
  return (
    <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5">
      <h2 className="text-slate-200 font-medium mb-4">Every scan</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-slate-500 text-xs uppercase tracking-wider">
              <th className="text-left font-medium pb-2">When</th>
              <th className="text-right font-medium pb-2">Score</th>
              <th className="text-right font-medium pb-2">Coverage</th>
              <th className="text-right font-medium pb-2">Findings</th>
            </tr>
          </thead>
          <tbody>
            {records.map((r, i) => (
              <tr key={`${r.startedAt}-${i}`} className="border-t border-slate-800">
                <td className="py-2 text-slate-300">{formatTimestamp(r.startedAt)}</td>
                <td className="py-2 text-right text-slate-200 tabular-nums">
                  {r.score ?? <span className="text-slate-600">not enough data</span>}
                </td>
                <td className="py-2 text-right text-slate-400 tabular-nums">
                  {r.modulesReporting != null && r.modulesTotal != null
                    ? `${r.modulesReporting}/${r.modulesTotal}`
                    : '—'}
                </td>
                <td className="py-2 text-right text-slate-400 tabular-nums">{r.findings ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
