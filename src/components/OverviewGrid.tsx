import React from 'react';
import {
  ArrowRightToLine,
  Bug,
  Monitor,
  RotateCcw,
  Router,
  Shield,
  ShieldAlert,
  Users,
  Wifi,
} from 'lucide-react';

import type { OverviewTile } from '../types';
import { formatTimestamp, isKnown, unknownDetail, unknownLabel } from '../types';
import { SeverityIcon } from './SeverityBadge';

interface OverviewGridProps {
  tiles: OverviewTile[];
  /** Opens the findings for one area. */
  onOpen?: (category: string) => void;
}

const ICONS: Record<string, typeof Shield> = {
  Desktop: Monitor,
  Network: Wifi,
  Router: Router,
  Devices: Users,
  Vulnerabilities: ShieldAlert,
  Malware: Bug,
  Firewall: Shield,
  Updates: RotateCcw,
  OpenPorts: ArrowRightToLine,
};

export function OverviewGrid({ tiles, onOpen }: OverviewGridProps) {
  return (
    <div className="grid grid-cols-3 gap-4">
      {tiles.map((tile) => (
        <TileCard key={tile.id} tile={tile} onOpen={onOpen} />
      ))}
    </div>
  );
}

function TileCard({
  tile,
  onOpen,
}: {
  tile: OverviewTile;
  onOpen?: (category: string) => void;
}) {
  const Icon = ICONS[tile.category] ?? Shield;

  // Narrow once, so the compiler enforces that a verdict is only read when one
  // actually exists.
  const status = tile.status;
  const verdict = isKnown(status) ? status.data : null;
  const known = verdict !== null;

  // A tile with nothing behind it is visibly inert: no hover affordance, muted
  // text, and the reason it could not report shown in place of a verdict.
  const severity = verdict?.severity ?? 'Unknown';
  const message = verdict?.message ?? unknownDetail(status);
  const label = verdict?.severity ?? unknownLabel(status);

  // Only clickable where there is something to show: a tile reporting
  // "No issues found" has no findings to open, and a dead click is worse than
  // an obviously inert card.
  const openable = known && verdict.severity !== 'Safe' && onOpen !== undefined;

  return (
    <div
      role={openable ? 'button' : undefined}
      tabIndex={openable ? 0 : undefined}
      onClick={openable ? () => onOpen(tile.category) : undefined}
      onKeyDown={
        openable
          ? (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onOpen(tile.category);
              }
            }
          : undefined
      }
      className={`bg-slate-800/30 border rounded-xl p-4 transition-colors group ${
        openable
          ? 'border-slate-700/50 hover:bg-slate-800/50 cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500/60'
          : known
            ? 'border-slate-700/50'
            : 'border-slate-800/60 border-dashed'
      }`}
      title={known ? undefined : unknownDetail(status)}
    >
      <div className="flex items-start justify-between mb-3">
        <div
          className={`transition-colors ${
            known ? 'text-slate-400 group-hover:text-slate-300' : 'text-slate-600'
          }`}
        >
          <Icon className="w-6 h-6" />
        </div>
        {openable && (
          <div className="text-slate-500 opacity-0 group-hover:opacity-100 transition-opacity">
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="m9 18 6-6-6-6" />
            </svg>
          </div>
        )}
      </div>

      <h3 className={`font-medium text-sm mb-2 ${known ? 'text-slate-200' : 'text-slate-400'}`}>
        {tile.title}
      </h3>

      <div className="flex items-center gap-2 mb-2">
        <SeverityIcon severity={severity} className="w-4 h-4 shrink-0" />
        <span className={`text-sm ${known ? 'text-slate-300' : 'text-slate-500'}`}>{label}</span>
      </div>

      <div className="text-slate-400 text-xs mb-3 min-h-[2rem] leading-4 line-clamp-2">{message}</div>

      <div className="text-slate-500 text-xs">
        {tile.lastChecked ? `Last checked ${formatTimestamp(tile.lastChecked)}` : 'Never checked'}
      </div>
    </div>
  );
}
