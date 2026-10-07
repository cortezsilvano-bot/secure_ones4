import React from 'react';
import {
  AlertTriangle,
  Clock,
  HelpCircle,
  History,
  LayoutDashboard,
  Loader2,
  Lock,
  Monitor,
  Settings,
  Shield,
} from 'lucide-react';

import type { ScanState } from '../hooks/useScan';
import { formatTimestamp, isKnown } from '../types';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  scan: ScanState;
}

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'devices', label: 'Devices', icon: Monitor },
  { id: 'timeline', label: 'Timeline', icon: Clock },
  { id: 'history', label: 'History', icon: History },
  { id: 'privacy', label: 'Privacy', icon: Lock },
];

const BOTTOM_ITEMS = [
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'help', label: 'Help', icon: HelpCircle },
];

export function Sidebar({ activeTab, setActiveTab, scan }: SidebarProps) {
  return (
    <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen text-slate-300 shrink-0">
      <div className="p-6 flex items-center gap-3 text-white mb-2">
        <div className="bg-blue-600/20 p-1.5 rounded-lg border border-blue-500/30">
          <Shield className="w-6 h-6 text-blue-500" />
        </div>
        <span className="font-semibold text-lg tracking-wide">SENTRY</span>
      </div>

      <nav className="flex-1 px-4 space-y-1">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                isActive
                  ? 'bg-blue-600/10 text-blue-400 font-medium'
                  : 'hover:bg-slate-800/50 hover:text-slate-200'
              }`}
            >
              <Icon className={`w-5 h-5 ${isActive ? 'text-blue-500' : 'text-slate-400'}`} />
              {item.label}
            </button>
          );
        })}
      </nav>

      <div className="px-4 py-6 space-y-4">
        <ScanStatusBox scan={scan} />

        <nav className="space-y-1">
          {BOTTOM_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors hover:bg-slate-800/50 hover:text-slate-200"
              >
                <Icon className="w-5 h-5 text-slate-400" />
                {item.label}
              </button>
            );
          })}
        </nav>
      </div>
    </div>
  );
}

/**
 * The old version of this box always read "All systems healthy". It now states
 * the actual finding count and, crucially, how much was checked -- a green dot
 * over one working module out of nine would be the same lie in a smaller space.
 */
function ScanStatusBox({ scan }: { scan: ScanState }) {
  const { dashboard, scanning, error } = scan;

  const openFindings = dashboard?.findings.filter((f) => f.status === 'open').length ?? 0;
  const checked = dashboard?.tiles.filter((t) => isKnown(t.status)).length ?? 0;
  const total = dashboard?.tiles.length ?? 9;

  const dot = error
    ? 'bg-rose-500'
    : scanning
      ? 'bg-blue-500 animate-pulse'
      : openFindings > 0
        ? 'bg-amber-500'
        : checked === 0
          ? 'bg-slate-600'
          : checked < total
            ? 'bg-amber-500'
            : 'bg-emerald-500';

  const headline = error
    ? 'Scan failed'
    : scanning
      ? 'Scanning'
      : openFindings > 0
        ? `${openFindings} finding${openFindings === 1 ? '' : 's'}`
        : checked === 0
          ? 'Nothing checked'
          : 'No problems found';

  return (
    <div className="bg-slate-800/40 rounded-xl p-4 border border-slate-700/50">
      <div className="flex items-center gap-2 mb-3">
        {scanning ? (
          <Loader2 className="w-3 h-3 text-blue-400 animate-spin" />
        ) : (
          <div className={`w-2 h-2 rounded-full ${dot}`} />
        )}
        <span className="text-sm font-medium text-slate-200">Scan status</span>
      </div>

      <div className="text-sm text-slate-400 mb-1">{headline}</div>
      <div className="text-xs text-slate-500 mb-1">
        {checked} of {total} areas checked
      </div>
      <div className="text-xs text-slate-500">
        Last scan: {formatTimestamp(dashboard?.scannedAt ?? null)}
      </div>
    </div>
  );
}
