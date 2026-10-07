import React, { useCallback, useEffect, useState } from 'react';
import {
  Check,
  Flag,
  HelpCircle,
  Laptop,
  Loader2,
  Monitor,
  Pencil,
  Radar,
  Router,
  X,
} from 'lucide-react';

import {
  cancelDeviceDiscovery,
  discoverDevices,
  getDevices,
  renameDevice,
  setDeviceTrust,
} from '../services/ipc';
import type { DeviceList, DeviceRow, Known, SweepSummary, Trust } from '../types';
import { formatTimestamp, isKnown, unknownDetail } from '../types';

export function DevicesView() {
  const [list, setList] = useState<Known<DeviceList>>({ state: 'not_scanned' });
  const [loading, setLoading] = useState(true);
  const [sweeping, setSweeping] = useState(false);
  const [sweep, setSweep] = useState<SweepSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    getDevices().then((result) => {
      setList(result);
      setLoading(false);
    });
  }, []);

  useEffect(load, [load]);

  const runSweep = async () => {
    setSweeping(true);
    setError(null);
    setSweep(null);
    try {
      setSweep(await discoverDevices());
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSweeping(false);
    }
  };

  const update = async (fn: () => Promise<void>) => {
    try {
      await fn();
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const devices = isKnown(list) ? list.data.devices : [];
  const visibleNow = isKnown(list) ? list.data.visibleNow : 0;
  const unreviewed = devices.filter(
    (d) => d.trust === 'none' && !d.isSelf && !d.isGateway,
  ).length;

  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-start justify-between mb-8 gap-6">
          <div>
            <h1 className="text-2xl font-semibold text-white mb-2">Devices</h1>
            <p className="text-slate-400">
              Everything SENTRY can see on your home network.
            </p>
          </div>
          <div className="flex gap-2 shrink-0">
            <button
              onClick={runSweep}
              disabled={sweeping}
              className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/40 disabled:cursor-not-allowed text-white px-4 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 transition-colors"
            >
              {sweeping ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
              {sweeping ? 'Looking...' : 'Look for devices'}
            </button>
            {sweeping && (
              <button
                onClick={cancelDeviceDiscovery}
                title="Stop. Devices found so far are kept."
                className="bg-slate-800 hover:bg-slate-700 text-slate-400 border border-slate-700 px-3 rounded-lg transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Passive by default: say so, or "no devices" reads as "none exist". */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 mb-6">
          <p className="text-slate-400 text-sm">
            {sweep
              ? sweepSummary(sweep)
              : 'This list comes from devices your PC has recently talked to. Use ' +
                '"Look for devices" to check every address on your network.'}
          </p>
          {devices.length > 0 && (
            <p className="text-slate-500 text-xs mt-2">
              {visibleNow} of {devices.length} answering right now. Devices stay listed for 30 days
              after they were last seen, so one that is simply switched off does not disappear.
            </p>
          )}
        </div>

        {error && (
          <div className="bg-rose-500/10 border border-rose-500/20 rounded-xl p-4 mb-6">
            <p className="text-slate-300 text-sm">{error}</p>
          </div>
        )}

        {!isKnown(list) && !loading && (
          <div className="bg-slate-800/30 border border-slate-700/50 border-dashed rounded-xl p-8 text-center">
            <HelpCircle className="w-8 h-8 text-slate-600 mx-auto mb-3" />
            <h3 className="text-slate-300 font-medium mb-1">Devices could not be listed</h3>
            <p className="text-slate-500 text-sm max-w-md mx-auto">{unknownDetail(list)}</p>
          </div>
        )}

        {loading && devices.length === 0 && (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 text-slate-600 animate-spin" />
          </div>
        )}

        {isKnown(list) && !list.data.vendorRegistryAvailable && devices.length > 0 && (
          <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 mb-4">
            <p className="text-slate-300 text-sm">
              The manufacturer list has not been downloaded, so devices show only as addresses.
              Download it from the dashboard to see what most of these are.
            </p>
          </div>
        )}

        {devices.length > 0 && (
          <>
            {unreviewed > 0 && (
              <p className="text-slate-400 text-sm mb-4">
                {unreviewed} device{unreviewed === 1 ? '' : 's'} not yet reviewed. Marking the ones
                you recognise means anything new stands out later.
              </p>
            )}
            <div className="space-y-3">
              {devices.map((device) => (
                <DeviceCard
                  key={device.id}
                  device={device}
                  onTrust={(trust) => update(() => setDeviceTrust(device.id, trust))}
                  onRename={(name) => update(() => renameDevice(device.id, name))}
                />
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function sweepSummary(sweep: SweepSummary): string {
  if (sweep.skippedReason) return sweep.skippedReason;

  const base = `Checked ${sweep.addressesProbed} addresses on ${sweep.subnet ?? 'your network'} in ${(sweep.durationMs / 1000).toFixed(1)}s.`;
  return sweep.conclusive
    ? base
    : `${base} The sweep was stopped early, so this may not be every device.`;
}

const KIND_ICON = {
  router: Router,
  thiscomputer: Laptop,
  unknown: Monitor,
} as const;

function DeviceCard({
  device,
  onTrust,
  onRename,
}: {
  device: DeviceRow;
  onTrust: (trust: Trust) => void;
  onRename: (name: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(device.displayName ?? '');

  const Icon = KIND_ICON[device.deviceType] ?? Monitor;
  const reviewable = !device.isSelf && !device.isGateway;

  return (
    <div
      className={`bg-slate-800/30 border rounded-xl p-4 flex items-start gap-4 ${
        device.currentlyVisible ? 'border-slate-700/50' : 'border-slate-800/60 border-dashed'
      }`}
    >
      <div className="text-slate-400 mt-0.5 shrink-0">
        <Icon className="w-5 h-5" />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-1">
          {editing ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                onRename(draft);
                setEditing(false);
              }}
              className="flex items-center gap-2"
            >
              <input
                autoFocus
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                maxLength={64}
                placeholder="Name this device"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
              />
              <button type="submit" className="text-emerald-500 hover:text-emerald-400">
                <Check className="w-4 h-4" />
              </button>
              <button
                type="button"
                onClick={() => setEditing(false)}
                className="text-slate-500 hover:text-slate-300"
              >
                <X className="w-4 h-4" />
              </button>
            </form>
          ) : (
            <>
              <span className="text-slate-200 font-medium">{device.label}</span>
              <button
                onClick={() => {
                  setDraft(device.displayName ?? '');
                  setEditing(true);
                }}
                title="Give this device a name"
                className="text-slate-600 hover:text-slate-400 transition-colors"
              >
                <Pencil className="w-3.5 h-3.5" />
              </button>
            </>
          )}

          {device.isGateway && <Tag>Your router</Tag>}
          {device.isSelf && <Tag>This PC</Tag>}
          {!device.currentlyVisible && <Tag>Not answering</Tag>}
          {device.trust === 'trusted' && <Tag tone="emerald">Recognised</Tag>}
          {device.trust === 'flagged' && <Tag tone="rose">Flagged</Tag>}
        </div>

        <div className="text-slate-500 text-xs font-mono mb-1">
          {device.ip ?? 'address unknown'}
          {device.mac && <> &middot; {device.mac}</>}
        </div>

        <div className="text-slate-500 text-xs">
          {device.vendor ??
            (device.macIsRandom
              ? 'Randomised address, so the manufacturer cannot be identified'
              : 'Manufacturer not found in the registry')}
          {device.currentlyVisible
            ? device.firstSeen && <> &middot; first seen {formatTimestamp(device.firstSeen)}</>
            : <> &middot; last seen {formatTimestamp(device.lastSeen)}</>}
        </div>
      </div>

      {reviewable && (
        <div className="flex gap-1.5 shrink-0">
          <button
            onClick={() => onTrust(device.trust === 'trusted' ? 'none' : 'trusted')}
            title={device.trust === 'trusted' ? 'Undo' : 'I recognise this device'}
            className={`px-2.5 py-1.5 rounded-lg text-xs border transition-colors ${
              device.trust === 'trusted'
                ? 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20'
                : 'text-slate-400 bg-slate-800 border-slate-700 hover:bg-slate-700'
            }`}
          >
            <Check className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => onTrust(device.trust === 'flagged' ? 'none' : 'flagged')}
            title={device.trust === 'flagged' ? 'Undo' : 'I do not recognise this'}
            className={`px-2.5 py-1.5 rounded-lg text-xs border transition-colors ${
              device.trust === 'flagged'
                ? 'text-rose-500 bg-rose-500/10 border-rose-500/20'
                : 'text-slate-400 bg-slate-800 border-slate-700 hover:bg-slate-700'
            }`}
          >
            <Flag className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}

function Tag({
  children,
  tone = 'slate',
}: {
  children: React.ReactNode;
  tone?: 'slate' | 'emerald' | 'rose';
}) {
  const styles = {
    slate: 'text-slate-400 bg-slate-700/40 border-slate-700',
    emerald: 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20',
    rose: 'text-rose-500 bg-rose-500/10 border-rose-500/20',
  }[tone];

  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${styles}`}>{children}</span>
  );
}
