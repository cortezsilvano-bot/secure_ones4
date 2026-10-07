import React, { useEffect, useState } from 'react';
import { AlertTriangle, Check, Key, Loader2, Play, Trash2 } from 'lucide-react';

import {
  deleteEverything,
  deleteLocalData,
  getSettings,
  setNvdApiKey,
  setScanOnStart,
} from '../services/ipc';
import type { DeletionSummary, SettingsView as SettingsState } from '../types';

export function SettingsView() {
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [keyDraft, setKeyDraft] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<'local' | 'everything' | null>(null);

  const load = () => getSettings().then(setSettings);
  useEffect(() => {
    load();
  }, []);

  const run = async (fn: () => Promise<void>, ok: string) => {
    setError(null);
    setMessage(null);
    try {
      await fn();
      setMessage(ok);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const wipe = async (scope: 'local' | 'everything') => {
    setConfirming(null);
    setError(null);
    setMessage(null);
    try {
      const summary: DeletionSummary =
        scope === 'local' ? await deleteLocalData() : await deleteEverything();
      setMessage(
        summary.rowsDeleted === 0
          ? 'There was nothing to delete.'
          : `Deleted ${summary.rowsDeleted.toLocaleString()} records.`,
      );
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-8">
      <div className="max-w-2xl mx-auto">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-white mb-2">Settings</h1>
          <p className="text-slate-400">How SENTRY behaves, and what it keeps.</p>
        </div>

        {message && (
          <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-xl p-3 mb-4 flex items-center gap-2">
            <Check className="w-4 h-4 text-emerald-500 shrink-0" />
            <span className="text-slate-300 text-sm">{message}</span>
          </div>
        )}
        {error && (
          <div className="bg-rose-500/10 border border-rose-500/20 rounded-xl p-3 mb-4">
            <span className="text-slate-300 text-sm">{error}</span>
          </div>
        )}

        {!settings && (
          <div className="flex justify-center py-12">
            <Loader2 className="w-6 h-6 text-slate-600 animate-spin" />
          </div>
        )}

        {settings && (
          <div className="space-y-4">
            {/* Scanning */}
            <Card icon={Play} title="Scanning">
              <Toggle
                label="Scan when SENTRY opens"
                description="Otherwise the dashboard waits until you press Scan now."
                checked={settings.scanOnStart}
                onChange={(v) =>
                  run(() => setScanOnStart(v), v ? 'Will scan on open.' : 'Will not scan on open.')
                }
              />
            </Card>

            {/* NVD key */}
            <Card icon={Key} title="Vulnerability database key">
              <p className="text-slate-400 text-sm mb-1">
                Optional. The vulnerability database limits anyone without a key to 5 requests
                every 30 seconds, which is why a full refresh takes minutes. A free key raises
                that to 50 and makes it roughly ten times faster.
              </p>
              <p className="text-slate-500 text-xs mb-3">
                The key is stored on this PC and sent only to nvd.nist.gov. Get one at
                nvd.nist.gov/developers/request-an-api-key
              </p>

              {settings.hasNvdApiKey ? (
                <div className="flex items-center gap-3">
                  <span className="text-emerald-500 text-sm flex items-center gap-1.5">
                    <Check className="w-4 h-4" /> A key is saved
                  </span>
                  <button
                    onClick={() => run(() => setNvdApiKey(null), 'Key removed.')}
                    className="text-slate-400 hover:text-slate-200 text-sm underline underline-offset-2"
                  >
                    Remove it
                  </button>
                </div>
              ) : (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    run(() => setNvdApiKey(keyDraft), 'Key saved.').then(() => setKeyDraft(''));
                  }}
                  className="flex gap-2"
                >
                  <input
                    type="password"
                    value={keyDraft}
                    onChange={(e) => setKeyDraft(e.target.value)}
                    placeholder="Paste your key"
                    className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    type="submit"
                    disabled={!keyDraft.trim()}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 border border-slate-700 px-4 rounded-lg text-sm transition-colors"
                  >
                    Save
                  </button>
                </form>
              )}
            </Card>

            {/* Deletion. Two scopes, because throwing away the downloaded
                feeds costs a rate-limited hour and contains nothing personal. */}
            <Card icon={Trash2} title="Delete your data">
              <p className="text-slate-400 text-sm mb-4">
                Everything SENTRY knows is in one file on this PC. You can empty it at any time.
              </p>

              <div className="space-y-3">
                <DeleteRow
                  title="Delete what SENTRY learned about this PC"
                  description="Findings, devices, installed programs, scan history and listening services. The downloaded public vulnerability data is kept, because it contains nothing about you and takes a long time to fetch again."
                  confirming={confirming === 'local'}
                  onAsk={() => setConfirming('local')}
                  onCancel={() => setConfirming(null)}
                  onConfirm={() => wipe('local')}
                />
                <DeleteRow
                  title="Delete everything, including downloaded data"
                  description="Also removes the vulnerability database, the exploited-vulnerability catalogue and the manufacturer registry. Re-downloading them takes a while."
                  danger
                  confirming={confirming === 'everything'}
                  onAsk={() => setConfirming('everything')}
                  onCancel={() => setConfirming(null)}
                  onConfirm={() => wipe('everything')}
                />
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}

function Card({
  icon: Icon,
  title,
  children,
}: {
  icon: typeof Key;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-4 h-4 text-slate-400" />
        <h2 className="text-slate-200 font-medium">{title}</h2>
      </div>
      {children}
    </div>
  );
}

function Toggle({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <label className="flex items-start justify-between gap-4 cursor-pointer">
      <span className="min-w-0">
        <span className="block text-slate-300 text-sm">{label}</span>
        <span className="block text-slate-500 text-xs">{description}</span>
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative w-10 h-6 rounded-full transition-colors shrink-0 ${
          checked ? 'bg-blue-600' : 'bg-slate-700'
        }`}
      >
        <span
          className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${
            checked ? 'translate-x-5' : 'translate-x-1'
          }`}
        />
      </button>
    </label>
  );
}

/** Deletion is irreversible, so it always asks first and names what goes. */
function DeleteRow({
  title,
  description,
  danger,
  confirming,
  onAsk,
  onCancel,
  onConfirm,
}: {
  title: string;
  description: string;
  danger?: boolean;
  confirming: boolean;
  onAsk: () => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="border border-slate-700/50 rounded-lg p-3">
      <div className="text-slate-300 text-sm mb-1">{title}</div>
      <div className="text-slate-500 text-xs mb-3">{description}</div>

      {confirming ? (
        <div className="flex items-center gap-2">
          <AlertTriangle className={`w-4 h-4 shrink-0 ${danger ? 'text-rose-500' : 'text-amber-500'}`} />
          <span className="text-slate-300 text-xs flex-1">This cannot be undone.</span>
          <button
            onClick={onCancel}
            className="text-slate-400 hover:text-slate-200 text-xs px-3 py-1.5"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
              danger
                ? 'text-rose-400 border-rose-500/30 bg-rose-500/10 hover:bg-rose-500/20'
                : 'text-amber-400 border-amber-500/30 bg-amber-500/10 hover:bg-amber-500/20'
            }`}
          >
            Delete
          </button>
        </div>
      ) : (
        <button
          onClick={onAsk}
          className="text-slate-400 hover:text-slate-200 text-xs border border-slate-700 rounded-lg px-3 py-1.5 transition-colors"
        >
          Delete
        </button>
      )}
    </div>
  );
}
