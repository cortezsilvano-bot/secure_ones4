import React, { useEffect, useState } from 'react';
import { Database, Globe, HardDrive, Loader2, ShieldOff } from 'lucide-react';

import { getPrivacyReport } from '../services/ipc';
import type { PrivacyReport } from '../types';
import { formatTimestamp } from '../types';

/**
 * The privacy claim, made checkable.
 *
 * Every number here is counted from the store on disk rather than written into
 * the page, and every outbound address is listed with what is actually sent to
 * it. A privacy page that simply asserts "we respect your privacy" is worth
 * nothing; this one is meant to be something the user can verify.
 */
export function PrivacyView() {
  const [report, setReport] = useState<PrivacyReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    getPrivacyReport().then((result) => {
      if (!alive) return;
      setReport(result);
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-slate-950">
        <Loader2 className="w-6 h-6 text-slate-600 animate-spin" />
      </div>
    );
  }

  if (!report) {
    return (
      <div className="flex-1 flex items-center justify-center bg-slate-950 text-slate-500">
        The privacy report could not be read.
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-auto bg-slate-950 p-8">
      <div className="max-w-3xl mx-auto">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-white mb-2">Privacy</h1>
          <p className="text-slate-400">
            Exactly what SENTRY keeps about this machine, and everything that leaves it.
          </p>
        </div>

        {/* Where the data lives. One file, named. */}
        <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5 mb-4">
          <div className="flex items-center gap-2 mb-3">
            <HardDrive className="w-4 h-4 text-slate-400" />
            <h2 className="text-slate-200 font-medium">Where it is kept</h2>
          </div>
          <p className="text-slate-400 text-sm mb-2">
            Everything SENTRY knows is in one file on this PC. There is no account and no server.
          </p>
          <p className="text-slate-300 text-xs font-mono break-all bg-slate-950 border border-slate-800 rounded-lg p-3">
            {report.databasePath}
          </p>
          <p className="text-slate-500 text-xs mt-2">{formatBytes(report.databaseBytes)}</p>
        </div>

        {/* What is in it, counted. */}
        <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5 mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Database className="w-4 h-4 text-slate-400" />
            <h2 className="text-slate-200 font-medium">What is in it</h2>
          </div>
          <p className="text-slate-500 text-xs mb-4">
            Counted from the file itself, not from a description of it.
          </p>
          <div className="space-y-3">
            {report.stored.map((item) => (
              <div key={item.label} className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="text-slate-300 text-sm">{item.label}</div>
                  <div className="text-slate-500 text-xs">{item.description}</div>
                </div>
                <div className="text-slate-200 text-sm font-mono shrink-0">
                  {item.count.toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Everything that leaves the machine. */}
        <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5 mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Globe className="w-4 h-4 text-slate-400" />
            <h2 className="text-slate-200 font-medium">What leaves this PC</h2>
          </div>
          <p className="text-slate-500 text-xs mb-4">
            These are the only addresses SENTRY ever contacts, and only when you ask it to
            download vulnerability data. Scans themselves make no network requests at all.
          </p>
          <div className="space-y-4">
            {report.endpoints.map((endpoint) => (
              <div key={endpoint.url} className="border-l-2 border-slate-700 pl-3">
                <div className="flex items-baseline justify-between gap-3 mb-1">
                  <span className="text-slate-300 text-sm">{endpoint.name}</span>
                  <span className="text-slate-600 text-xs shrink-0">
                    {endpoint.lastContacted
                      ? formatTimestamp(endpoint.lastContacted)
                      : 'never contacted'}
                  </span>
                </div>
                <div className="text-slate-500 text-xs font-mono mb-1">{endpoint.url}</div>
                <div className="text-slate-400 text-xs">{endpoint.sends}</div>
              </div>
            ))}
          </div>
        </div>

        {/* The specific promises, stated so they can be held to. */}
        <div className="bg-slate-800/30 border border-slate-700/50 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <ShieldOff className="w-4 h-4 text-slate-400" />
            <h2 className="text-slate-200 font-medium">What SENTRY never does</h2>
          </div>
          <ul className="space-y-2">
            {report.neverDoes.map((item) => (
              <li key={item} className="text-slate-400 text-sm flex gap-2">
                <span className="text-slate-600 shrink-0">&mdash;</span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
