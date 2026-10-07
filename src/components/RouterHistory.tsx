import { useEffect, useState } from 'react';
import { getRouterHistory } from '../services/ipc';
import type { SavedRouterReport } from '../types';
import { formatTimestamp, isKnown, unknownDetail } from '../types';
import { FirmwareDetails, SettingsDetails } from './RouterPanel';

export function RouterHistory() {
  const [saved, setSaved] = useState<SavedRouterReport[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true;
    void getRouterHistory().then(rows => { if (alive) setSaved(rows); })
      .catch(reason => { if (alive) setError(String(reason)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, []);
  return <section className="mt-8 space-y-3">
    <h2 className="text-lg text-slate-200">Saved router reports</h2>
    <p className="text-sm text-slate-500">Historical observations from standalone router scans. Opening a report does not scan your network.</p>
    {loading && <p className="text-sm text-slate-400">Loading saved reports…</p>}
    {error && <p role="status" className="text-sm text-amber-400">{error}</p>}
    {!loading && !error && !saved.length && <p className="text-sm text-slate-500">No standalone router reports saved yet.</p>}
    {saved.map(entry => <details key={entry.id} className="rounded-xl border border-slate-700 p-4 text-sm text-slate-300">
      <summary className="cursor-pointer">Router scan saved {formatTimestamp(entry.savedAt)}</summary>
      {isKnown(entry.report) ? <div className="mt-3 space-y-3">
        <p>Gateway: {entry.report.data.facts.gateway ?? entry.report.data.facts.target?.address ?? 'Unknown'} · {entry.report.data.facts.target?.interfaceName}</p>
        <p>Observed {formatTimestamp(entry.report.data.facts.collectedAt)}. These results do not establish current status.</p>
        {entry.report.data.findings.length ? entry.report.data.findings.map(finding => <article key={finding.id} className="border-t border-slate-700 pt-3">
          <h3>{finding.severity}: {finding.title}</h3>
          <p className="text-slate-400">{finding.whatHappened}</p>
          <p className="text-slate-400">{finding.whyItMatters}</p>
          <ul className="list-disc pl-5 text-xs text-slate-500">{finding.evidence.map((line, i) => <li key={i}>{line}</li>)}</ul>
        </article>) : <p>No findings were recorded from the available evidence. This does not establish safety.</p>}
        <details><summary className="cursor-pointer">Saved facts and coverage</summary>
          <p className="my-3">Reported model: {entry.report.data.facts.model ?? 'Unknown'}.</p>
          <p className="my-3">TCP ports accepting connections: {entry.report.data.facts.adminPorts.map(p => p.port).join(', ') || 'None recorded; coverage may be incomplete'}.</p>
          <SettingsDetails settings={entry.report.data.facts.settings} />
          <FirmwareDetails assessment={entry.report.data.facts.firmwareAssessment} />
        </details>
      </div> : <p className="mt-3">{unknownDetail(entry.report)}</p>}
    </details>)}
  </section>;
}
