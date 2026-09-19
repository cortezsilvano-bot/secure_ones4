import React, { useEffect, useState } from 'react';
import { Eye, EyeOff, KeyRound, Loader2, Router as RouterIcon } from 'lucide-react';

import { getRouterStatus } from '../services/ipc';
import type { Known, RouterFacts } from '../types';
import { isKnown, unknownDetail } from '../types';

/**
 * The router, and the honest boundaries around it.
 *
 * Most consumer "router security" features quietly present things they cannot
 * actually determine from inside the network as if they had checked them. This
 * panel keeps the three categories visibly apart: what was established, what
 * would need the router's password, and what cannot be answered from here at
 * all.
 */
export function RouterPanel() {
  const [status, setStatus] = useState<Known<RouterFacts>>({ state: 'not_scanned' });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    getRouterStatus().then((result) => {
      if (!alive) return;
      setStatus(result);
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  if (loading) {
    return (
      <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6 flex items-center gap-3">
        <Loader2 className="w-4 h-4 text-slate-500 animate-spin" />
        <span className="text-slate-400 text-sm">Checking your router...</span>
      </div>
    );
  }

  if (!isKnown(status)) {
    return (
      <div className="bg-slate-800/30 border border-slate-700/50 border-dashed rounded-2xl p-6">
        <div className="flex items-center gap-2 mb-2">
          <RouterIcon className="w-4 h-4 text-slate-500" />
          <h3 className="text-slate-300 font-medium">Router</h3>
        </div>
        <p className="text-slate-500 text-sm">{unknownDetail(status)}</p>
      </div>
    );
  }

  const facts = status.data;
  const forwards = facts.portForwards;

  return (
    <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6">
      <div className="flex items-center gap-2 mb-1">
        <RouterIcon className="w-4 h-4 text-slate-400" />
        <h3 className="text-slate-200 font-medium">Your router</h3>
      </div>
      <p className="text-slate-500 text-xs mb-4 font-mono">
        {facts.gateway ?? 'address unknown'}
        {facts.model && <> &middot; {facts.model}</>}
      </p>

      {/* What was actually established. */}
      <Section icon={Eye} title="What SENTRY checked">
        <Row label="UPnP" value={facts.upnpEnabled ? 'On' : 'Off or not answering'} />
        <Row
          label="Ports forwarded from the internet"
          value={
            forwards === null
              ? 'Could not be read'
              : forwards.filter((f) => f.enabled).length === 0
                ? 'None'
                : `${forwards.filter((f) => f.enabled).length}`
          }
        />
        <Row
          label="Admin pages reachable from here"
          value={
            facts.adminPorts.length === 0
              ? 'None found'
              : facts.adminPorts.map((p) => p.port).join(', ')
          }
        />
      </Section>

      {forwards === null && facts.forwardsUnavailableReason && (
        <p className="text-slate-500 text-xs mb-4 -mt-2 pl-6">
          {facts.forwardsUnavailableReason}
        </p>
      )}

      {/* Things that need the router's own password. */}
      <Section icon={KeyRound} title="Needs your router's password">
        {facts.requiresRouterLogin.map((item) => (
          <li key={item} className="text-slate-500 text-xs leading-relaxed">
            {item}
          </li>
        ))}
        <li className="text-slate-600 text-xs italic mt-1.5 list-none">
          SENTRY does not ask for that password and does not sign in to your router.
        </li>
      </Section>

      {/* Things that genuinely cannot be answered from inside the network. */}
      <Section icon={EyeOff} title="Cannot be determined from here">
        {facts.cannotDetermine.map((item) => (
          <li key={item} className="text-slate-500 text-xs leading-relaxed">
            {item}
          </li>
        ))}
      </Section>
    </div>
  );
}

function Section({
  icon: Icon,
  title,
  children,
}: {
  icon: typeof Eye;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mb-4 last:mb-0">
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-3.5 h-3.5 text-slate-500 shrink-0" />
        <h4 className="text-xs uppercase tracking-wider text-slate-500">{title}</h4>
      </div>
      <ul className="space-y-1.5 pl-6">{children}</ul>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <li className="flex items-baseline justify-between gap-3 text-xs">
      <span className="text-slate-400">{label}</span>
      <span className="text-slate-300 text-right shrink-0">{value}</span>
    </li>
  );
}
