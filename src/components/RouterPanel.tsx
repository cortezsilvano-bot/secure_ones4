import React, { useState } from 'react';
import { Eye, EyeOff, KeyRound, Loader2, Router as RouterIcon } from 'lucide-react';

import { useRouter } from '../hooks/useRouter';
import { FindingCard } from './FindingCard';
import { AsusLoginForm } from './AsusLoginForm';
import { formatTimestamp, isKnown, unknownDetail, unknownLabel } from '../types';
import type { Known, RouterFacts, RouterSettings, WifiAuthentication } from '../types';

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
  const { environment, status, loading, inspect, cancel, select } = useRouter();
  const [consentGeneration, setConsentGeneration] = useState<number | null>(null);
  const reviewing = consentGeneration !== null && consentGeneration === environment?.generation;
  const selected = environment?.candidates.find((target) => target.id === environment.selectedId);
  const controls = (
    <div className="flex flex-wrap items-center gap-2 my-3">
      {selected && environment && !loading && <AsusLoginForm
        key={environment.generation}
        address={selected.address}
        submit={(options) => { setConsentGeneration(null); void inspect(environment.generation, options); }}
      />}
      {environment && environment.candidates.length > 1 && (
        <select
          aria-label="Router to inspect"
          value={environment.selectedId ?? ''}
          disabled={loading}
          onChange={(event) => void select(event.target.value)}
          className="bg-slate-900 text-slate-200 border border-slate-600 rounded px-2 py-1 text-xs max-w-full"
        >
          <option value="" disabled>Select a router</option>
          {environment.candidates.map((target) => (
            <option key={target.id} value={target.id}>{target.address} / {target.interfaceName}</option>
          ))}
        </select>
      )}
      <button
        onClick={() => loading ? void cancel() : setConsentGeneration(environment?.generation ?? null)}
        disabled={!loading && !selected}
        className="text-xs text-blue-300 hover:text-blue-200 border border-slate-600 rounded px-3 py-1"
      >{loading ? 'Cancel request' : 'Review router scan'}</button>
      {reviewing && selected && !loading && (
        <div role="alert" className="w-full rounded border border-amber-700/50 bg-amber-950/20 p-3 text-xs text-slate-300">
          <p>
            Scan {selected.address} on {selected.interfaceName}? This sends discovery messages,
            UPnP queries and connection probes to your network, and may read an SSH greeting.
            These checks can affect sensitive
            routers. No router settings will be changed. Approval applies only to this scan.
          </p>
          <div className="flex gap-3 mt-3">
            <button className="text-slate-300 underline" onClick={() => setConsentGeneration(null)}>Not now</button>
            <button className="text-amber-300 underline" onClick={() => {
              const approved = consentGeneration;
              setConsentGeneration(null);
              if (approved !== null) void inspect(approved);
            }}>Confirm active scan</button>
          </div>
        </div>
      )}
    </div>
  );

  if (loading) {
    return (
      <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6">
        <Loader2 className="w-4 h-4 text-slate-500 animate-spin" />
        <span className="text-slate-400 text-sm">Loading router results...</span>
        {controls}
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
        <p className="text-slate-500 text-sm">{environment?.reason ?? (status.state === 'not_scanned'
          ? 'No current router scan. Opening this panel does not probe your router.'
          : unknownDetail(status))}</p>
        {controls}
      </div>
    );
  }

  const facts = status.data.facts;
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
        {facts.target && <> &middot; {facts.target.interfaceName}</>}
      </p>
      <p className="text-slate-500 text-xs">Checked {formatTimestamp(facts.collectedAt)}</p>

      {controls}
      <div className="space-y-3 my-4">
        {status.data.historyError && <p role="status" className="text-xs text-amber-400">{status.data.historyError}</p>}
        <h4 className="text-xs uppercase tracking-wider text-slate-500">Findings from this router scan</h4>
        {status.data.findings.length ? status.data.findings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        )) : <p className="text-xs text-slate-500">No findings from the available evidence. Unchecked settings and services remain unverified.</p>}
      </div>
      {facts.identity && (
        <Section icon={Eye} title="Reported router identity">
          <Row label="Manufacturer" value={isKnown(facts.identity.vendor) ? facts.identity.vendor.data : 'Unrecognized'} />
          <Row label="Model" value={isKnown(facts.identity.reportedModel) ? facts.identity.reportedModel.data : 'Unknown'} />
          <Row label="Installed firmware" value={isKnown(facts.identity.firmwareVersion) ? facts.identity.firmwareVersion.data : 'Not checked'} />
          {facts.identity.evidence.map((item) => <li key={item} className="text-slate-500 text-xs">{item}</li>)}
          <li className="text-slate-500 text-xs">Settings coverage is listed below; missing values remain unchecked.</li>
        </Section>
      )}
      {/* What was actually established. */}
      <Section icon={Eye} title="What SENTRY checked">
        <Row
          label="Gateway UPnP discovery"
          value={isKnown(facts.upnpDiscovery) && facts.upnpDiscovery.data
            ? 'Responded'
            : 'Could not be determined'}
        />
        {!isKnown(facts.upnpDiscovery) && (
          <li className="text-slate-500 text-xs">{unknownDetail(facts.upnpDiscovery)}</li>
        )}
        <Row
          label="Enabled mappings in the UPnP table"
          value={
            forwards === null
              ? 'Could not be read'
              : forwards.filter((f) => f.enabled).length === 0
                ? 'None in this table'
                : `${forwards.filter((f) => f.enabled).length}`
          }
        />
        <Row
          label="TCP ports accepting connections"
          value={
            facts.adminPorts.length === 0
              ? (isKnown(facts.adminProbe) ? 'None on tested ports' : 'Inconclusive')
              : facts.adminPorts.map((p) => p.port).join(', ')
          }
        />
        <li className="text-slate-500 text-xs">
          A port number alone does not establish protocol or encryption. A configured mapping does not prove
          public Internet reachability; other forwarding rules may not appear in UPnP.
        </li>
        {facts.adminPorts.map((port) => (
          <Row key={port.port} label={`Port ${port.port}: observed protocol / transport`}
            value={`${isKnown(port.protocol) ? port.protocol.data.toUpperCase() : 'Unverified'} / ${isKnown(port.encryption) ? port.encryption.data : 'unverified'}`} />
        ))}
        {(facts.observedServices ?? []).map((service, index) => (
          <Row key={`observed-${service.port}-${index}`} label={`Observed service on port ${service.port}`}
            value={`${isKnown(service.protocol) ? service.protocol.data.toUpperCase() : 'Unverified'} / ${isKnown(service.encryption) ? service.encryption.data : 'unverified'}`} />
        ))}
        {!!facts.observedServices?.length && <li className="text-slate-500 text-xs">
          Service evidence comes from existing read-only requests. These endpoints may serve UPnP data;
          they are not confirmed login pages.
        </li>}
        {!isKnown(facts.adminProbe) && (
          <li className="text-slate-500 text-xs">{unknownDetail(facts.adminProbe)}</li>
        )}
      </Section>

      {forwards === null && facts.forwardsUnavailableReason && (
        <p className="text-slate-500 text-xs mb-4 -mt-2 pl-6">
          {facts.forwardsUnavailableReason}
        </p>
      )}

      <SettingsDetails settings={facts.settings} />
      <FirmwareDetails assessment={facts.firmwareAssessment} />

      {/* Things that need the router's own password. */}
      {facts.requiresRouterLogin.length > 0 && <Section icon={KeyRound} title="Beyond this unauthenticated scan">
        {facts.requiresRouterLogin.map((item) => (
          <li key={item} className="text-slate-500 text-xs leading-relaxed">
            {item}
          </li>
        ))}
        <li className="text-slate-600 text-xs italic mt-1.5 list-none">
          The separately confirmed ASUS settings scan reads supported settings after login.
          Password strength and default-password testing are not included.
        </li>
      </Section>}

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

const authenticationLabels: Record<WifiAuthentication, string> = {
  open: 'Open', wep: 'WEP', wpa_personal: 'WPA-Personal',
  wpa2_personal: 'WPA2-Personal', wpa3_personal: 'WPA3-Personal',
  wpa2_wpa3_personal: 'WPA2/WPA3-Personal', enterprise: 'Enterprise',
  unrecognized: 'Unrecognized mode',
};

export function FirmwareDetails({ assessment }: { assessment?: RouterFacts['firmwareAssessment'] }) {
  const matches = assessment?.advisoryMatches;
  const answer = (value?: Known<boolean>) => value && isKnown(value)
    ? value.data ? 'Yes' : 'No' : value ? unknownLabel(value) : 'Not checked';
  return (
    <Section icon={Eye} title="Firmware coverage">
      <Row label="Update available" value={answer(assessment?.updateAvailable)} />
      <Row label="ASUS regional end of support established" value={answer(assessment?.endOfSupport)} />
      {assessment?.catalogScope && <li className="text-xs text-slate-500">{assessment.catalogScope}</li>}
      {assessment?.advisoryReviews && isKnown(assessment.advisoryReviews) && assessment.advisoryReviews.data.map((review) => (
        <li key={review.id} className="text-xs text-slate-400">
          <strong>{review.id}</strong> — {review.disposition === 'fix_documented' ? 'Published fix documented' : review.disposition === 'review_required' ? 'Applicability needs review' : 'Affected build documented'}.
          <p>{review.detail}</p>
          {review.sources.map((source) => <p key={source} className="break-words text-slate-500">{source}</p>)}
        </li>
      ))}
      {matches && isKnown(matches) ? (
        matches.data.length ? matches.data.map((match, index) => (
          <li key={`${match.id}-${index}`} className="text-xs text-slate-400">{match.id} — {match.source}</li>
        )) : <li className="text-xs text-slate-500">No exact matches in the supplied catalog. This does not establish that the firmware is safe or current.</li>
      ) : <li className="text-xs text-slate-500">Advisories: {matches ? unknownLabel(matches) : 'Not checked'}. {matches ? unknownDetail(matches) : ''}</li>}
      {assessment?.catalogReviewedAt && <li className="text-xs text-slate-500">Catalog reviewed {formatTimestamp(assessment.catalogReviewedAt)}</li>}
      {assessment?.catalogValidUntil && <li className="text-xs text-slate-500">Catalog review expires {formatTimestamp(assessment.catalogValidUntil)}</li>}
      {assessment?.lifecycleEvidence?.map((item, index) => <li key={`lifecycle-${index}`} className="text-xs text-slate-500 break-words">{item}</li>)}
      {assessment?.releaseEvidence?.map((item, index) => <li key={index} className="text-xs text-slate-500 break-words">{item}</li>)}
      <li className="text-xs text-slate-500">Firmware identity comes from the ASUS settings scan. Release comparisons use dated bundled evidence; no firmware is downloaded or installed.</li>
    </Section>
  );
}

function wirelessProfileLabel(id: string, index: number): string {
  const match = /^wl([01])(?:\.(\d{1,2}))?$/.exec(id);
  return match ? `Radio ${Number(match[1]) + 1}${match[2] ? `, guest ${Number(match[2])}` : ', primary network'}` : `Wi-Fi profile ${index + 1}`;
}

export function SettingsDetails({ settings }: { settings?: RouterSettings }) {
  const toggle = (value?: Known<boolean>) => !value || value.state === 'not_scanned'
    ? 'Not checked' : isKnown(value) ? (value.data ? 'Enabled' : 'Disabled') : unknownLabel(value);
  const profiles = settings?.wifiProfiles;
  return (
    <Section icon={KeyRound} title="Router settings coverage">
      <Row label="WAN management configuration" value={toggle(settings?.wanManagementEnabled)} />
      <Row label="IPv4 firewall configuration" value={toggle(settings?.ipv4FirewallEnabled)} />
      <Row label="IPv6 firewall configuration" value={toggle(settings?.ipv6FirewallEnabled)} />
      <Row label="Wi-Fi profile inventory" value={settings && isKnown(settings.wifiInventoryComplete)
        ? settings.wifiInventoryComplete.data ? 'Complete for this router' : 'Incomplete' : 'Not established'} />
      {profiles && isKnown(profiles) ? profiles.data.map((profile, index) => (
        <li key={`${profile.profileId}-${index}`} className="text-xs text-slate-400">
          {wirelessProfileLabel(profile.profileId, index)}: {toggle(profile.enabled)}; authentication: {isKnown(profile.authentication)
            ? authenticationLabels[profile.authentication.data] ?? 'Unrecognized mode'
            : unknownLabel(profile.authentication)}; WPS: {toggle(profile.wpsEnabled)}
        </li>
      )) : <li className="text-xs text-slate-500">Wi-Fi authentication and WPS: {profiles ? unknownLabel(profiles) : 'Not checked'}.</li>}
      <li className="text-xs text-slate-500">
        ASUS settings scans read firewall, WAN management and a bounded wireless inventory. Configured values do not prove effective
        filtering, Internet reachability, or password strength.
      </li>
    </Section>
  );
}
