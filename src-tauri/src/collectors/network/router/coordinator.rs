//! Shared router lifecycle for dashboard, panel and background scans.
use super::{
    probe::ProbeContext,
    provider::{GenericIgdProvider, RouterProvider},
    target::{self, RouterTarget},
    RouterFacts,
};
use crate::{
    collectors::network::{
        interfaces::{self, InterfaceFacts},
        neighbors,
    },
    security::Known,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterEnvironment {
    pub generation: u64,
    pub candidates: Vec<RouterTarget>,
    pub selected_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Default)]
struct State {
    key: Option<Vec<String>>,
    generation: u64,
    candidates: Vec<RouterTarget>,
    selected_id: Option<String>,
    reason: Option<String>,
    active: Option<ProbeContext>,
    cached: Option<(Instant, Known<RouterFacts>)>,
}

pub struct RouterCoordinator {
    refresh_gate: Mutex<()>,
    state: Mutex<State>,
    scan_gate: Mutex<()>,
    /// Full dashboards are serialized too, so older persistence cannot win a race.
    pub dashboard_gate: Mutex<()>,
    provider: Arc<dyn RouterProvider>,
}

impl Default for RouterCoordinator {
    fn default() -> Self {
        Self::with_provider(Arc::new(GenericIgdProvider))
    }
}

impl RouterCoordinator {
    fn with_provider(provider: Arc<dyn RouterProvider>) -> Self {
        Self {
            refresh_gate: Mutex::new(()),
            state: Mutex::new(State::default()),
            scan_gate: Mutex::new(()),
            dashboard_gate: Mutex::new(()),
            provider,
        }
    }
    pub fn environment(&self) -> RouterEnvironment {
        let s = self.state.lock();
        RouterEnvironment {
            generation: s.generation,
            candidates: s.candidates.clone(),
            selected_id: s.selected_id.clone(),
            reason: s.reason.clone(),
        }
    }
    pub fn generation(&self) -> u64 {
        self.state.lock().generation
    }
    pub fn refresh_network(&self) -> RouterEnvironment {
        let _refresh = self.refresh_gate.lock();
        match interfaces::collect() {
            Ok(facts) => {
                let neighbors = neighbors::collect().ok();
                self.update_network(&facts, neighbors.as_ref());
            }
            Err(e) => {
                let mut s = self.state.lock();
                if s.key.is_some() || s.generation == 0 {
                    Self::invalidate(&mut s);
                    s.key = None;
                    s.candidates.clear();
                    s.selected_id = None;
                }
                s.reason = Some(format!("Network information is unavailable: {e}"));
            }
        }
        self.environment()
    }
    fn invalidate(s: &mut State) {
        s.generation += 1;
        if let Some(ctx) = s.active.take() {
            ctx.cancel();
        }
        s.cached = None;
    }
    pub(crate) fn update_network(
        &self,
        facts: &InterfaceFacts,
        neighbors: Option<&neighbors::NeighborFacts>,
    ) {
        let key = target::network_key(facts);
        let mut targets = target::candidates(facts, 0);
        if let Some(neighbors) = neighbors {
            for target in &mut targets {
                let matches: Vec<_> = neighbors
                    .devices()
                    .filter(|n| n.ip == target.address.to_string())
                    .collect();
                if matches.len() == 1 {
                    target.gateway_mac = matches[0].mac.clone();
                }
            }
        }
        let mut s = self.state.lock();
        if s.key.as_ref() == Some(&key) {
            let mut identity_changed = false;
            for candidate in &targets {
                if let Some(previous) = s.candidates.iter_mut().find(|t| {
                    t.address == candidate.address && t.interface_id == candidate.interface_id
                }) {
                    match (&previous.gateway_mac, &candidate.gateway_mac) {
                        (Some(old), Some(new)) if old != new => identity_changed = true,
                        (None, Some(new)) => previous.gateway_mac = Some(new.clone()),
                        _ => {}
                    }
                }
            }
            // Learning a previously unknown MAC or aging out an ARP entry does not
            // prove the network changed. A different observed MAC does.
            if !identity_changed {
                return;
            }
        }
        Self::invalidate(&mut s);
        s.key = Some(key);
        for (index, t) in targets.iter_mut().enumerate() {
            t.network_generation = s.generation;
            t.id = format!("router-{}-{index}", s.generation);
        }
        s.selected_id = (targets.len() == 1).then(|| targets[0].id.clone());
        s.reason = match targets.len() {
            0 => Some("No unambiguous private IPv4 gateway is available. IPv6-only, public, off-subnet and overlapping gateway routes are not supported yet.".into()),
            1 => None,
            _ => Some("Multiple local gateways are available. Select the router to inspect.".into()),
        };
        s.candidates = targets;
    }
    pub fn select(&self, id: &str, generation: u64) -> Result<RouterEnvironment, String> {
        let mut s = self.state.lock();
        if generation != s.generation {
            return Err("The network changed. Refresh the router list.".into());
        }
        let Some(index) = s.candidates.iter().position(|t| t.id == id) else {
            return Err("Unknown router target.".into());
        };
        if s.selected_id.as_deref() == Some(id) {
            drop(s);
            return Ok(self.environment());
        }
        Self::invalidate(&mut s);
        let next_generation = s.generation;
        for (i, t) in s.candidates.iter_mut().enumerate() {
            t.network_generation = next_generation;
            t.id = format!("router-{next_generation}-{i}");
        }
        s.selected_id = Some(s.candidates[index].id.clone());
        s.reason = None;
        drop(s);
        Ok(self.environment())
    }
    pub fn cancel(&self, generation: u64) {
        let mut s = self.state.lock();
        if s.generation == generation {
            let selected = s
                .candidates
                .iter()
                .position(|t| Some(&t.id) == s.selected_id.as_ref());
            // Invalidate queued requests as well as the request currently in flight.
            Self::invalidate(&mut s);
            let next = s.generation;
            for (i, target) in s.candidates.iter_mut().enumerate() {
                target.network_generation = next;
                target.id = format!("router-{next}-{i}");
            }
            s.selected_id = selected.map(|i| s.candidates[i].id.clone());
            s.reason = Some("Router scan cancelled. Run a new scan to refresh results.".into());
        }
    }
    /// Reading status is passive, including when the cache is empty or expired.
    pub fn cached(&self, generation: u64) -> Known<RouterFacts> {
        let s = self.state.lock();
        if s.generation != generation {
            return stale();
        }
        match &s.cached {
            Some((at, facts)) if at.elapsed() < Duration::from_secs(30) => facts.clone(),
            Some(_) => Known::Unavailable("Router results have expired. Start a router scan only when you want active network checks.".into()),
            None => Known::NotScanned,
        }
    }

    /// Approval applies to one requested scan of this exact context, never future scans.
    pub fn scan_confirmed(&self, generation: u64, confirmed: bool) -> Known<RouterFacts> {
        if !confirmed {
            return Known::PermissionRequired(
                "Confirm the active router scan before any network requests are sent.".into(),
            );
        }
        self.inspect_with(generation, true, || {
            self.refresh_network();
        })
    }
    fn inspect_with(
        &self,
        generation: u64,
        force: bool,
        recheck: impl FnOnce(),
    ) -> Known<RouterFacts> {
        self.inspect_using(generation, force, recheck, self.provider.as_ref())
    }

    pub fn scan_asus_confirmed(
        &self,
        generation: u64,
        confirmed: bool,
        options: super::asus_session::LoginOptions,
    ) -> Known<RouterFacts> {
        if !confirmed {
            return Known::PermissionRequired(
                "Confirm this ASUS login and settings scan first.".into(),
            );
        }
        let provider = match super::asus_session::AsusProvider::new(options) {
            Ok(provider) => provider,
            Err(error) => return error.into_known(),
        };
        self.inspect_using(
            generation,
            true,
            || {
                self.refresh_network();
            },
            &provider,
        )
    }

    fn inspect_using(
        &self,
        generation: u64,
        force: bool,
        recheck: impl FnOnce(),
        provider: &dyn RouterProvider,
    ) -> Known<RouterFacts> {
        // Serialize and coalesce overlapping requests. The active scan has a 20s deadline.
        let Some(_gate) = self
            .scan_gate
            .try_lock_for(super::probe::SCAN_DEADLINE + Duration::from_secs(3))
        else {
            return Known::Unavailable(
                "A router inspection is still running. Try again after it finishes.".into(),
            );
        };
        let (target, ctx) = {
            let mut s = self.state.lock();
            if s.generation != generation {
                return stale();
            }
            if !force {
                if let Some((at, facts)) = &s.cached {
                    if at.elapsed() < Duration::from_secs(30) {
                        return facts.clone();
                    }
                }
            }
            let Some(target) = s
                .candidates
                .iter()
                .find(|t| Some(&t.id) == s.selected_id.as_ref())
                .cloned()
            else {
                return Known::Unavailable(
                    s.reason
                        .clone()
                        .unwrap_or_else(|| "Select a router first.".into()),
                );
            };
            let ctx = ProbeContext::new(&target);
            s.reason = None;
            s.active = Some(ctx.clone());
            (target, ctx)
        };
        let result = provider.collect(&target, &ctx);
        recheck();
        let mut s = self.state.lock();
        if s.generation != generation {
            return stale();
        }
        s.active = None;
        let result = match result {
            Ok(mut facts) => {
                facts.target = Some(target);
                facts.provider_id = Some(provider.id().into());
                facts.requests_sent = ctx.request_count();
                facts.observed_services = ctx.observed_services();
                Known::Known(facts)
            }
            Err(e) => e.into_known(),
        };
        s.cached = Some((Instant::now(), result.clone()));
        result
    }

    /// Hold the generation steady while committing a result to the local store.
    pub fn if_current<T>(&self, generation: u64, f: impl FnOnce() -> T) -> Option<T> {
        let s = self.state.lock();
        (s.generation == generation).then(f)
    }
}

fn stale() -> Known<RouterFacts> {
    Known::Unavailable(
        "The router or network changed during this scan. Run a new scan for the current network."
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn asus_consent_and_stale_context_reject_before_transport() {
        let c = RouterCoordinator::default();
        c.update_network(&target::fixture(), None);
        let generation = c.generation();
        let options = || super::super::asus_session::LoginOptions {
            username: "admin".into(),
            password: "fixture-only".into(),
            https_port: 8443,
            certificate_pem: String::new(),
            support_region: Default::default(),
        };
        assert!(matches!(
            c.scan_asus_confirmed(generation, false, options()),
            Known::PermissionRequired(_)
        ));
        c.cancel(generation);
        // The stale generation exits inspect_using before collect or recheck.
        assert!(matches!(
            c.scan_asus_confirmed(generation, true, options()),
            Known::Unavailable(_)
        ));
        assert!(!c.cached(c.generation()).is_known());
    }
    use crate::security::CollectorError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fake(AtomicUsize);
    impl RouterProvider for Fake {
        fn id(&self) -> &'static str {
            "fake"
        }
        fn collect(
            &self,
            _: &RouterTarget,
            _: &ProbeContext,
        ) -> Result<RouterFacts, CollectorError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(RouterFacts::default())
        }
    }
    #[test]
    fn observed_services_flow_through_cache_and_rules_without_network_io() {
        struct Observed;
        impl RouterProvider for Observed {
            fn id(&self) -> &'static str {
                "offline_fixture"
            }
            fn collect(
                &self,
                target: &RouterTarget,
                ctx: &ProbeContext,
            ) -> Result<RouterFacts, CollectorError> {
                ctx.fixture_http_response(&format!("http://{}:49000/root.xml", target.address))?;
                Ok(RouterFacts::default())
            }
        }
        let c = RouterCoordinator::with_provider(Arc::new(Observed));
        c.update_network(&target::fixture(), None);
        let generation = c.generation();
        let result = c.inspect_with(generation, true, || {});
        let facts = result.value().unwrap();
        assert_eq!(facts.requests_sent, 0);
        assert_eq!(facts.observed_services.len(), 1);
        assert_eq!(facts.provider_id.as_deref(), Some("offline_fixture"));
        let cached = c.cached(generation);
        let findings = crate::rules::router::evaluate(cached.value().unwrap());
        let found = findings.iter().find(|f| f.rule_id == "RTR-005").unwrap();
        assert_eq!(
            found.affected_asset,
            Some(facts.target.as_ref().unwrap().asset())
        );
        let serialized = serde_json::to_value(&cached).unwrap();
        assert_eq!(
            serialized["data"]["observedServices"][0]["protocol"]["data"],
            "http"
        );
        let stale = c.inspect_with(generation, true, || c.cancel(generation));
        assert!(!stale.is_known());
        assert!(!c.cached(c.generation()).is_known());
    }

    #[test]
    fn passive_status_and_unconfirmed_requests_never_invoke_the_provider() {
        let provider = Arc::new(Fake(AtomicUsize::new(0)));
        let c = RouterCoordinator::with_provider(provider.clone());
        c.update_network(&target::fixture(), None);
        let generation = c.generation();
        assert!(matches!(c.cached(generation), Known::NotScanned));
        assert!(matches!(
            c.scan_confirmed(generation, false),
            Known::PermissionRequired(_)
        ));
        c.state.lock().cached = Some((
            Instant::now() - Duration::from_secs(60),
            Known::Known(RouterFacts::default()),
        ));
        assert!(matches!(c.cached(generation), Known::Unavailable(_)));
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn repeated_requests_share_results_and_old_generations_cannot_publish() {
        let provider = Arc::new(Fake(AtomicUsize::new(0)));
        let c = RouterCoordinator::with_provider(provider.clone());
        let mut network = target::fixture();
        c.update_network(&network, None);
        let generation = c.generation();
        assert!(c.inspect_with(generation, false, || {}).is_known());
        assert!(c.inspect_with(generation, false, || {}).is_known());
        assert_eq!(provider.0.load(Ordering::SeqCst), 1);
        let result = c.inspect_with(generation, true, || {
            network.interfaces[0].dns_servers.push("192.168.1.2".into());
            c.update_network(&network, None);
        });
        assert!(!result.is_known());
        assert!(c
            .if_current(generation, || panic!("stale commit"))
            .is_none());
        assert!(!c.inspect_with(generation, false, || {}).is_known());
    }
    #[test]
    fn only_issued_current_targets_can_be_selected() {
        let c = RouterCoordinator::default();
        let mut network = target::fixture();
        network.interfaces[0].gateways.push("192.168.1.2".into());
        c.update_network(&network, None);
        let env = c.environment();
        assert!(env.selected_id.is_none());
        assert!(c.select("http://8.8.8.8", env.generation).is_err());
        let selected = c.select(&env.candidates[1].id, env.generation).unwrap();
        assert!(selected.generation > env.generation);
        assert!(c.select(&env.candidates[0].id, env.generation).is_err());
    }

    #[test]
    fn cancellation_invalidates_requests_that_have_not_started_yet() {
        let provider = Arc::new(Fake(AtomicUsize::new(0)));
        let c = RouterCoordinator::with_provider(provider.clone());
        c.update_network(&target::fixture(), None);
        let old = c.generation();
        c.cancel(old);
        assert!(!c.inspect_with(old, true, || {}).is_known());
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);
        let current = c.generation();
        c.cancel(old);
        assert_eq!(
            c.generation(),
            current,
            "late cancel must not cancel a new generation"
        );
        assert!(c.inspect_with(current, true, || {}).is_known());
    }

    #[test]
    fn gateway_mac_changes_invalidate_but_cache_aging_does_not() {
        use neighbors::{Neighbor, NeighborFacts, NeighborState};
        let c = RouterCoordinator::default();
        let network = target::fixture();
        c.update_network(&network, None);
        let first = c.generation();
        let mut neighbors = NeighborFacts {
            neighbors: vec![Neighbor {
                ip: "192.168.1.1".into(),
                mac: Some("00:11:22:33:44:55".into()),
                state: NeighborState::Reachable,
                interface_index: 1,
                is_multicast: false,
            }],
            ..Default::default()
        };
        c.update_network(&network, Some(&neighbors));
        assert_eq!(c.generation(), first);
        c.update_network(&network, Some(&NeighborFacts::default()));
        assert_eq!(c.generation(), first);
        neighbors.neighbors[0].mac = Some("00:11:22:33:44:66".into());
        c.update_network(&network, Some(&neighbors));
        assert!(c.generation() > first);
    }

    #[test]
    fn overlapping_inspections_share_one_provider_run() {
        use std::sync::mpsc;
        struct Blocking {
            calls: AtomicUsize,
            entered: mpsc::Sender<()>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl RouterProvider for Blocking {
            fn id(&self) -> &'static str {
                "blocking"
            }
            fn collect(
                &self,
                _: &RouterTarget,
                _: &ProbeContext,
            ) -> Result<RouterFacts, CollectorError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                Ok(RouterFacts::default())
            }
        }
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let provider = Arc::new(Blocking {
            calls: AtomicUsize::new(0),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        let c = Arc::new(RouterCoordinator::with_provider(provider.clone()));
        c.update_network(&target::fixture(), None);
        let generation = c.generation();
        let first = c.clone();
        let a = std::thread::spawn(move || first.inspect_with(generation, false, || {}));
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = c.clone();
        let b = std::thread::spawn(move || second.inspect_with(generation, false, || {}));
        release_tx.send(()).unwrap();
        assert!(a.join().unwrap().is_known());
        assert!(b.join().unwrap().is_known());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }
}
