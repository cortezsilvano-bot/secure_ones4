use super::{probe::ProbeContext, target::RouterTarget, RouterFacts};
use crate::security::CollectorError;

pub trait RouterProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn collect(
        &self,
        target: &RouterTarget,
        ctx: &ProbeContext,
    ) -> Result<RouterFacts, CollectorError>;
}

pub struct GenericIgdProvider;
impl RouterProvider for GenericIgdProvider {
    fn id(&self) -> &'static str {
        "generic_igd"
    }
    fn collect(
        &self,
        target: &RouterTarget,
        ctx: &ProbeContext,
    ) -> Result<RouterFacts, CollectorError> {
        super::collect_target(target, ctx)
    }
}
