//! Exercises the remediation path without changing anything.
//!
//! Attempts a Defender policy change while unelevated. Windows refuses it, so
//! the whole chain -- COM, the WMI method call, the return code, the error
//! mapping -- is proven while the machine is provably unmodified.

use sentry_lib::collectors::defender_policy;
use sentry_lib::remediation::{actions, elevation, Action};

fn main() {
    println!(
        "elevated: {}
",
        elevation::is_elevated()
    );

    let before = defender_policy::collect().expect("read policy");
    println!(
        "before: DisableArchiveScanning = {:?}",
        before.archive_scanning_disabled
    );

    println!("\nattempting: {}", Action::EnableArchiveScanning.describe());
    println!(
        "needs admin: {}",
        Action::EnableArchiveScanning.needs_admin()
    );

    match actions::perform(Action::EnableArchiveScanning, true) {
        Ok(outcome) => println!("  succeeded: {}", outcome.detail),
        Err(e) => println!("  refused:   {e}"),
    }

    let after = defender_policy::collect().expect("read policy");
    println!(
        "\nafter:  DisableArchiveScanning = {:?}",
        after.archive_scanning_disabled
    );
    println!(
        "unchanged: {}",
        before.archive_scanning_disabled == after.archive_scanning_disabled
    );

    // The success path, using the only action that changes no configuration.
    let benign = Action::UpdateDefinitions;
    println!(
        "
attempting: {}  (needs admin: {})",
        benign.describe(),
        benign.needs_admin()
    );
    match actions::perform(benign, false) {
        Ok(o) => println!("  succeeded: {}", o.detail),
        Err(e) => println!("  failed:    {e}"),
    }
}
