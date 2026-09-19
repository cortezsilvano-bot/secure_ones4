//! Read-only commands reporting local Windows security posture.

use crate::collectors::defender::{self, DefenderFacts};
use crate::security::Known;

/// Current Microsoft Defender state.
///
/// Returns `Known<T>` rather than `Result`: a failure to read Defender is not
/// an error the UI should swallow into an empty state, it is a fact about
/// coverage the user needs to see ("Permission required", "Unavailable").
#[tauri::command]
pub async fn get_defender_status() -> Known<DefenderFacts> {
    // WMI is blocking and initialises COM on its calling thread; keep it off
    // the async runtime's worker threads.
    match tauri::async_runtime::spawn_blocking(defender::collect).await {
        Ok(result) => {
            if let Err(e) = &result {
                log::warn!("defender collector failed: {e}");
            }
            result.into()
        }
        Err(join_err) => {
            log::error!("defender collector panicked: {join_err}");
            Known::Unavailable(
                "The Defender check stopped unexpectedly. See the application log for details."
                    .into(),
            )
        }
    }
}
