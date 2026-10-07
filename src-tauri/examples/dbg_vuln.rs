use sentry_lib::collectors::software;
use sentry_lib::database::Database;
use sentry_lib::vulnerabilities::assess;

fn dirs_app_data() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("APPDATA").unwrap()).join("com.ones4.sentry")
}

fn main() {
    let db = Database::open(&dirs_app_data().join("sentry.db")).unwrap();
    let programs = software::collect().unwrap().programs;
    let facts = assess::assess(&db, &programs).unwrap();

    let filter = std::env::args().nth(1).unwrap_or_default().to_lowercase();

    println!(
        "vulnerable={} undetermined={} programs={} never_checked={} no_version={}
",
        facts.vulnerable.len(),
        facts.undetermined.len(),
        facts.programs_total,
        facts.programs_never_checked,
        facts.programs_without_version
    );

    let mut by_program: std::collections::BTreeMap<&str, usize> = Default::default();
    for m in facts.undetermined.iter() {
        *by_program.entry(m.program_name.as_str()).or_default() += 1;
    }
    println!("UNDETERMINED by program:");
    for (name, count) in by_program.iter().take(12) {
        println!("  {count:4}  {name}");
    }
    println!();

    for m in facts.vulnerable.iter() {
        if !filter.is_empty() && !m.program_name.to_lowercase().contains(&filter) {
            continue;
        }
        println!(
            "{} [{}]\n    {}  CVSS {:?} KEV={} EPSS={:?}\n    range: {}   cpe: {}\n    conf: {:?}",
            m.program_name,
            m.installed_version.as_deref().unwrap_or("?"),
            m.cve_id,
            m.cvss_score,
            m.kev.is_some(),
            m.epss.map(|e| format!("{:.1}%", e.as_percent())),
            m.affected_range,
            m.matched_criteria,
            m.confidence,
        );
    }
}
