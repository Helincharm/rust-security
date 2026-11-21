use crate::{Finding, Report, Rule, MAX_INPUT_BYTES};
use semver::{BuildMetadata, Version};
use serde::Deserialize;
use std::sync::OnceLock;
use toml::Spanned;

const INDEX: &str = include_str!("../data/rustsec-index.json");
static ADVISORIES: OnceLock<Result<AdvisoryIndex, serde_json::Error>> = OnceLock::new();

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    package: Vec<LockedPackage>,
}

#[derive(Deserialize)]
struct LockedPackage {
    name: String,
    version: Spanned<String>,
    source: Option<String>,
}

#[derive(Deserialize)]
struct AdvisoryIndex {
    entries: Vec<Advisory>,
}

#[derive(Deserialize)]
struct Advisory {
    id: String,
    #[serde(rename = "crate")]
    package: String,
    ranges: Vec<Vec<Event>>,
    versions: Vec<Version>,
    attribution: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Event {
    Introduced(String),
    Fixed(Version),
    LastAffected(Version),
    Limit(Version),
}

impl Advisory {
    fn affects(&self, version: &Version) -> bool {
        self.versions
            .iter()
            .any(|candidate| precedence(candidate) == *version)
            || self
                .ranges
                .iter()
                .any(|events| range_contains(events, version))
    }
}

fn precedence(version: &Version) -> Version {
    let mut version = version.clone();
    version.build = BuildMetadata::EMPTY;
    version
}

fn range_contains(events: &[Event], version: &Version) -> bool {
    let mut active = false;
    for event in events {
        match event {
            Event::Introduced(value) => {
                active = value == "0"
                    || Version::parse(value).is_ok_and(|start| *version >= precedence(&start));
            }
            Event::Fixed(end) | Event::Limit(end) => {
                if active && *version < precedence(end) {
                    return true;
                }
                active = false;
            }
            Event::LastAffected(end) => {
                if active && *version <= precedence(end) {
                    return true;
                }
                active = false;
            }
        }
    }
    active
}

fn is_crates_io(origin: Option<&str>) -> bool {
    matches!(
        origin,
        Some("registry+https://github.com/rust-lang/crates.io-index")
            | Some("registry+https://index.crates.io/")
            | Some("sparse+https://index.crates.io/")
    )
}

pub fn analyze_lock(relative_path: &str, source: &str) -> Vec<Finding> {
    let mut report = Report::new(relative_path, source, "cargo-lock", "dependency");
    if source.len() > MAX_INPUT_BYTES {
        report.coverage(
            "HEL-LOCK-LIMIT",
            "Cargo.lock exceeds the offline parser size limit.",
        );
        return report.finish();
    }
    let Ok(lock) = toml::from_str::<Lock>(source) else {
        report.coverage(
            "HEL-LOCK-PARSE",
            "The Cargo.lock package data could not be parsed.",
        );
        return report.finish();
    };
    let Ok(database) = ADVISORIES.get_or_init(|| serde_json::from_str(INDEX)) else {
        report.coverage(
            "HEL-LOCK-INDEX",
            "The bundled advisory snapshot could not be read.",
        );
        return report.finish();
    };

    let mut invalid_version = false;
    for package in lock
        .package
        .iter()
        .filter(|package| is_crates_io(package.source.as_deref()))
    {
        let Ok(version) = Version::parse(package.version.get_ref()) else {
            invalid_version = true;
            continue;
        };
        for advisory in database
            .entries
            .iter()
            .filter(|entry| entry.package == package.name)
        {
            if advisory.affects(&precedence(&version)) {
                report.push(Rule {
                    id: &advisory.id,
                    cwe: None,
                    severity: "medium",
                    confidence: "high",
                    explanation: "The locked crates.io version falls in the advisory's affected range. Review the advisory's platform and usage conditions.",
                    remediation: "Check the advisory for fixed releases or mitigation and update the dependency using Cargo.",
                }, Some(package.version.span()), format!("{} {} ({})", advisory.package, version, advisory.attribution));
            }
        }
    }
    if invalid_version {
        report.coverage(
            "HEL-LOCK-VERSION",
            "Cargo.lock contains a crates.io version that could not be checked.",
        );
    }
    report.finish()
}
