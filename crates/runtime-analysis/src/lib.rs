//! Host-side coordination for a fixed fixture in a verified local container.

mod docker;

use serde_json::{json, Value};
use std::io::{self, BufRead, IsTerminal, Read, Write};

const FIXTURE: &str = "fixture-arithmetic";
const IMAGE_ID: Option<&str> = option_env!("HELINITY_RUNTIME_IMAGE_ID");

pub fn status() -> Value {
    let preflight = docker::LocalDocker::new().and_then(|docker| docker.preflight(IMAGE_ID));
    json!({
        "fixture": FIXTURE,
        "engine": "local Linux Docker",
        "prerequisites_verified": preflight.is_ok(),
        "reason": preflight.err(),
        "image_id_configured": IMAGE_ID.is_some_and(docker::is_image_id),
        "cargo_test": "fixed fixture only, subject to prerequisites and approval",
        "miri": "not implemented",
        "asan": "not implemented",
        "tsan": "not implemented",
        "fuzzing": "not implemented"
    })
}

pub fn request() -> Value {
    json!({
        "fixture": FIXTURE,
        "approval_required": true,
        "approval_method": "fresh confirmation in an interactive local terminal for each run",
        "executed": false,
        "description": "Request an offline Cargo unit test of the embedded arithmetic fixture in a verified local container."
    })
}

/// Prompt for one execution of the fixed fixture using the verified image.
pub fn run_fixture_in_terminal() -> Result<Value, String> {
    let input = io::stdin();
    let prompt = io::stderr();
    if !input.is_terminal() || !prompt.is_terminal() {
        return Err("An interactive local terminal is required.".to_owned());
    }
    let docker = docker::LocalDocker::new()?;
    let image_id = docker.preflight(IMAGE_ID)?;
    confirm_fixture(input, prompt, image_id)?;
    docker.run_fixture(image_id)?;
    Ok(json!({
        "fixture": FIXTURE,
        "executed": true,
        "outcome": "passed",
        "image_id": image_id
    }))
}

fn confirm_fixture(input: io::Stdin, prompt: io::Stderr, image_id: &str) -> Result<(), String> {
    let mut random = [0; 8];
    getrandom::fill(&mut random)
        .map_err(|_| "A fresh fixture approval phrase could not be generated.")?;
    let challenge = format!("RUN FIXTURE {:016x}", u64::from_ne_bytes(random));
    let mut prompt = prompt.lock();
    writeln!(
        prompt,
        "Run the embedded {FIXTURE} unit test once, offline in isolated local Docker?\nImage {image_id}.\nEnter {challenge} to approve."
    )
    .and_then(|_| prompt.flush())
    .map_err(|_| "The fixture approval prompt could not be displayed.")?;
    drop(prompt);

    let mut response = Vec::new();
    input
        .lock()
        .take((challenge.len() + 2) as u64)
        .read_until(b'\n', &mut response)
        .map_err(|_| "The fixture approval response could not be read.")?;
    if !approval_matches(&response, challenge.as_bytes()) {
        return Err("Runtime execution requires explicit human approval.".to_owned());
    }
    Ok(())
}

fn approval_matches(response: &[u8], challenge: &[u8]) -> bool {
    response
        .strip_suffix(b"\r\n")
        .or_else(|| response.strip_suffix(b"\n"))
        == Some(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_requires_the_current_phrase_and_a_complete_line() {
        let challenge = b"RUN FIXTURE 0123456789abcdef";
        assert!(approval_matches(
            b"RUN FIXTURE 0123456789abcdef\n",
            challenge
        ));
        assert!(approval_matches(
            b"RUN FIXTURE 0123456789abcdef\r\n",
            challenge
        ));
        assert!(!approval_matches(
            b"RUN FIXTURE 0123456789abcdee\n",
            challenge
        ));
        assert!(!approval_matches(
            b"RUN FIXTURE 0123456789abcdef",
            challenge
        ));
        assert!(!approval_matches(
            b"RUN FIXTURE 0123456789abcdef \n",
            challenge
        ));
        assert!(!approval_matches(b"RUN FIXTURE\n", challenge));
    }

    #[test]
    fn request_only_describes_the_fixture() {
        assert_eq!(request()["fixture"], FIXTURE);
        assert_eq!(request()["approval_required"], true);
        assert_eq!(request()["executed"], false);
    }
}
