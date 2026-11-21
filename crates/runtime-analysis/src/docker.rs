use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
const ENDPOINT: &str = "npipe:////./pipe/dockerDesktopLinuxEngine";
#[cfg(not(windows))]
const ENDPOINT: &str = "unix:///var/run/docker.sock";
const ENGINE_TIMEOUT: Duration = Duration::from_secs(4);
const RUN_TIMEOUT: Duration = Duration::from_secs(45);
const OUTPUT_LIMIT: usize = 128 * 1024;
const TMPFS: &str = "rw,nosuid,nodev,exec,size=64m,mode=0700,uid=65532,gid=65532";
const SECCOMP: &str = "seccomp=builtin";
const NO_NEW_PRIVILEGES: &str = "no-new-privileges=true";
const ENTRYPOINT: &str = "/usr/bin/env";
const OWNER_LABEL: &str = "io.helinity.runtime.owner";
const CONTAINER_COMMAND: &[&str] = &[
    "-i",
    "PATH=/usr/bin:/bin",
    "HOME=/work",
    "CARGO_HOME=/work/.cargo",
    "TMPDIR=/work",
    "/bin/sh",
    "-eu",
    "-c",
];

pub(super) struct LocalDocker {
    binary: PathBuf,
    config: PathBuf,
    container_name: String,
    owner: String,
    #[cfg(windows)]
    _client_lock: fs::File,
    #[cfg(windows)]
    system_root: std::ffi::OsString,
}

impl LocalDocker {
    pub(super) fn new() -> Result<Self, String> {
        #[cfg(windows)]
        let (binary, client_lock) = windows::system_client()
            .ok_or("A verified system-installed Docker client was not found in Program Files.")?;
        #[cfg(windows)]
        let system_root =
            windows::system_root().ok_or("The Windows system directory could not be verified.")?;
        #[cfg(windows)]
        let config_parent = windows::config_parent()
            .ok_or("A local Docker client config directory could not be verified.")?;
        #[cfg(not(windows))]
        let binary = docker_binary().ok_or("A Docker client installation was not found.")?;
        #[cfg(not(windows))]
        let config_parent = std::env::temp_dir();
        let owner = owner_token()?;
        let name_token = owner_token()?;
        let container_name = format!("helinity-fixture-{name_token}");
        let config = config_parent.join(&container_name);
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder
            .create(&config)
            .map_err(|_| "An isolated Docker client config could not be created.")?;
        Ok(Self {
            binary,
            config,
            container_name,
            owner,
            #[cfg(windows)]
            _client_lock: client_lock,
            #[cfg(windows)]
            system_root,
        })
    }

    pub(super) fn preflight<'a>(&self, pin: Option<&'a str>) -> Result<&'a str, String> {
        let info = self
            .query(&["info", "--format", "{{json .}}"])
            .map_err(|_| {
                "The fixed local Docker engine endpoint is unavailable or unresponsive."
            })?;
        let seccomp = info["SecurityOptions"].as_array().is_some_and(|options| {
            options.iter().any(|option| {
                option
                    .as_str()
                    .is_some_and(|value| value.split(',').any(|part| part == "name=seccomp"))
            })
        });
        if info["OSType"] != "linux"
            || info["CgroupVersion"] != "2"
            || !seccomp
            || !info["Runtimes"]["runc"].is_object()
        {
            return Err(
                "The local engine does not expose Linux, cgroup v2, runc and seccomp support."
                    .to_owned(),
            );
        }
        let digest = pin
            .filter(|value| is_image_id(value))
            .ok_or("A trusted local image ID has not been configured at build time.")?;
        let image = self
            .query(&["image", "inspect", digest, "--format", "{{json .}}"])
            .map_err(|_| "The pinned local image could not be inspected.")?;
        if image["Id"] != digest || image["Os"] != "linux" || !empty(&image["Config"]["Volumes"]) {
            return Err(
                "The local image identity or image volume configuration could not be verified."
                    .to_owned(),
            );
        }
        if !verified_env(&image["Config"]["Env"]) {
            return Err("The pinned image declares unexpected environment variables.".to_owned());
        }
        Ok(digest)
    }

    pub(super) fn run_fixture(&self, digest: &str) -> Result<(), String> {
        let script = fixture_script();
        let mount = format!("/work:{TMPFS}");
        let owner = format!("{OWNER_LABEL}={}", self.owner);
        let mut args = vec![
            "container",
            "create",
            "--name",
            &self.container_name,
            "--label",
            &owner,
            "--pull",
            "never",
            "--restart",
            "no",
            "--runtime",
            "runc",
            "--network",
            "none",
            "--ipc",
            "none",
            "--cgroupns",
            "private",
            "--read-only",
            "--tmpfs",
            &mount,
            "--workdir",
            "/work",
            "--user",
            "65532:65532",
            "--cap-drop",
            "ALL",
            "--security-opt",
            SECCOMP,
            "--security-opt",
            NO_NEW_PRIVILEGES,
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "--cpus",
            "1",
            "--pids-limit",
            "64",
            "--ulimit",
            "cpu=30:30",
            "--ulimit",
            "fsize=67108864:67108864",
            "--ulimit",
            "nofile=256:256",
            "--ulimit",
            "core=0:0",
            "--no-healthcheck",
            "--log-driver",
            "none",
            "--entrypoint",
            ENTRYPOINT,
            digest,
        ];
        args.extend_from_slice(CONTAINER_COMMAND);
        args.push(&script);
        let result = match self.call(&args, ENGINE_TIMEOUT) {
            Ok((status, bytes)) if status.success() => {
                let id = std::str::from_utf8(&bytes).unwrap_or_default().trim();
                if is_digest(id) {
                    self.run_created_fixture(id, digest, &script)
                } else {
                    Err("Docker did not return a valid fixture container ID.".to_owned())
                }
            }
            Ok(_) => Err("Docker refused to create the fixture container.".to_owned()),
            Err(error) => Err(format!(
                "{error} Creation of {} was not confirmed.",
                self.container_name
            )),
        };

        let cleanup = self.cleanup(result.is_ok());
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(run_error), Err(cleanup_error)) => Err(format!("{run_error} {cleanup_error}")),
        }
    }

    fn run_created_fixture(&self, id: &str, digest: &str, script: &str) -> Result<(), String> {
        let inspection = self.query(&["container", "inspect", id, "--format", "{{json .}}"])?;
        if owned_id(&inspection, &self.container_name, &self.owner) != Some(id)
            || !verified_config(&inspection, id, digest, script)
        {
            return Err("Docker did not confirm the required container configuration.".to_owned());
        }
        let (status, _) = self.call(&["container", "start", "--attach", id], RUN_TIMEOUT)?;
        let state = self.query(&["container", "inspect", id, "--format", "{{json .State}}"])?;
        if state["Status"] != "exited" {
            return Err("Docker did not confirm that the fixture container exited.".to_owned());
        }
        match state["ExitCode"].as_i64() {
            Some(0) if status.success() => Ok(()),
            Some(70) => {
                Err("The in-container isolation checks failed before Cargo ran.".to_owned())
            }
            Some(124 | 137) => {
                Err("The fixture was terminated by a timeout or resource limit.".to_owned())
            }
            _ => Err("The isolated Cargo fixture did not complete successfully.".to_owned()),
        }
    }

    fn cleanup(&self, run_confirmed: bool) -> Result<(), String> {
        let owner = format!("label={OWNER_LABEL}={}", self.owner);
        let unresolved = || {
            format!(
                "Docker ownership or cleanup could not be confirmed for {}.",
                self.container_name
            )
        };
        let (status, bytes) = self
            .call(
                &[
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--filter",
                    &owner,
                    "--format",
                    "{{.ID}}",
                ],
                ENGINE_TIMEOUT,
            )
            .map_err(|_| unresolved())?;
        if !status.success() {
            return Err(unresolved());
        }
        let ids = std::str::from_utf8(&bytes)
            .map_err(|_| unresolved())?
            .trim();
        if ids.is_empty() {
            if run_confirmed {
                return Ok(());
            }
            return Err(format!(
                "No owned container was visible during cleanup. If creation finishes later, {} may remain stopped.",
                self.container_name
            ));
        }
        // Require one full immutable ID, then independently confirm the name and
        // ownership label. A colliding name can never be used as a deletion target.
        if !is_digest(ids) {
            return Err(unresolved());
        }
        let inspection = self
            .query(&["container", "inspect", ids, "--format", "{{json .}}"])
            .map_err(|_| unresolved())?;
        if owned_id(&inspection, &self.container_name, &self.owner) != Some(ids) {
            return Err(unresolved());
        }
        self.remove(ids)
    }

    fn remove(&self, id: &str) -> Result<(), String> {
        if self
            .call(&["container", "rm", "--force", id], ENGINE_TIMEOUT)
            .is_ok_and(|(status, _)| status.success())
        {
            return Ok(());
        }
        Err(format!("Docker did not confirm removal of container {id}."))
    }

    fn query(&self, args: &[&str]) -> Result<Value, String> {
        let (status, bytes) = self.call(args, ENGINE_TIMEOUT)?;
        if !status.success() {
            return Err("Docker rejected a runtime prerequisite check.".to_owned());
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| "Docker returned an invalid inspection response.".to_owned())
    }

    fn call(&self, args: &[&str], timeout: Duration) -> Result<(ExitStatus, Vec<u8>), String> {
        let deadline = Instant::now() + timeout;
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .arg("--config")
            .arg(&self.config)
            .args(["--host", ENDPOINT])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(install_dir) = self.binary.parent() {
            command.current_dir(install_dir);
        }
        #[cfg(windows)]
        command.env("SystemRoot", &self.system_root);
        let mut child = command
            .spawn()
            .map_err(|_| "The local Docker client could not be started.")?;
        let stdout = read_pipe(child.stdout.take().expect("requested stdout pipe"));
        let stderr = read_pipe(child.stderr.take().expect("requested stderr pipe"));
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(15)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(
                        "The local Docker command timed out or could not be monitored.".to_owned(),
                    );
                }
            }
        };
        let bytes = receive_pipe(stdout, deadline)?;
        receive_pipe(stderr, deadline)?;
        Ok((status, bytes))
    }
}

impl Drop for LocalDocker {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.config);
    }
}

fn read_pipe(pipe: impl Read + Send + 'static) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = pipe.take((OUTPUT_LIMIT + 1) as u64).read_to_end(&mut bytes);
        let _ = sender.send(result.map(|_| bytes));
    });
    receiver
}

fn receive_pipe(
    pipe: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let bytes = pipe
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()
        .and_then(Result::ok)
        .ok_or("Docker output could not be read within the limit.")?;
    if bytes.len() > OUTPUT_LIMIT {
        return Err("Docker output exceeded the runtime limit.".to_owned());
    }
    Ok(bytes)
}

#[cfg(not(windows))]
fn docker_binary() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    let paths = [
        Some(PathBuf::from("/usr/bin/docker")),
        Some(PathBuf::from("/usr/local/bin/docker")),
    ];
    #[cfg(not(any(windows, target_os = "linux")))]
    let paths: [Option<PathBuf>; 0] = [];
    paths
        .into_iter()
        .flatten()
        .find(|path| path.is_absolute() && path.is_file())
}

fn owner_token() -> Result<String, String> {
    let mut random = [0; 16];
    getrandom::fill(&mut random)
        .map_err(|_| "The system could not create a fixture ownership token.")?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn owned_id<'a>(container: &'a Value, name: &str, owner: &str) -> Option<&'a str> {
    let id = container["Id"].as_str()?;
    (is_digest(id)
        && container["Name"] == format!("/{name}")
        && container["Config"]["Labels"][OWNER_LABEL] == owner)
        .then_some(id)
}

pub(super) fn is_image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(is_digest)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn empty(value: &Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn verified_env(value: &Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(|variables| {
            variables.iter().all(|variable| {
                variable
                    .as_str()
                    .is_some_and(|entry| entry.starts_with("PATH="))
            })
        })
}

fn same_members(actual: &Value, expected: &[Value]) -> bool {
    actual.as_array().is_some_and(|actual| {
        actual.len() == expected.len() && expected.iter().all(|item| actual.contains(item))
    })
}

fn fixture_script() -> String {
    let isolation = include_str!("verify-isolation.sh");
    let manifest = include_str!("../../../fixtures/runtime/Cargo.toml");
    let source = include_str!("../../../fixtures/runtime/src/lib.rs");
    format!(
        "{isolation}\ncd /work\nmkdir src\ncat > Cargo.toml <<'HELINITY_MANIFEST'\n{manifest}\nHELINITY_MANIFEST\ncat > src/lib.rs <<'HELINITY_SOURCE'\n{source}\nHELINITY_SOURCE\n/usr/bin/timeout --kill-after=2s 35s /usr/bin/cargo test --offline --jobs 1 --lib -- --test-threads=1\n"
    )
}

fn verified_config(container: &Value, id: &str, digest: &str, script: &str) -> bool {
    let host = &container["HostConfig"];
    let config = &container["Config"];
    let cmd: Vec<_> = CONTAINER_COMMAND.iter().copied().chain([script]).collect();
    let channels_closed = host["NetworkMode"] == "none"
        && host["IpcMode"] == "none"
        && host["PidMode"] == ""
        && host["CgroupnsMode"] == "private"
        && host["LogConfig"]["Type"] == "none"
        && config["OpenStdin"] == false
        && config["Tty"] == false
        && verified_env(&config["Env"])
        && empty(&host["Binds"])
        && empty(&host["Mounts"])
        && empty(&host["VolumesFrom"])
        && empty(&host["Devices"])
        && empty(&host["DeviceRequests"])
        && empty(&host["DeviceCgroupRules"])
        && empty(&host["PortBindings"])
        && empty(&config["Volumes"]);
    let confined = host["Runtime"] == "runc"
        && host["Privileged"] == false
        && host["ReadonlyRootfs"] == true
        && host["CapDrop"] == serde_json::json!(["ALL"])
        && empty(&host["CapAdd"])
        && same_members(
            &host["SecurityOpt"],
            &[SECCOMP.into(), NO_NEW_PRIVILEGES.into()],
        )
        && host["Tmpfs"] == serde_json::json!({"/work": TMPFS})
        && container["Mounts"].as_array().is_some_and(|mounts| {
            mounts
                .iter()
                .all(|mount| mount["Type"] == "tmpfs" && mount["Destination"] == "/work")
        });
    let bounded = host["Memory"] == 268_435_456
        && host["MemorySwap"] == 268_435_456
        && host["NanoCpus"] == 1_000_000_000
        && host["PidsLimit"] == 64
        && host["RestartPolicy"]["Name"] == "no"
        && same_members(
            &host["Ulimits"],
            &[
                serde_json::json!({"Name": "cpu", "Soft": 30, "Hard": 30}),
                serde_json::json!({"Name": "fsize", "Soft": 67_108_864, "Hard": 67_108_864}),
                serde_json::json!({"Name": "nofile", "Soft": 256, "Hard": 256}),
                serde_json::json!({"Name": "core", "Soft": 0, "Hard": 0}),
            ],
        );
    container["Id"] == id
        && container["Image"] == digest
        && container["State"]["Status"] == "created"
        && config["User"] == "65532:65532"
        && config["WorkingDir"] == "/work"
        && config["Healthcheck"]["Test"] == serde_json::json!(["NONE"])
        && config["Entrypoint"] == serde_json::json!([ENTRYPOINT])
        && config["Cmd"] == serde_json::json!(cmd)
        && channels_closed
        && confined
        && bounded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_full_lowercase_image_ids() {
        let zeros = "0".repeat(64);
        assert!(is_image_id(&format!("sha256:{zeros}")));
        assert!(!is_image_id(&zeros));
        assert!(!is_image_id("rust:latest"));
        assert!(!is_image_id("sha256:abcdef"));
        assert!(!is_image_id(&format!("sha256:{}", "A".repeat(64))));
    }

    #[test]
    fn missing_engine_evidence_does_not_verify_isolation() {
        let script = fixture_script();
        let config = serde_json::json!({"Id": "fixture", "Image": "pinned"});
        assert!(!verified_config(&config, "fixture", "pinned", &script));
    }

    #[test]
    fn cleanup_requires_label_name_and_full_immutable_id() {
        let id = "a".repeat(64);
        let mut inspection = serde_json::json!({
            "Id": id,
            "Name": "/helinity-fixture-test",
            "Config": {"Labels": {OWNER_LABEL: "fixture-token"}}
        });
        assert_eq!(
            owned_id(&inspection, "helinity-fixture-test", "fixture-token"),
            Some(id.as_str())
        );
        assert_eq!(
            owned_id(&inspection, "helinity-fixture-test", "another-token"),
            None
        );
        assert_eq!(owned_id(&inspection, "other-name", "fixture-token"), None);
        inspection["Id"] = "aaaaaaaaaaaa".into();
        assert_eq!(
            owned_id(&inspection, "helinity-fixture-test", "fixture-token"),
            None
        );
    }

    #[test]
    fn configuration_must_match_fixture_and_close_host_channels() {
        let script = fixture_script();
        let cmd: Vec<_> = CONTAINER_COMMAND
            .iter()
            .copied()
            .chain([script.as_str()])
            .collect();
        let config = serde_json::json!({
            "Id": "fixture",
            "Image": "pinned",
            "State": {"Status": "created"},
            "Config": {
                "Env": ["PATH=/usr/bin:/bin"],
                "OpenStdin": false,
                "Tty": false,
                "User": "65532:65532",
                "WorkingDir": "/work",
                "Healthcheck": {"Test": ["NONE"]},
                "Entrypoint": [ENTRYPOINT],
                "Cmd": cmd
            },
            "HostConfig": {
                "NetworkMode": "none",
                "IpcMode": "none",
                "PidMode": "",
                "CgroupnsMode": "private",
                "LogConfig": {"Type": "none"},
                "Runtime": "runc",
                "Privileged": false,
                "ReadonlyRootfs": true,
                "CapDrop": ["ALL"],
                "SecurityOpt": [NO_NEW_PRIVILEGES, SECCOMP],
                "Tmpfs": {"/work": TMPFS},
                "Memory": 268_435_456,
                "MemorySwap": 268_435_456,
                "NanoCpus": 1_000_000_000,
                "PidsLimit": 64,
                "RestartPolicy": {"Name": "no"},
                "Ulimits": [
                    {"Name": "core", "Soft": 0, "Hard": 0},
                    {"Name": "cpu", "Soft": 30, "Hard": 30},
                    {"Name": "fsize", "Soft": 67_108_864, "Hard": 67_108_864},
                    {"Name": "nofile", "Soft": 256, "Hard": 256}
                ]
            },
            "Mounts": []
        });
        assert!(verified_config(&config, "fixture", "pinned", &script));
        assert!(!verified_config(&config, "fixture", "other-image", &script));
        for (pointer, override_value) in [
            ("/HostConfig/NetworkMode", serde_json::json!("host")),
            ("/HostConfig/Privileged", serde_json::json!(true)),
            ("/HostConfig/MemorySwap", serde_json::json!(-1)),
            (
                "/Config/Env",
                serde_json::json!(["HTTP_PROXY=http://example.invalid"]),
            ),
            (
                "/Mounts",
                serde_json::json!([{"Type": "bind", "Destination": "/run"}]),
            ),
        ] {
            let mut unexpected = config.clone();
            *unexpected.pointer_mut(pointer).unwrap() = override_value;
            assert!(
                !verified_config(&unexpected, "fixture", "pinned", &script),
                "{pointer}"
            );
        }
    }
}
