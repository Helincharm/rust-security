"""Build the local Rust Security scanner and verify its stdio MCP connection."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / ".rust-security"
NAME = "rust-security"


def build(offline):
    args = ["cargo", "build", "--locked", "-p", "helinity", "--message-format=json-render-diagnostics"]
    if offline:
        args.append("--offline")
    result = subprocess.run(args, cwd=ROOT, stdout=subprocess.PIPE, check=True, text=True)
    artifact = None
    for line in result.stdout.splitlines():
        message = json.loads(line)
        if message.get("executable") and message.get("target", {}).get("name") == "helinity":
            artifact = Path(message["executable"])
    if artifact is None or not artifact.is_file():
        raise SystemExit("Cargo returned no Helinity executable.")
    INSTALL.mkdir(exist_ok=True)
    target = INSTALL / artifact.name
    if not target.is_file() or artifact.read_bytes() != target.read_bytes():
        shutil.copy2(artifact, target)
    for source in ("mcp_server/server.py", "experiments/checkpoints.json", "experiments/codet5.py"):
        dest = INSTALL / source
        dest.parent.mkdir(exist_ok=True)
        shutil.copy2(ROOT / source, dest)
    return target


def mcp_python(existing, offline):
    if existing:
        interpreter = existing.expanduser().absolute()
        subprocess.run([str(interpreter), "-I", "-c",
                        "from importlib.metadata import version; "
                        "raise SystemExit(version('mcp') != '1.30.0')"], check=True, cwd=ROOT)
        return interpreter
    env = INSTALL / "venv"
    interpreter = env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not interpreter.is_file():
        venv.EnvBuilder(with_pip=True).create(env)
    deps = "requirements-mcp-windows.lock" if os.name == "nt" else "requirements-mcp.txt"
    flags = ["--no-index"] if offline else []
    subprocess.run([str(interpreter), "-I", "-m", "pip", "install", *flags, "-r", str(ROOT / deps)],
                   cwd=ROOT, check=True)
    return interpreter


def client_path(client, override):
    if override:
        exe = override.expanduser().resolve(strict=True)
    else:
        name = client + ".exe" if os.name == "nt" else client
        command = shutil.which(name)
        if not command:
            raise SystemExit("Client executable unavailable. Set --client-exe to the installed native executable.")
        exe = Path(command).resolve(strict=True)
    if os.name == "nt" and exe.suffix.lower() != ".exe":
        raise SystemExit("Use the native client executable.")
    return str(exe)


def register(client, exe, binary, python, project):
    args = ["mcp", "--root", str(project)]
    env = {"HELINITY_MCP_PYTHON": str(python), "HELINITY_MCP_SHARE_SOURCE": "0"}
    server = dict(type="stdio", command=str(binary), args=args, env=env)
    if client == "codex":
        # Check all official configuration fields we intend to set before changing anything.
        existing = subprocess.run([exe, "mcp", "get", NAME, "--json"], cwd=ROOT, capture_output=True, text=True)
        if existing.returncode == 0:
            transport = json.loads(existing.stdout).get("transport", {})
            if all(transport.get(key) == value for key, value in server.items()) and json.loads(existing.stdout).get("enabled", True):
                print("Matching Codex MCP connection already exists.")
                return
            raise SystemExit("A different Codex connection uses rust-security. Review it in the client first.")
        if "no mcp server" not in (existing.stderr + existing.stdout).lower():
            raise SystemExit("Could not establish whether Codex already has a rust-security connection.")
        command = [exe, "mcp", "add", NAME]
        for key, value in env.items():
            command.extend(["--env", f"{key}={value}"])
        subprocess.run([*command, "--", str(binary), *args], cwd=ROOT, check=True)
    else:
        # add-json rejects an existing name. Never remove or overwrite an existing server.
        result = subprocess.run([exe, "mcp", "add-json", "--scope", "local", NAME, "-"],
                                cwd=project, input=json.dumps(server), capture_output=True, text=True)
        if result.returncode and "already exists" in (result.stderr + result.stdout).lower():
            raise SystemExit("Existing Claude registration preserved. Inspect its settings before changing it.")
        if result.returncode:
            raise SystemExit("Claude did not add the server. Inspect its existing rust-security entry with claude mcp get rust-security.")
    print("Registered rust-security. Reopen the client in the selected project and inspect its MCP tools.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", choices=("codex", "claude", "verify"), required=True)
    parser.add_argument("--project", type=Path, required=True, help="Only this directory will be exposed to MCP.")
    parser.add_argument("--client-exe", type=Path, help="Path to an installed Codex or Claude native executable.")
    parser.add_argument("--mcp-python", type=Path, help="Reuse an interpreter containing the pinned MCP SDK.")
    parser.add_argument("--offline", action="store_true", help="Use local Cargo/Python dependencies only.")
    opts = parser.parse_args()
    project = opts.project.expanduser().resolve(strict=True)
    if not project.is_dir() or project == Path.home() or project == Path(project.anchor):
        parser.error("Choose a specific project directory.")
    if sys.version_info < (3, 11):
        parser.error("Python 3.11 or later is required.")
    client = client_path(opts.client, opts.client_exe) if opts.client != "verify" else None
    binary = build(opts.offline)
    python = mcp_python(opts.mcp_python, opts.offline)
    subprocess.run([str(python), "-I", str(ROOT / "scripts/probe_mcp.py"), str(binary), str(project),
                    str(ROOT / "fixtures/static")], cwd=ROOT, check=True)
    if client:
        register(opts.client, client, binary, python, project)


if __name__ == "__main__":
    main()
