"""Drive the CLI and official stdio MCP client against static fixtures, using a temporary DB."""
import asyncio
import hashlib
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from jsonschema import validate
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT=Path(__file__).resolve().parents[1]
BIN=Path(sys.argv[1]).resolve()
FIX=ROOT/"fixtures/static"
SCHEMA=Path(sys.argv[2]).resolve()
if hashlib.sha256(SCHEMA.read_bytes()).hexdigest()!="c96eb2d311c37b0a38cbd18c52d79a68f778bbd2d831abed7412d9850740f785":
    raise SystemExit("Unexpected SARIF schema digest")
async def protocol(env,foreign):
    params=StdioServerParameters(command=str(BIN),args=["mcp","--root",str(FIX)],env=env)
    async with stdio_client(params) as (reader,writer), ClientSession(reader,writer) as client:
        init=await client.initialize()
        tools=sorted(t.name for t in (await client.list_tools()).tools)
        assert len(tools)==10,tools
        async def call(name,args):
            rsp=await client.call_tool(name,args)
            assert not rsp.isError,(name,rsp.content)
            return json.loads(rsp.content[0].text)
        scan=await call("analyze_rust_file",{"path":"review_markers.rs"})
        assert scan["findings"]==4
        assert "project" not in scan
        sid=scan["scan_id"]
        listed=await call("list_security_findings",{"scan_id":sid})
        assert len(listed["untrusted_observations"])==scan["findings"]
        item=await call("get_finding_evidence",{"scan_id":sid,"index":0})
        observation=item["untrusted_observation"]
        lines=(FIX/observation["path"]).read_text("utf-8").splitlines()
        sharing=env.get("HELINITY_MCP_SHARE_SOURCE")=="1"
        assert observation["line"]>0 and observation["column"]>0
        assert ("source_context" in observation)==sharing
        assert ("source_line" in observation)==sharing
        assert ("evidence" in observation)==sharing
        assert all(("source_context" in f)==sharing for f in listed["untrusted_observations"])
        assert all(("source_line" in f)==sharing for f in listed["untrusted_observations"])
        if sharing:
            assert observation["source_context"].splitlines()[0] in lines[observation["line"]-1]
            assert observation["source_line"] == lines[observation["line"]-1]
        exported=await call("export_security_report",{"scan_id":sid,"format":"json"})
        assert all(("source_context" in f)==sharing for f in exported["findings"])
        assert all(("source_line" in f)==sharing for f in exported["findings"])
        assert ("diagnostics" in scan)==sharing
        assert lines[observation["line"]-1].strip()
        report=await call("export_security_report",{"scan_id":sid})
        assert ('"snippet"' in json.dumps(report))==sharing
        validate(report,json.loads(SCHEMA.read_bytes()))
        whole=await call("analyze_rust_project",{})
        dep=await call("analyze_dependencies",{})
        assert dep["findings"]==1
        rejected=await client.call_tool("analyze_rust_file",{"path":"../outside.rs"})
        assert rejected.isError
        foreign_result=await client.call_tool("export_security_report",{"scan_id":foreign})
        assert foreign_result.isError and "Unknown scan" in str(foreign_result.content)
        history=await call("get_scan_history",{})
        assert history["active_job"] is None and {s["scan_id"] for s in history["scans"]} == {sid,whole["scan_id"],dep["scan_id"]}
        assert foreign not in str(history)
        status=await call("get_dynamic_analysis_status",{})
        assert isinstance(status,dict) and status
        for unknown in ["invalid",foreign]:
            assert (await client.call_tool("cancel_analysis",{"job_id":unknown})).isError
        runtime=await call("request_dynamic_analysis",{})
        assert not runtime["executed"] and runtime["approval_required"]
        return dict(protocol=init.protocolVersion,server=init.serverInfo.name,tools=tools,
                    fixture_observations=scan["findings"],project_files=whole["files"],dependency_observations=dep["findings"],
                    outside_path_refused=rejected.isError,foreign_scan_refused=foreign_result.isError,runtime_request_only=not runtime["executed"])

async def coverage_cases(env, root):
    root.mkdir()
    # Exceed the worker's 32-message raw sample and the scanner's 128-message cap.
    for n in range(135):
        (root/f".private-name-{n}").touch()
    for n in range(6):
        (root/f"invalid{n}.rs").write_text("fn incomplete( {")
    params=StdioServerParameters(command=str(BIN),args=["mcp","--root",str(root)],env=env)
    async with stdio_client(params) as streams, ClientSession(*streams) as client:
        await client.initialize()
        async def call(name,args):
            response=await client.call_tool(name,args)
            assert not response.isError, response.content
            return json.loads(response.content[0].text)
        for expected in (0,4):
            if expected:
                (root/"markers.rs").write_bytes((FIX/"review_markers.rs").read_bytes())
            result=await call("analyze_rust_project",{})
            assert (result["findings"],result["warning_count"])==(expected,6),result
            assert result["coverage"] == {
                "warning_categories": {"ast_parse_error": 6},
                "diagnostic_categories": {"path_policy_exclusion": 127, "omission_notice": 1},
                "omitted_diagnostics": 8,
            }, result
            assert result["diagnostic_count"] == 128
            assert "diagnostics" not in result and "private-name" not in json.dumps(result)
            args={"scan_id":result["scan_id"]}
            listed=await call("list_security_findings",args)
            assert len(listed["untrusted_observations"])==expected
            report=await call("export_security_report",{**args,"format":"json"})
            assert len(report["warnings"])==6 and len(report["findings"])==expected
            assert all("source_context" not in w for w in report["warnings"])
            assert all("source_line" not in w for w in report["warnings"])
            sarif=await call("export_security_report",args)
            validate(sarif,json.loads(SCHEMA.read_bytes()))
            run=sarif["runs"][0]
            assert len(run["results"])==expected
            assert len(run["invocations"][0]["toolExecutionNotifications"])>=6
        return {"warnings_only":[0,6],"mixed":[4,6]}

async def active_cancellation(env, root):
    root.mkdir()
    # Enough ordinary source to keep the real worker busy during the status round trip.
    content = "".join(f"pub fn arithmetic_{i}(n: u32) -> u32 {{ n.saturating_add(1) }}\n" for i in range(200))
    for i in range(80):
        (root/f"module_{i}.rs").write_text(content)
    params = StdioServerParameters(command=str(BIN), args=["mcp","--root",str(root)], env=env)
    async with stdio_client(params) as (reader,writer), ClientSession(reader,writer) as client:
        await client.initialize()
        job = asyncio.create_task(client.call_tool("analyze_rust_project",{}))
        async with asyncio.timeout(12):
            while not job.done():
                response = await client.call_tool("get_scan_history",{})
                active = json.loads(response.content[0].text)["active_job"]
                if active:
                    result = await client.call_tool("cancel_analysis",{"job_id":active})
                    assert not result.isError and json.loads(result.content[0].text)["reconnect_required"]
                    assert (await job).isError
                    assert (await client.call_tool("analyze_rust_project",{})).isError
                    return True
        raise AssertionError("Could not observe an active fixture job")

def main():
    with TemporaryDirectory(prefix="helinity-acceptance-") as tmp:
        env=dict(os.environ,HELINITY_MCP_SHARE_SOURCE="0",HELINITY_DB=str(Path(tmp)/"history.sqlite3"),HELINITY_MCP_PYTHON=sys.executable)
        def run(*args,ok=True):
            r=subprocess.run([str(BIN),*args],env=env,capture_output=True,encoding="utf-8",timeout=30)
            if ok: assert r.returncode==0,r.stderr
            else: assert r.returncode!=0
            return r
        scan=json.loads(run("scan",str(FIX),"--json").stdout)
        validate(scan,json.loads((ROOT/"tests/report.schema.json").read_bytes()))
        assert {f["cwe"] for f in scan["findings"]}>={"CWE-22","CWE-20","CWE-78","CWE-89"}
        clean=json.loads(run("scan",str(FIX/"controls.rs"),"--json").stdout)
        assert not clean["findings"]
        history=json.loads(run("history").stdout);assert len(history)==2
        assert scan["id"] in [s["id"] for s in history]
        assert "observations" in run("findings","--scan",scan["id"]).stdout
        assert json.loads(run("report","--format","json","--scan",scan["id"]).stdout)==scan
        identical=json.loads(run("compare",scan["id"],scan["id"]).stdout)
        assert identical["changes"]==[] and "project" not in identical["before"]
        changed=Path(tmp)/"edited.rs"
        changed.write_bytes((FIX/"review_markers.rs").read_bytes())
        before=json.loads(run("scan",str(changed),"--json").stdout)
        changed.write_text("pub fn changed() {}")
        after=json.loads(run("scan",str(changed),"--json").stdout)
        delta=json.loads(run("compare",before["id"],after["id"]).stdout)
        assert sum(d["count_delta"] for d in delta["changes"]) == -4
        assert "source_context" not in json.dumps(delta) and str(changed) not in json.dumps(delta)
        run("compare",before["id"],scan["id"],ok=False)
        answer=json.loads(run("review",scan["id"],"CWE-22").stdout)
        assert answer["references"] and answer["events"] and answer["answer"]
        sarif=json.loads(run("report","--format","sarif","--scan",scan["id"]).stdout)
        validate(sarif,json.loads(SCHEMA.read_bytes()))
        status=json.loads(run("doctor").stdout)
        missing=run("scan",str(Path(tmp)/"absent"),ok=False)
        assert "Cannot open target" in missing.stderr
        unattended=run("runtime","run-fixture",ok=False)
        assert "interactive local terminal" in unattended.stderr
        result=asyncio.run(protocol(env,scan["id"]))
        asyncio.run(protocol(dict(env,HELINITY_MCP_SHARE_SOURCE="1"),scan["id"]))
        result["coverage_cases"]=asyncio.run(coverage_cases(env,Path(tmp)/"coverage"))
        result["source_sharing_modes_verified"]=True
        result["active_worker_cancellation"]=asyncio.run(active_cancellation(env,Path(tmp)/"cancellation"))
        evidence=dict(completed_utc=datetime.now(UTC).isoformat(),binary_sha256=hashlib.sha256(BIN.read_bytes()).hexdigest(),cli=dict(project_files=len(scan["files"]),observations=len(scan["findings"]),control_observations=len(clean["findings"]),
            persisted_scans=len(history),json_and_sarif_valid=True,bad_target_rejected=missing.returncode!=0,unattended_runtime_rejected=unattended.returncode!=0),
            mcp=result,doctor_runtime=status["runtime"])
        print(json.dumps(evidence, indent=2))

if __name__=="__main__":main()
