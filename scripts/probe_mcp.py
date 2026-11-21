"""Verify the stdio service with the official SDK; never run the selected project."""
import asyncio
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def check(binary, root, database, fixture=False):
    env = dict(os.environ, HELINITY_MCP_PYTHON=sys.executable,
               HELINITY_MCP_SHARE_SOURCE="0", HELINITY_DB=str(database))
    server = StdioServerParameters(command=str(binary), args=["mcp", "--root", str(root)], env=env)
    async with stdio_client(server) as streams, ClientSession(*streams) as session:
        await session.initialize()
        names = {tool.name for tool in (await session.list_tools()).tools}
        required = {"analyze_rust_file", "list_security_findings", "get_finding_evidence"}
        if not required <= names:
            raise RuntimeError("Rust Security did not expose the expected scan tools")
        if fixture:
            response = await session.call_tool("analyze_rust_file", {"path": "controls.rs"})
            if response.isError or json.loads(response.content[0].text).get("findings") != 0:
                raise RuntimeError("The clean control did not return zero findings")
            positive = await session.call_tool("analyze_rust_file", {"path": "review_markers.rs"})
            result = json.loads(positive.content[0].text)
            if positive.isError or result["findings"] != 4:
                raise RuntimeError("Expected four static review markers")
            evidence = await session.call_tool("get_finding_evidence", {"scan_id": result["scan_id"], "index": 0})
            record = json.loads(evidence.content[0].text)["untrusted_observation"]
            if evidence.isError or record["path"] != "review_markers.rs" or record["line"] < 1:
                raise RuntimeError("Missing source location for positive control")
            outside = await session.call_tool("analyze_rust_file", {"path": "../outside.rs"})
            if not outside.isError:
                raise RuntimeError("Out-of-scope path accepted")


async def main():
    binary, project, fixture = map(Path, sys.argv[1:])
    with TemporaryDirectory() as tmp:
        database = Path(tmp) / "history.sqlite3"
        async with asyncio.timeout(90):
            await check(binary, fixture, database, fixture=True)
            await check(binary, project, database)
    print("MCP handshake, tool inventory and fixture checks passed (4 review markers, source location, clean control, scope refusal).")


if __name__ == "__main__":
    asyncio.run(main())
