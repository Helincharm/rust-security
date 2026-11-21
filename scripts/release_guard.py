"""Privacy checks for bytes intended for public distribution. Prints categories, never matches."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys

MAX_FILE = 192 * 1024 * 1024
FORBIDDEN_DIRS = {".git", ".work", ".tools", ".codex", ".claude", ".ssh", ".aws", ".cache", ".config", "target", "node_modules", "__pycache__", "backups", "debug", ".venv", "venv"}
BAD_EXT = {".exe", ".dll", ".dylib", ".so", ".pdb", ".dmp", ".zip", ".gz", ".7z", ".tar", ".xz", ".rar", ".map", ".sqlite", ".sqlite3", ".db", ".bak", ".pem", ".p12", ".pfx", ".key", ".crt", ".cer", ".der", ".ppk", ".log", ".pyc", ".pyo", ".pt", ".pth", ".bin", ".pkl", ".pickle", ".ckpt", ".onnx", ".gguf"}
SIGNATURES = {
    "access-token": re.compile(r"(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9_]{26,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|AIza[\w-]{35}|xox[baprs]-[\w-]{15,}|eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,})"),
    "private-key-or-certificate": re.compile(r"-----BEGIN (?:[A-Z 0-9]*PRIVATE KEY|CERTIFICATE)-----"),
    "secret-assignment": re.compile(r"""(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|session[_-]?id|set-cookie|authorization)\b["']?\s*[:=]\s*["'](?:Bearer\s+)?[a-z0-9+_=/.:~-]{12,}["']"""),
    "credential-header": re.compile(r"(?i)\b(?:authorization\s*:\s*bearer|set-cookie\s*:|cookie\s*:\s*(?:session|sid|auth)=)\s*[a-z0-9+_/=.-]{16,}"),
    "credential-uri": re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/ @\s]+@"),
    "user-home-or-wsl": re.compile(r"(?i)(?:/(?:users|home)/[^\s/\"']+|/mnt/[a-z]/|\\\\(?:wsl\$|wsl.localhost)\\)"),
    "absolute-windows-path": re.compile(r"(?i)(?<![a-z0-9_])[a-z]:[\\/]"),
    "network-share": re.compile(r"""(?i)(?<!\\)\\\\[a-z0-9][a-z0-9.-]{1,}\\[a-z0-9_.$-]+"""),
    "workspace-location": re.compile(r"(?i)(?:\.chatgpt-projects[/\\]|[/\\]\.(?:claude|codex)[/\\](?:projects|sessions|attachments|generated_images)[/\\])"),
    "email": re.compile(r"(?i)(?<![\w%+.~-])[\w.%+~-]+@(?:[\w-]+\.)+[a-z]{2,}\b"),
    "private-service-host": re.compile(r"(?i)\b(?:https?|wss?|ssh)://(?:[a-z0-9-]+\.)+(?:lan|internal|localdomain|home|corp)(?=[/:?#\s'\"<>]|$)"),
}
IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?i)\b(?:https?|wss?)://\[([a-f0-9:%]+)\]")
PRIVATE = tuple(ipaddress.ip_network((address, bits)) for address, bits in [(0x0a000000,8),(0xac100000,12),(0xc0a80000,16),(0xa9fe0000,16),(0xfc00 << 112,7),(0xfe80 << 112,10)])
LITERAL_SECRETS = [v for k,v in os.environ.items() if len(v)>=12 and re.search(r"(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET|PASSWORD)$",k,re.I)]
LOCAL_NAMES = [v for v in {Path.home().name, socket.gethostname(), os.environ.get("COMPUTERNAME", "")} if len(v)>=4 and v.lower() not in {"user","users","admin","root","runner","localhost","build"}]

def scan_text(s):
    results={k for k,p in SIGNATURES.items() if p.search(s)}
    if any(value in s for value in LITERAL_SECRETS):
        results.add("environment-secret")
    if any(re.search(r"(?<!\w)"+re.escape(v)+r"(?!\w)",s,re.I) for v in LOCAL_NAMES):
        results.add("current-local-identity")
    for urlhost in re.findall(r"(?i)\b(?:https?|wss?)://([a-z0-9-]+)(?=[:/?#'\"<>\s]|$)",s):
        if urlhost.lower() not in {"localhost"}:results.add("private-service-host")
    for candidate in [*IP.findall(s),*IPV6.findall(s)]:
        try: addr=ipaddress.ip_address(candidate)
        except ValueError: continue
        if any(addr in net for net in PRIVATE):
            results.add("private-network")
    return results

def safe_label(name):
    return "member-"+hashlib.sha256(os.fsencode(name)).hexdigest()[:12] if scan_text(name) or not name.isascii() else name

def path_reasons(name):
    parts=name.split("/")
    p=Path(name)
    blocked=any(part.lower() in FORBIDDEN_DIRS or part.lower().startswith(("local-candidate", ".env", "id_rsa", "id_ed25519")) for part in parts)
    blocked |= any(part.lower() in {"credentials","cookies","login data","history.sqlite3","auth.json",".netrc",".npmrc",".pypirc",".gitmodules"} for part in parts)
    if name.startswith("/") or "\\" in name or not all(re.fullmatch(r"[A-Za-z0-9_. @+-]+",x) and x not in {".",".."} for x in parts):
        blocked=True
    return scan_text(name) | ({"prohibited-path-or-format"} if blocked or p.suffix.lower() in BAD_EXT else set())

def png_is_clean(data):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    pos=8
    while pos+12<=len(data):
        size,typ=struct.unpack_from(">I4s",data,pos)
        pos+=12+size
        if typ not in {b"IHDR",b"PLTE",b"IDAT",b"IEND",b"sRGB",b"gAMA",b"cHRM",b"tRNS",b"pHYs",b"bKGD",b"sBIT"} or pos>len(data):
            return False
        if typ==b"IEND":return size==0 and pos==len(data)
    return False

def icon_is_clean(data):
    if not data.startswith(b"\0\0\1\0") or len(data)<6:return False
    count=int.from_bytes(data[4:6],"little")
    end=6+count*16
    if not count or end>len(data):return False
    ranges=[]
    for i in range(count):
        size,start=struct.unpack_from("<II",data,6+i*16+8)
        block=data[start:start+size]
        if not size or len(block)!=size:return False
        if block.startswith(b"\x89PNG"):
            if not png_is_clean(block):return False
        elif len(block)<40 or int.from_bytes(block[:4],"little")!=40:
            return False
        ranges.append((start,start+size))
    for a,b in sorted(ranges):
        if a!=end:return False
        end=b
    return end==len(data)

def scan_data(name,data):
    issues=path_reasons(name)
    if len(data)>MAX_FILE:return issues|{"file-size-outside-policy"}
    ext=Path(name).suffix.lower()
    if ext in {".png",".ico"}:
        if not (png_is_clean(data) if ext==".png" else icon_is_clean(data)):issues.add("image-metadata-or-format")
        for pattern,encoding in [(rb"[ -~]{5,}","ascii"),(rb"(?:[ -~]\0){5,}","utf-16-le"),(rb"(?:\0[ -~]){5,}","utf-16-be")]:
            # Pixel content itself requires independent visual review.
            strings=[x.decode(encoding) for x in re.findall(pattern,data)]
            issues.update(scan_text("\n".join(strings)))
        return issues
    if ext==".safetensors":
        if len(data)<9:return issues|{"invalid-tensor-header"}
        length=int.from_bytes(data[:8],"little")
        if not 2<=length<=min(len(data)-8,16*1024*1024):return issues|{"invalid-tensor-header"}
        try:
            header=json.loads(data[8:8+length]);assert isinstance(header,dict)
            issues.update(scan_text(json.dumps(header,ensure_ascii=False)))
        except (ValueError,AssertionError,ImportError):
            return issues|{"tensor-parser-or-header-unverified"}
        # The release currently excludes model binaries; any future enrollment needs an
        # independent tensor loader plus rights, compatibility, and raw-byte review.
        return issues|{"tensor-payload-needs-independent-verification"}
    if data.startswith((b"MZ",b"\x7fELF",b"PK\x03\x04",b"\x1f\x8b",b"SQLite format 3",b"\xca\xfe\xba\xbe")) or b"\x00" in data:return issues|{"unexpected-binary"}
    try: s=data.decode("utf-8-sig")
    except UnicodeDecodeError:return issues|{"unrecognized-encoding"}
    issues.update(scan_text(s))
    if ext==".json":
        try: issues.update(scan_text(json.dumps(json.loads(s),ensure_ascii=False)))
        except (ValueError,RecursionError):issues.add("malformed-json")
    return issues

def git(repo,*args,raw=False):
    p=subprocess.run(["git","-C",str(repo),*args],capture_output=True)
    if p.returncode:raise ValueError("git-command-failed")
    return p.stdout if raw else p.stdout.decode("utf-8","strict").rstrip("\r\n")

def check_index(repo):
    errors=[]
    for record in git(repo,"ls-files","--stage","-z",raw=True).split(b"\0"):
        if not record:continue
        meta,path=record.split(b"\t",1)
        mode,oid,stage=meta.decode("ascii").split();name=path.decode("utf-8")
        if mode not in {"100644","100755"} or stage!="0":errors.append((safe_label(name),"unsupported-index-entry"));continue
        if int(git(repo,"cat-file","-s",oid))>MAX_FILE:errors.append((safe_label(name),"too-large"));continue
        errors.extend((safe_label(name),why) for why in sorted(scan_data(name,git(repo,"cat-file","blob",oid,raw=True))))
    return errors

def precommit_identity(repo):
    local_name=git(repo,"config","--local","--get","user.name")
    local_email=git(repo,"config","--local","--get","user.email")
    if not local_name or not re.fullmatch(r"(?:[0-9]+\+)?[A-Za-z0-9-]+@users\.noreply\.github\.com",local_email):
        return False
    for role in ("GIT_AUTHOR_IDENT","GIT_COMMITTER_IDENT"):
        ident=git(repo,"var",role)
        if not ident.startswith(local_name+" <"+local_email+"> "):return False
    return True

if __name__=="__main__":
    try:
        root=Path(git(Path.cwd(),"rev-parse","--show-toplevel"))
        failures=check_index(root)
        if not precommit_identity(root):failures.append(("git","privacy-safe-local-identity-required"))
        for label,why in failures:print(label,why)
        sys.exit(int(bool(failures)))
    except Exception:
        print("FAIL: unable to verify staged content")
        sys.exit(1)

