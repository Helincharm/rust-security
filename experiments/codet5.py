"""Offline optical second opinion on one bounded file, using the original pinned exports."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory

def main(model_dir: Path, path: Path):
    if path.suffix != ".rs" or not path.is_file():
        raise ValueError("Select a regular .rs file")
    with path.open("rb") as stream:
        raw=stream.read(256*1024+1)
    if len(raw)>256*1024:
        raise ValueError("Source exceeds the experimental adapter budget")
    pins=json.loads(Path(__file__).with_name("checkpoints.json").read_bytes())
    def check_asset(path):
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or getattr(info,"st_file_attributes",0)&0x400 or info.st_nlink!=1:
            raise ValueError("Choose an original regular local checkpoint asset")
    policy_file=model_dir/"decision_policy.json"
    check_asset(policy_file)
    with policy_file.open("rb") as stream:
        policy_data=stream.read(32769)
    if len(policy_data)>32768:raise ValueError("Oversized decision policy")
    config_hash=hashlib.sha256(policy_data).hexdigest()
    version=next((name for name,values in pins.items() if values["decision_policy.json"]==config_hash),None)
    if version is None:
        raise ValueError("Only the two pinned Helinity research exports are supported")
    os.environ.update(HF_HUB_OFFLINE="1",TRANSFORMERS_OFFLINE="1",HF_HUB_DISABLE_TELEMETRY="1")
    from tree_sitter import Language, Parser
    import tree_sitter_rust
    import torch
    from transformers import AutoTokenizer,T5ForSequenceClassification
    torch.set_num_threads(4)
    with TemporaryDirectory(prefix="helinity-model-") as tmp:
        dest=Path(tmp)
        for name,expected in pins[version].items():
            source=model_dir/name
            check_asset(source)
            if source.stat().st_size>250_000_000: raise ValueError("Asset exceeds budget")
            with source.open("rb") as origin,(dest/name).open("xb") as copy:
                copied=0
                while chunk:=origin.read(1024*1024):
                    copied+=len(chunk)
                    if copied>250_000_000:raise ValueError("Asset grew beyond limit")
                    copy.write(chunk)
            with (dest/name).open("rb") as stream:
                if hashlib.file_digest(stream,"sha256").hexdigest()!=expected:
                    raise ValueError("Model artifact hash mismatch")
        tokenizer=AutoTokenizer.from_pretrained(dest,local_files_only=True,trust_remote_code=False)
        model=T5ForSequenceClassification.from_pretrained(dest,local_files_only=True,use_safetensors=True).eval()
        policy=json.loads((dest/"decision_policy.json").read_bytes())
        root=Parser(Language(tree_sitter_rust.language())).parse(raw).root_node
        if root.has_error: raise ValueError("Rust parser reported a syntax error")
        nodes=[root];results=[]
        while nodes:
            node=nodes.pop()
            if node.type!="function_item":
                nodes.extend(reversed(node.named_children));continue
            if len(results)>=64: raise ValueError("At most 64 functions per experimental review")
            source=raw[node.start_byte:node.end_byte].decode("utf-8")
            if version=="v3":source=source.replace("\r\n","\n")
            tokenized=tokenizer([source],return_tensors="pt",split_special_tokens=True,return_token_type_ids=False,verbose=False)
            ids=tokenized["input_ids"][0]
            score=None
            if len(ids)>policy["max_length"]:reason="token limit"
            elif ids.tolist().count(tokenizer.eos_token_id)!=1:reason="tokenization"
            else:
                with torch.inference_mode():
                    score=float((model(**tokenized).logits/policy.get("temperature",1.0)).softmax(-1)[0,policy["positive_label_id"]])
                reason="near threshold" if abs(score-policy["threshold"])<=policy["abstention_margin"] else None
            results.append({"line":node.start_point.row+1,"score":score,"reason":reason,
                "decision":"abstain" if reason else "review" if score>=policy["threshold"] else "lower_score"})
    print(json.dumps({"category":"experimental_ml","verified":False,"cwe":None,"checkpoint":version,"results":results}))

if __name__=="__main__":
    main(Path(sys.argv[1]),Path(sys.argv[2]))
