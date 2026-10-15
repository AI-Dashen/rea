#!/usr/bin/env python
"""Read-only FLUTE v2 container inspector for authorized REA inputs."""
from __future__ import annotations
import argparse, hashlib, json, math, os, pathlib, struct
from android_container import ensure_target
MAGIC=b"FLUTE"; HEADER_SIZE=21; MAX_ENTRIES=4096; MAX_PATH_BYTES=4096; SAMPLE_BYTES=1024*1024

def sha256_file(path, offset=0, size=None):
    digest=hashlib.sha256(); remaining=size
    with path.open("rb") as stream:
        stream.seek(offset)
        while remaining is None or remaining>0:
            chunk=stream.read(1024*1024 if remaining is None else min(1024*1024,remaining))
            if not chunk: break
            digest.update(chunk)
            if remaining is not None: remaining-=len(chunk)
    if remaining not in (None,0): raise ValueError("FLUTE_TRUNCATED_ENTRY")
    return digest.hexdigest()

def safe_path(raw):
    try: value=raw.decode("utf-8")
    except UnicodeDecodeError as error: raise ValueError("FLUTE_PATH_ENCODING") from error
    normalized=value.lstrip("/"); parts=pathlib.PurePosixPath(normalized).parts
    if not normalized or value.endswith("/") or any(part in {"",".",".."} for part in parts):
        raise ValueError("FLUTE_UNSAFE_PATH")
    return "/"+"/".join(parts)

def entropy(data):
    if not data: return 0.0
    counts=[0]*256
    for value in data: counts[value]+=1
    length=len(data)
    return -sum((count/length)*math.log2(count/length) for count in counts if count)

def detect_magic(data):
    for signature,label in ((b"\x7fELF","ELF"),(b"PK\x03\x04","ZIP"),(b"\x89PNG\r\n\x1a\n","PNG"),(b"SQLite format 3\x00","SQLITE3"),(b"\x93NUMPY","NUMPY"),(b"{","JSON_OBJECT"),(b"[","JSON_ARRAY")):
        if data.startswith(signature): return label
    return "UNKNOWN"

def inspect_flute(path):
    file_size=path.stat().st_size
    with path.open("rb") as stream:
        header=stream.read(HEADER_SIZE)
        if len(header)!=HEADER_SIZE or header[:5]!=MAGIC: raise ValueError("FLUTE_MAGIC_INVALID")
        version,data_offset,entry_count=struct.unpack("<IQI",header[5:])
        if version!=2: raise ValueError("FLUTE_VERSION_UNSUPPORTED")
        if not 0<entry_count<=MAX_ENTRIES: raise ValueError("FLUTE_ENTRY_COUNT_INVALID")
        if data_offset<HEADER_SIZE or data_offset>file_size: raise ValueError("FLUTE_DATA_OFFSET_INVALID")
        entries=[]; names=set()
        for _ in range(entry_count):
            raw=bytearray()
            while True:
                if stream.tell()>=data_offset or len(raw)>=MAX_PATH_BYTES: raise ValueError("FLUTE_TABLE_TRUNCATED")
                value=stream.read(1)
                if value==b"\x00": break
                raw.extend(value)
            name=safe_path(bytes(raw))
            if name in names: raise ValueError("FLUTE_DUPLICATE_PATH")
            names.add(name); metadata=stream.read(24)
            if len(metadata)!=24: raise ValueError("FLUTE_TABLE_TRUNCATED")
            offset,size,tag=struct.unpack("<QQQ",metadata)
            if offset<data_offset or size>file_size or offset>file_size-size: raise ValueError("FLUTE_ENTRY_BOUNDS")
            entries.append({"path":name,"offset":offset,"size":size,"tag_hex":f"{tag:016x}"})
        table_end=stream.tell()
        if table_end!=data_offset: raise ValueError("FLUTE_TABLE_SIZE_MISMATCH")
    previous_end=data_offset
    for entry in sorted(entries,key=lambda item:(item["offset"],item["path"])):
        if entry["offset"]<previous_end: raise ValueError("FLUTE_ENTRY_OVERLAP")
        previous_end=entry["offset"]+entry["size"]
    for entry in entries:
        with path.open("rb") as stream:
            stream.seek(entry["offset"]); sample=stream.read(min(entry["size"],SAMPLE_BYTES))
        entry.update({"sha256":sha256_file(path,entry["offset"],entry["size"]),"sample_bytes":len(sample),"sample_entropy_bits_per_byte":round(entropy(sample),6),"sample_printable_ratio":round(sum(byte in b"\t\n\r" or 32<=byte<=126 for byte in sample)/len(sample),6) if sample else 0.0,"head_hex":sample[:32].hex(),"detected_magic":detect_magic(sample)})
    return {"schema_version":1,"provider":"rea-flute-v2","status":"VERIFIED","static_only":True,"input":str(path),"bytes":file_size,"sha256":sha256_file(path),"magic":"FLUTE","version":version,"data_offset":data_offset,"table_end":table_end,"entry_count":entry_count,"entries":entries,"limitations":["Container entries are inventoried and hashed but are not executed.","Entropy and printable ratios use a bounded first-megabyte sample.","Unknown payload formats are not claimed to be convertible models."]}

def write_result(result,output):
    output.parent.mkdir(parents=True,exist_ok=True); temporary=output.with_name(f".{output.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n"); os.replace(temporary,output)

def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",required=True); parser.add_argument("--output"); args=parser.parse_args()
    try:
        target=ensure_target(args.input)
        if not target.is_file(): raise ValueError("FLUTE_FILE_REQUIRED")
        result=inspect_flute(target)
        if args.output:
            output=pathlib.Path(args.output).resolve(); root=pathlib.Path(__file__).resolve().parents[2]
            if not output.is_relative_to(root): raise ValueError("FLUTE_OUTPUT_DENIED")
            write_result(result,output)
        print(json.dumps(result,ensure_ascii=False)); return 0
    except (OSError,ValueError) as error:
        print(json.dumps({"status":"FAILED","error":str(error)},ensure_ascii=False)); return 2
if __name__=="__main__": raise SystemExit(main())
