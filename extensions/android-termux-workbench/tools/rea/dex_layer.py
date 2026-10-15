#!/usr/bin/env python
"""SQLite DEX index and exact, on-demand JADX class decompilation.

Target code is never executed. The cheap index makes large APKs searchable
without waiting for whole-application decompilation.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, mmap, os, pathlib, re, sqlite3, struct, sys, zipfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from android_container import ensure_target, inspect_target, materialize_apks_bundle
from runlog import JAVA, ROOT, run
from evidence_contract import make_evidence_graph_v2, make_evidence_v2, make_graph_edge_v2

BASE = ROOT / "run/rea-b06dd042"
JOBS = BASE / "dex-jobs"
def _find_jadx_jar():
    candidates = [
        os.environ.get("REA_JADX_JAR"),
        os.environ.get("REA_JADX_MCP_JAR"),
        "/data/data/com.termux/files/usr/share/java/jadx-1.5.6-all.jar",
        ROOT / "run/rea-3a0be4d8/jadx-local/data/data/com.termux/files/usr/share/java/jadx-1.5.6-all.jar",
    ]
    return next((pathlib.Path(value) for value in candidates if value and pathlib.Path(value).is_file()), pathlib.Path("/nonexistent/jadx.jar"))

JADX_JAR = _find_jadx_jar()
JOB_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DEX_MAGIC = re.compile(br"dex\n\d{3}\x00")
MAX_DEX_BYTES, MAX_TABLE_ITEMS = 512 * 1024 * 1024, 2_000_000
MAX_STRING_BYTES, MAX_STORED_STRING_CHARS = 4 * 1024 * 1024, 16_384

def utc_now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def sha256_file(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): digest.update(chunk)
    return digest.hexdigest()
def atomic_json(path, payload):
    path = pathlib.Path(path); temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n"); os.replace(temporary, path)
def relative_to_root(path): return str(pathlib.Path(path).resolve().relative_to(ROOT.resolve()))
def target_fingerprint(view):
    if len(view["units"]) == 1 and pathlib.Path(view["target"]).is_file(): return view["units"][0]["sha256"]
    material = "\n".join(f"{pathlib.Path(u['path']).name}\0{u['sha256']}" for u in sorted(view["units"], key=lambda x: pathlib.Path(x["path"]).name))
    return hashlib.sha256(material.encode()).hexdigest()
def _uleb(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data): raise ValueError("DEX_TRUNCATED_ULEB128")
        byte = data[offset]; offset += 1; value |= (byte & 0x7f) << shift
        if not byte & 0x80: return value, offset
    raise ValueError("DEX_INVALID_ULEB128")
def _sleb(data, offset):
    value = shift = 0
    for _ in range(5):
        if offset >= len(data): raise ValueError("DEX_TRUNCATED_SLEB128")
        byte = data[offset]; offset += 1; value |= (byte & 0x7f) << shift; shift += 7
        if not byte & 0x80:
            if shift < 32 and byte & 0x40: value |= -(1 << shift)
            return value, offset
    raise ValueError("DEX_INVALID_SLEB128")

class DexReader:
    """Bounded DEX identity/symbol parser."""
    def __init__(self, data):
        self.data = data; self.strings = {}; self.types = {}; self.protos = {}; self.methods = {}; self.fields = {}
        self.header = self._read_header()
    def _range(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data): raise ValueError("DEX_TABLE_OUT_OF_RANGE")
    def u16(self, offset): self._range(offset, 2); return struct.unpack_from("<H", self.data, offset)[0]
    def u32(self, offset): self._range(offset, 4); return struct.unpack_from("<I", self.data, offset)[0]
    def _read_header(self):
        if len(self.data) < 112 or not DEX_MAGIC.fullmatch(bytes(self.data[:8])): raise ValueError("DEX_HEADER_INVALID")
        names = ("file_size","header_size","endian_tag","link_size","link_off","map_off","string_ids_size","string_ids_off","type_ids_size","type_ids_off","proto_ids_size","proto_ids_off","field_ids_size","field_ids_off","method_ids_size","method_ids_off","class_defs_size","class_defs_off","data_size","data_off")
        header = dict(zip(names, struct.unpack_from("<20I", self.data, 32)))
        if header["file_size"] > len(self.data) or header["header_size"] < 112: raise ValueError("DEX_FILE_SIZE_INVALID")
        if header["endian_tag"] != 0x12345678: raise ValueError("DEX_ENDIAN_UNSUPPORTED")
        for name, width in (("string_ids",4),("type_ids",4),("proto_ids",12),("field_ids",8),("method_ids",8),("class_defs",32)):
            count, offset = header[f"{name}_size"], header[f"{name}_off"]
            if count > MAX_TABLE_ITEMS: raise ValueError(f"DEX_{name.upper()}_LIMIT")
            self._range(offset, count * width)
        return header
    def string(self, index):
        if index in self.strings: return self.strings[index]
        if not 0 <= index < self.header["string_ids_size"]: raise ValueError("DEX_STRING_INDEX_INVALID")
        offset = self.u32(self.header["string_ids_off"] + index * 4); utf16_length, start = _uleb(self.data, offset)
        end = self.data.find(b"\0", start, min(len(self.data), start + MAX_STRING_BYTES + 1))
        if end < 0: raise ValueError("DEX_STRING_TOO_LARGE_OR_UNTERMINATED")
        raw = bytes(self.data[start:end]); value = raw.replace(b"\xc0\x80", b"\0").decode("utf-8", errors="replace")
        result = (value[:MAX_STORED_STRING_CHARS], hashlib.sha256(raw).hexdigest(), len(raw), utf16_length, int(len(value) > MAX_STORED_STRING_CHARS))
        self.strings[index] = result; return result
    def type(self, index):
        if index not in self.types:
            if not 0 <= index < self.header["type_ids_size"]: raise ValueError("DEX_TYPE_INDEX_INVALID")
            self.types[index] = self.string(self.u32(self.header["type_ids_off"] + index * 4))[0]
        return self.types[index]
    def proto(self, index):
        if index in self.protos: return self.protos[index]
        if not 0 <= index < self.header["proto_ids_size"]: raise ValueError("DEX_PROTO_INDEX_INVALID")
        offset = self.header["proto_ids_off"] + index * 12; result, parameters_off = self.type(self.u32(offset + 4)), self.u32(offset + 8); parameters = []
        if parameters_off:
            size = self.u32(parameters_off)
            if size > self.header["type_ids_size"]: raise ValueError("DEX_PROTO_PARAMETER_LIMIT")
            self._range(parameters_off + 4, size * 2); parameters = [self.type(self.u16(parameters_off + 4 + i * 2)) for i in range(size)]
        self.protos[index] = f"({''.join(parameters)}){result}"; return self.protos[index]
    def method(self, index):
        if index not in self.methods:
            if not 0 <= index < self.header["method_ids_size"]: raise ValueError("DEX_METHOD_INDEX_INVALID")
            offset = self.header["method_ids_off"] + index * 8
            self.methods[index] = (self.type(self.u16(offset)), self.string(self.u32(offset + 4))[0], self.proto(self.u16(offset + 2)))
        return self.methods[index]
    def field(self, index):
        if index not in self.fields:
            if not 0 <= index < self.header["field_ids_size"]: raise ValueError("DEX_FIELD_INDEX_INVALID")
            offset = self.header["field_ids_off"] + index * 8
            self.fields[index] = (self.type(self.u16(offset)), self.string(self.u32(offset + 4))[0], self.type(self.u16(offset + 2)))
        return self.fields[index]
    def code_hash(self, offset):
        if not offset: return None
        self._range(offset, 16); tries_size, instructions = self.u16(offset + 6), self.u32(offset + 12); end = offset + 16 + instructions * 2; self._range(offset, end - offset)
        if tries_size:
            if instructions & 1: end += 2
            self._range(end, tries_size * 8); end += tries_size * 8; count, cursor = _uleb(self.data, end)
            if count > MAX_TABLE_ITEMS: raise ValueError("DEX_CATCH_HANDLER_LIMIT")
            for _ in range(count):
                size, cursor = _sleb(self.data, cursor)
                for _ in range(abs(size)): _, cursor = _uleb(self.data, cursor); _, cursor = _uleb(self.data, cursor)
                if size <= 0: _, cursor = _uleb(self.data, cursor)
            end = cursor
        self._range(offset, end - offset); return hashlib.sha256(self.data[offset:end]).hexdigest()
    def class_data(self, offset):
        if not offset: return [], []
        counts, cursor = [], offset
        for _ in range(4):
            count, cursor = _uleb(self.data, cursor)
            if count > MAX_TABLE_ITEMS: raise ValueError("DEX_CLASS_MEMBER_LIMIT")
            counts.append(count)
        fields = []
        for count in counts[:2]:
            field_index = 0
            for _ in range(count):
                delta, cursor = _uleb(self.data, cursor); access, cursor = _uleb(self.data, cursor); field_index += delta; fields.append((*self.field(field_index), access))
        methods = []
        for count in counts[2:]:
            method_index = 0
            for _ in range(count):
                delta, cursor = _uleb(self.data, cursor); access, cursor = _uleb(self.data, cursor); code_off, cursor = _uleb(self.data, cursor); method_index += delta
                owner, name, prototype = self.method(method_index); methods.append((method_index, owner, name, prototype, access, code_off, self.code_hash(code_off)))
        return fields, methods
    def iter_classes(self):
        for ordinal in range(self.header["class_defs_size"]):
            offset = self.header["class_defs_off"] + ordinal * 32
            class_idx, access, super_idx, interfaces_off, source_idx, _, class_data_off, _ = struct.unpack_from("<8I", self.data, offset)
            descriptor = self.type(class_idx); superclass = None if super_idx == 0xffffffff else self.type(super_idx); source = None if source_idx == 0xffffffff else self.string(source_idx)[0]; interfaces = []
            if interfaces_off:
                size = self.u32(interfaces_off)
                if size > self.header["type_ids_size"]: raise ValueError("DEX_INTERFACE_LIMIT")
                interfaces = [self.type(self.u16(interfaces_off + 4 + i * 2)) for i in range(size)]
            fields, methods = self.class_data(class_data_off)
            identity = {"descriptor":descriptor,"access":access,"superclass":superclass,"interfaces":interfaces,"fields":fields,"methods":[(m[2],m[3],m[4],m[6]) for m in methods]}
            fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest(); java_name = descriptor[1:-1].replace("/", ".") if descriptor.startswith("L") and descriptor.endswith(";") else descriptor
            yield (class_idx, descriptor, java_name, superclass, source, access, class_data_off, fingerprint, methods)

SCHEMA = """
PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS dex_units(id INTEGER PRIMARY KEY,unit_key TEXT UNIQUE,container TEXT,member TEXT,bytes INTEGER,sha256 TEXT,status TEXT,error TEXT,string_count INTEGER DEFAULT 0,class_count INTEGER DEFAULT 0,method_count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS strings(dex_unit_id INTEGER,string_idx INTEGER,value TEXT,value_sha256 TEXT,byte_length INTEGER,utf16_length INTEGER,truncated INTEGER,PRIMARY KEY(dex_unit_id,string_idx));
CREATE INDEX IF NOT EXISTS strings_hash_idx ON strings(value_sha256);
CREATE TABLE IF NOT EXISTS classes(dex_unit_id INTEGER,class_idx INTEGER,descriptor TEXT,java_name TEXT,super_descriptor TEXT,source_file TEXT,access_flags INTEGER,class_data_off INTEGER,structural_sha256 TEXT,PRIMARY KEY(dex_unit_id,class_idx));
CREATE INDEX IF NOT EXISTS classes_name_idx ON classes(java_name);
CREATE TABLE IF NOT EXISTS methods(dex_unit_id INTEGER,method_idx INTEGER,class_descriptor TEXT,name TEXT,prototype TEXT,access_flags INTEGER,code_off INTEGER,code_sha256 TEXT,PRIMARY KEY(dex_unit_id,method_idx));
CREATE INDEX IF NOT EXISTS methods_owner_name_idx ON methods(class_descriptor,name);
CREATE TABLE IF NOT EXISTS archive_members(container TEXT,member TEXT,category TEXT,bytes INTEGER,compressed_bytes INTEGER,crc32 TEXT,strong_sha256 TEXT,PRIMARY KEY(container,member));
"""
def _category(name):
    lower = name.lower()
    if lower.endswith(".dex"): return "dex"
    if lower.endswith(".so"): return "native"
    if lower.endswith("androidmanifest.xml"): return "manifest"
    if lower.endswith((".xml", ".arsc")) or "/res/" in f"/{lower}": return "resource"
    if lower.startswith("assets/") or "/assets/" in f"/{lower}": return "asset"
    return "other"
def analysis_view(target, source_view, job):
    if source_view["kind"] != "APKS": return source_view
    output = job / "apks-units"; return inspect_target(output) if output.exists() else materialize_apks_bundle(target, output)
def _unit_label(view, unit):
    if len(view["units"]) == 1: return "base"
    if unit.get("role") == "base": return "base"
    return pathlib.Path(unit["path"]).name
def inventory(connection, view):
    for unit in view["units"]:
        label = _unit_label(view, unit); strong = {i["path"]:i["sha256"] for i in unit.get("dex", []) + unit.get("native_libraries", [])}
        with zipfile.ZipFile(unit["path"]) as archive:
            for info in archive.infolist():
                if not info.is_dir(): connection.execute("INSERT OR REPLACE INTO archive_members VALUES(?,?,?,?,?,?,?)", (label,info.filename,_category(info.filename),info.file_size,info.compress_size,f"{info.CRC:08x}",strong.get(info.filename)))
def dex_units(view):
    return [{"key":f"{_unit_label(view,u)}!/{i['path']}","container":pathlib.Path(u["path"]),"label":_unit_label(view,u),"member":i["path"],"bytes":i["bytes"],"sha256":i["sha256"]} for u in view["units"] for i in sorted(u["dex"], key=lambda x:x["path"])]
def extract_dex(unit, job):
    if unit["bytes"] > MAX_DEX_BYTES: raise ValueError("DEX_MEMBER_TOO_LARGE")
    temporary = job / ".current.dex"; digest, size = hashlib.sha256(), 0
    with zipfile.ZipFile(unit["container"]) as archive:
        matches = [i for i in archive.infolist() if i.filename == unit["member"]]
        if len(matches) != 1: raise ValueError("DEX_MEMBER_NOT_UNIQUE")
        with archive.open(matches[0]) as source, temporary.open("wb") as output:
            for chunk in iter(lambda:source.read(1024*1024), b""):
                size += len(chunk)
                if size > MAX_DEX_BYTES: raise ValueError("DEX_MEMBER_TOO_LARGE")
                digest.update(chunk); output.write(chunk)
    if size != unit["bytes"] or digest.hexdigest() != unit["sha256"]: temporary.unlink(missing_ok=True); raise ValueError("DEX_MEMBER_DIGEST_MISMATCH")
    return temporary
def index_unit(connection, unit, path):
    old = connection.execute("SELECT id FROM dex_units WHERE unit_key=?", (unit["key"],)).fetchone()
    if old:
        for table in ("strings","classes","methods"): connection.execute(f"DELETE FROM {table} WHERE dex_unit_id=?", (old[0],))
        connection.execute("DELETE FROM dex_units WHERE id=?", (old[0],))
    cursor = connection.execute("INSERT INTO dex_units(unit_key,container,member,bytes,sha256,status) VALUES(?,?,?,?,?,'INDEXING')", (unit["key"],unit["label"],unit["member"],unit["bytes"],unit["sha256"])); unit_id = cursor.lastrowid
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        reader = DexReader(data); connection.executemany("INSERT INTO strings VALUES(?,?,?,?,?,?,?)", ((unit_id,i,*reader.string(i)) for i in range(reader.header["string_ids_size"])))
        class_count = method_count = 0
        for item in reader.iter_classes():
            connection.execute("INSERT INTO classes VALUES(?,?,?,?,?,?,?,?,?)", (unit_id,*item[:8])); connection.executemany("INSERT INTO methods VALUES(?,?,?,?,?,?,?,?)", ((unit_id,*m) for m in item[8])); class_count += 1; method_count += len(item[8])
        connection.execute("UPDATE dex_units SET status='VERIFIED',string_count=?,class_count=?,method_count=? WHERE id=?", (reader.header["string_ids_size"],class_count,method_count,unit_id))
    return {"unit_key":unit["key"],"status":"VERIFIED","sha256":unit["sha256"],"bytes":unit["bytes"],"strings":reader.header["string_ids_size"],"classes":class_count,"declared_methods":method_count}
def checkpoint(job,target,digest,phase,state,units): atomic_json(job/"checkpoint.json", {"schema_version":1,"pipeline":"rea-dex-layer-v1","phase":phase,"state":state,"input":relative_to_root(target),"target_sha256":digest,"units":units,"updated_at":utc_now()})
def build_index(target, job_name, resume=False):
    if not JOB_PATTERN.fullmatch(job_name): raise ValueError("INVALID_JOB")
    target = ensure_target(str(target)); source_view = inspect_target(target); digest = target_fingerprint(source_view); job = JOBS/job_name
    if job.exists() and not resume: raise ValueError("JOB_EXISTS")
    if job.exists():
        saved = json.loads((job/"checkpoint.json").read_text())
        if saved.get("input") != relative_to_root(target) or saved.get("target_sha256") != digest: raise ValueError("RESUME_INPUT_MISMATCH")
    else: job.mkdir(parents=True)
    view = analysis_view(target,source_view,job); units=dex_units(view); states=[]; checkpoint(job,target,digest,"INVENTORY","IN_PROGRESS",states); database=job/"index.sqlite3"; connection=sqlite3.connect(database)
    try:
        connection.executescript(SCHEMA)
        with connection: connection.execute("INSERT OR REPLACE INTO meta VALUES('input',?)",(relative_to_root(target),)); connection.execute("INSERT OR REPLACE INTO meta VALUES('target_sha256',?)",(digest,)); inventory(connection,view)
        completed=dict(connection.execute("SELECT unit_key,sha256 FROM dex_units WHERE status='VERIFIED'"))
        for unit in units:
            if completed.get(unit["key"]) == unit["sha256"]:
                row=connection.execute("SELECT string_count,class_count,method_count FROM dex_units WHERE unit_key=?",(unit["key"],)).fetchone(); state={"unit_key":unit["key"],"status":"VERIFIED","sha256":unit["sha256"],"bytes":unit["bytes"],"strings":row[0],"classes":row[1],"declared_methods":row[2],"resumed":True}
            else:
                dex_path=None
                try:
                    dex_path=extract_dex(unit,job)
                    with connection: state=index_unit(connection,unit,dex_path)
                except (OSError,ValueError,sqlite3.Error,struct.error) as error:
                    with connection: connection.execute("INSERT OR REPLACE INTO dex_units(unit_key,container,member,bytes,sha256,status,error) VALUES(?,?,?,?,?,'FAILED',?)",(unit["key"],unit["label"],unit["member"],unit["bytes"],unit["sha256"],f"{type(error).__name__}:{error}"))
                    state={"unit_key":unit["key"],"status":"FAILED","sha256":unit["sha256"],"bytes":unit["bytes"],"error":f"{type(error).__name__}:{error}"}
                finally:
                    if dex_path: dex_path.unlink(missing_ok=True)
            states.append(state); checkpoint(job,target,digest,"SYMBOLS","IN_PROGRESS",states)
        if target_fingerprint(inspect_target(target)) != digest: raise ValueError("INPUT_CHANGED")
        integrity=connection.execute("PRAGMA quick_check").fetchone()[0]; counts={"dex_units":connection.execute("SELECT count(*) FROM dex_units WHERE status='VERIFIED'").fetchone()[0],"strings":connection.execute("SELECT count(*) FROM strings").fetchone()[0],"classes":connection.execute("SELECT count(*) FROM classes").fetchone()[0],"declared_methods":connection.execute("SELECT count(*) FROM methods").fetchone()[0],"archive_members":connection.execute("SELECT count(*) FROM archive_members").fetchone()[0]}
    finally: connection.close()
    succeeded=sum(s["status"]=="VERIFIED" for s in states); status="VERIFIED" if units and succeeded==len(units) and integrity=="ok" else ("PARTIAL" if succeeded else "FAILED")
    result={"schema_version":1,"pipeline":"rea-dex-layer-v1","status":status,"input":relative_to_root(target),"target_sha256":digest,"container_kind":source_view["kind"],"analysis_semantics":source_view["analysis_semantics"],"database":relative_to_root(database),"jadx_inputs":[relative_to_root(u["path"]) for u in view["units"]],"layers":{"inventory":"VERIFIED","symbols":status,"on_demand_decompilation":"AVAILABLE" if succeeded else "UNAVAILABLE"},"counts":counts,"units":states,"sqlite_quick_check":integrity,"limitations":["Static DEX parsing and JADX output do not prove runtime behavior.","Method fingerprints exclude debug information.","Resources use ZIP size/CRC metadata unless a DEX/native SHA-256 is available.","Very long strings remain hash-indexed while their display value is truncated."],"completed_at":utc_now()}
    config_sha=sha256_file(pathlib.Path(__file__))
    common={"input_sha256":digest,"tool_versions":{"rea-dex-layer":"1.0"},"config_sha256":config_sha,"evidence_type":"STATIC","session_ref":job_name,"authorization_ref":"local-workbench-invocation","observed_at":result["completed_at"],"digest":digest}
    inventory_ev=make_evidence_v2(provider="rea-dex-layer",kind="archive_inventory",fidelity="static_fact",locator={"input":result["input"],"database":result["database"]},summary=f"Indexed {counts['archive_members']} archive members across {len(view['units'])} package units",match_quality="EXACT",source_refs=[{"path":result["input"]}],confidence="HIGH",confidence_score=1.0,metadata={"container_kind":source_view["kind"]},**common)
    symbols_ev=make_evidence_v2(provider="rea-dex-layer",kind="dex_symbol_index",fidelity="static_fact",locator={"database":result["database"]},summary=f"Indexed {counts['classes']} classes and {counts['declared_methods']} declared methods",match_quality="EXACT" if status=="VERIFIED" else "PARTIAL",source_refs=[{"path":u["unit_key"],"sha256":u["sha256"]} for u in states if u["status"]=="VERIFIED"],confidence="HIGH" if status=="VERIFIED" else "MEDIUM",confidence_score=1.0 if status=="VERIFIED" else 0.7,metadata={"completeness":status,"failed_units":sum(u["status"]!="VERIFIED" for u in states)},**common)
    result["evidence_graph_v2"]=make_evidence_graph_v2([inventory_ev,symbols_ev],edges=[make_graph_edge_v2(source=inventory_ev["evidence_id"],target=symbols_ev["evidence_id"],relation="CONTAINS_INDEX",match_quality="EXACT" if status=="VERIFIED" else "PARTIAL")],generated_at=result["completed_at"])
    atomic_json(job/"index.json",result); checkpoint(job,target,digest,"COMPLETE","COMPLETED" if status=="VERIFIED" else status,states); return result
def ensure_index(value):
    path=pathlib.Path(value); path=(ROOT/path if not path.is_absolute() else path).resolve(strict=True); path=(path/"index.json").resolve(strict=True) if path.is_dir() else path
    if path.is_symlink() or not path.is_file() or not path.is_relative_to(JOBS.resolve()): raise ValueError("INDEX_DENIED")
    payload=json.loads(path.read_text())
    if payload.get("pipeline")!="rea-dex-layer-v1" or payload.get("status") not in {"VERIFIED","PARTIAL"}: raise ValueError("INDEX_NOT_USABLE")
    database=(ROOT/payload["database"]).resolve(strict=True)
    if not database.is_file() or not database.is_relative_to(path.parent): raise ValueError("INDEX_DATABASE_DENIED")
    return path,payload
def search_index(index,query,kind="class",limit=100):
    _,payload=ensure_index(index)
    if not query or len(query)>512: raise ValueError("QUERY_INVALID")
    if not 1<=limit<=1000: raise ValueError("LIMIT_INVALID")
    connection=sqlite3.connect(f"file:{ROOT/payload['database']}?mode=ro",uri=True); escaped=query.replace("\\","\\\\").replace("%","\\%").replace("_","\\_")
    try:
        if kind=="class": return [{"java_name":r[0],"descriptor":r[1],"structural_sha256":r[2]} for r in connection.execute("SELECT java_name,descriptor,structural_sha256 FROM classes WHERE java_name LIKE ? ESCAPE '\\' ORDER BY java_name LIMIT ?",(f"%{escaped}%",limit))]
        if kind=="method": return [{"class_descriptor":r[0],"name":r[1],"prototype":r[2],"code_sha256":r[3]} for r in connection.execute("SELECT class_descriptor,name,prototype,code_sha256 FROM methods WHERE name LIKE ? ESCAPE '\\' ORDER BY class_descriptor,name LIMIT ?",(f"%{escaped}%",limit))]
        if kind=="string": return [{"value":r[0],"value_sha256":r[1],"byte_length":r[2],"truncated":bool(r[3])} for r in connection.execute("SELECT value,value_sha256,byte_length,truncated FROM strings WHERE value LIKE ? ESCAPE '\\' ORDER BY byte_length LIMIT ?",(f"%{escaped}%",limit))]
        raise ValueError("SEARCH_KIND_INVALID")
    finally: connection.close()
def decompile_class(index,class_name,timeout=180):
    index_path,payload=ensure_index(index)
    if not class_name or len(class_name)>512 or any(c in class_name for c in "\r\n\0"): raise ValueError("CLASS_NAME_INVALID")
    connection=sqlite3.connect(f"file:{ROOT/payload['database']}?mode=ro",uri=True)
    try: matches=connection.execute("SELECT descriptor,structural_sha256 FROM classes WHERE java_name=?",(class_name,)).fetchall()
    finally: connection.close()
    if not matches: raise ValueError("CLASS_NOT_INDEXED")
    if len({r[0] for r in matches})!=1: raise ValueError("CLASS_AMBIGUOUS")
    target=ensure_target(str(ROOT/payload["input"]))
    if target_fingerprint(inspect_target(target))!=payload["target_sha256"]: raise ValueError("INPUT_CHANGED")
    if not JADX_JAR.is_file(): raise ValueError("JADX_UNAVAILABLE")
    jadx_options=["-j","1","--no-res","--single-class"]
    decompiler={"name":"jadx","version":"1.5.6","jar_sha256":sha256_file(JADX_JAR),"options":jadx_options}
    decompiler["config_sha256"]=hashlib.sha256(json.dumps(decompiler,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    key=hashlib.sha256((payload["target_sha256"]+"\0"+class_name+"\0"+decompiler["config_sha256"]).encode()).hexdigest()[:24]; output=index_path.parent/"decompiled"/key; output.mkdir(parents=True,exist_ok=True); result_path,source=output/"result.json",output/"source.java"
    if result_path.is_file():
        cached=json.loads(result_path.read_text())
        if cached.get("status")=="VERIFIED" and cached.get("decompiler",{}).get("config_sha256")==decompiler["config_sha256"] and source.is_file() and sha256_file(source)==cached.get("source_sha256"): return cached
    inputs=[]
    for value in payload["jadx_inputs"]:
        path=(ROOT/value).resolve(strict=True)
        if not path.is_file() or not (path.is_relative_to((BASE/"inbox").resolve()) or path.is_relative_to((BASE/"samples").resolve()) or path.is_relative_to(index_path.parent.resolve())): raise ValueError("JADX_INPUT_DENIED")
        inputs.append(path)
    record=run("jadx-single",[JAVA,"-Xmx768m","-XX:ActiveProcessorCount=1","-cp",JADX_JAR,"jadx.cli.JadxCLI",*jadx_options,class_name,"--single-class-output",source,*inputs],output,max(30,min(timeout,900))); valid=source.is_file() and source.stat().st_size>0; status="VERIFIED" if record["exit_code"]==0 and valid else ("PARTIAL" if valid else "FAILED")
    result={"schema_version":1,"pipeline":"rea-dex-class-on-demand-v1","status":status,"index":relative_to_root(index_path),"target_sha256":payload["target_sha256"],"class_name":class_name,"descriptor":matches[0][0],"class_structural_sha256":matches[0][1],"decompiler":decompiler,"command":record,"source":relative_to_root(source) if valid else None,"source_sha256":sha256_file(source) if valid else None,"completed_at":utc_now(),"limitations":["JADX source is an approximate static reconstruction, not original source."]}; atomic_json(result_path,result); return result
def main():
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest="command",required=True)
    p=sub.add_parser("index"); p.add_argument("--input",required=True); p.add_argument("--job",required=True); p.add_argument("--resume",action="store_true")
    p=sub.add_parser("search"); p.add_argument("--index",required=True); p.add_argument("--kind",choices=("class","method","string"),default="class"); p.add_argument("--query",required=True); p.add_argument("--limit",type=int,default=100)
    p=sub.add_parser("class"); p.add_argument("--index",required=True); p.add_argument("--name",required=True); p.add_argument("--timeout",type=int,default=180); args=parser.parse_args()
    try:
        if args.command=="index": result=build_index(pathlib.Path(args.input),args.job,args.resume)
        elif args.command=="search": result={"status":"VERIFIED","results":search_index(args.index,args.query,args.kind,args.limit)}
        else: result=decompile_class(args.index,args.name,args.timeout)
    except (OSError,ValueError,json.JSONDecodeError,sqlite3.Error,zipfile.BadZipFile) as error: print(json.dumps({"status":"FAILED","error":str(error)},ensure_ascii=False)); return 2
    print(json.dumps(result,ensure_ascii=False)); return 0 if result["status"]=="VERIFIED" else 3
if __name__=="__main__": raise SystemExit(main())
