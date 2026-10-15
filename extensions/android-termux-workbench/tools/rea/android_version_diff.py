#!/usr/bin/env python
"""Complete, disk-backed differences between two REA DEX layer indexes."""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, sqlite3, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from dex_layer import ROOT, BASE, JOB_PATTERN, atomic_json, ensure_index, relative_to_root, utc_now
from evidence_contract import make_evidence_graph_v2, make_evidence_v2

DIFFS = BASE / "version-diffs"
SCHEMA = """
PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
CREATE TABLE changes(
 id INTEGER PRIMARY KEY, entity TEXT NOT NULL, item_key TEXT NOT NULL,
 change_kind TEXT NOT NULL, old_fingerprint TEXT, new_fingerprint TEXT,
 display TEXT, UNIQUE(entity,item_key,change_kind)
);
CREATE INDEX changes_entity_kind_idx ON changes(entity,change_kind);
"""

def checkpoint(job, phase, state, old_payload, new_payload, counts=None):
    atomic_json(job / "checkpoint.json", {"schema_version":1,"pipeline":"rea-android-version-diff-v1",
        "phase":phase,"state":state,"old_sha256":old_payload["target_sha256"],
        "new_sha256":new_payload["target_sha256"],"counts":counts or {},"updated_at":utc_now()})

def _normalise(connection, alias, table):
    connection.execute(f"CREATE TEMP TABLE {table}(entity TEXT,item_key TEXT,fingerprint TEXT,display TEXT,PRIMARY KEY(entity,item_key))")
    connection.execute(f"""INSERT INTO {table}
      SELECT 'class',java_name,group_concat(structural_sha256,'|'),java_name FROM
       (SELECT java_name,structural_sha256 FROM {alias}.classes ORDER BY java_name,structural_sha256)
      GROUP BY java_name""")
    connection.execute(f"""INSERT INTO {table}
      SELECT 'method',class_descriptor||'->'||name||prototype,
       group_concat(printf('%d:%s',access_flags,coalesce(code_sha256,'NO_CODE')),'|'),
       class_descriptor||'->'||name||prototype FROM
       (SELECT class_descriptor,name,prototype,access_flags,code_sha256 FROM {alias}.methods
        ORDER BY class_descriptor,name,prototype,access_flags,code_sha256)
      GROUP BY class_descriptor,name,prototype""")
    connection.execute(f"""INSERT INTO {table}
      SELECT 'string',value_sha256,printf('%d',count(*)),min(substr(value,1,200))
      FROM {alias}.strings GROUP BY value_sha256""")
    connection.execute(f"""INSERT INTO {table}
      SELECT CASE category WHEN 'native' THEN 'native_library' WHEN 'dex' THEN 'dex_member'
             WHEN 'manifest' THEN 'manifest' WHEN 'resource' THEN 'resource'
             WHEN 'asset' THEN 'asset' ELSE 'archive_member' END,
       container||'!/'||member,
       printf('%s:%d:%d:%s:%s',category,bytes,compressed_bytes,crc32,coalesce(strong_sha256,'')),
       member FROM {alias}.archive_members""")

def build_diff(old_index, new_index, job_name, resume=False):
    if not JOB_PATTERN.fullmatch(job_name): raise ValueError("INVALID_JOB")
    old_path, old_payload = ensure_index(old_index); new_path, new_payload = ensure_index(new_index)
    job = DIFFS / job_name
    if job.exists():
        if not resume: raise ValueError("JOB_EXISTS")
        existing = job / "diff.json"
        if existing.is_file():
            payload = json.loads(existing.read_text())
            if payload.get("old_sha256") == old_payload["target_sha256"] and payload.get("new_sha256") == new_payload["target_sha256"]: return payload
        saved = json.loads((job / "checkpoint.json").read_text())
        if saved.get("old_sha256") != old_payload["target_sha256"] or saved.get("new_sha256") != new_payload["target_sha256"]: raise ValueError("RESUME_INPUT_MISMATCH")
    else: job.mkdir(parents=True)
    checkpoint(job,"LOAD","IN_PROGRESS",old_payload,new_payload)
    output = job / "changes.sqlite3"; connection = sqlite3.connect(output)
    try:
        connection.executescript(SCHEMA)
        connection.execute("DELETE FROM changes")
        connection.execute("ATTACH DATABASE ? AS olddb", (str(ROOT / old_payload["database"]),))
        connection.execute("ATTACH DATABASE ? AS newdb", (str(ROOT / new_payload["database"]),))
        _normalise(connection,"olddb","old_entities"); _normalise(connection,"newdb","new_entities")
        checkpoint(job,"COMPARE","IN_PROGRESS",old_payload,new_payload)
        connection.execute("""INSERT INTO changes(entity,item_key,change_kind,old_fingerprint,new_fingerprint,display)
          SELECT o.entity,o.item_key,'REMOVED',o.fingerprint,NULL,o.display FROM old_entities o
          LEFT JOIN new_entities n ON n.entity=o.entity AND n.item_key=o.item_key WHERE n.item_key IS NULL""")
        connection.execute("""INSERT INTO changes(entity,item_key,change_kind,old_fingerprint,new_fingerprint,display)
          SELECT n.entity,n.item_key,'ADDED',NULL,n.fingerprint,n.display FROM new_entities n
          LEFT JOIN old_entities o ON o.entity=n.entity AND o.item_key=n.item_key WHERE o.item_key IS NULL""")
        connection.execute("""INSERT INTO changes(entity,item_key,change_kind,old_fingerprint,new_fingerprint,display)
          SELECT o.entity,o.item_key,'CHANGED',o.fingerprint,n.fingerprint,n.display FROM old_entities o
          JOIN new_entities n ON n.entity=o.entity AND n.item_key=o.item_key WHERE o.fingerprint<>n.fingerprint""")
        connection.commit()
        integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
        counts = {}
        for entity, kind, count in connection.execute("SELECT entity,change_kind,count(*) FROM changes GROUP BY entity,change_kind ORDER BY entity,change_kind"):
            counts.setdefault(entity,{"ADDED":0,"REMOVED":0,"CHANGED":0})[kind] = count
        total = connection.execute("SELECT count(*) FROM changes").fetchone()[0]
        samples = {}
        for entity, in connection.execute("SELECT DISTINCT entity FROM changes ORDER BY entity"):
            samples[entity] = [{"key":r[0],"change":r[1],"display":r[2]} for r in connection.execute(
                "SELECT item_key,change_kind,display FROM changes WHERE entity=? ORDER BY change_kind,item_key LIMIT 100",(entity,))]
    finally: connection.close()
    status = "VERIFIED" if old_payload["status"] == new_payload["status"] == "VERIFIED" and integrity == "ok" else "PARTIAL"
    result = {"schema_version":1,"pipeline":"rea-android-version-diff-v1","status":status,
        "old_index":relative_to_root(old_path),"new_index":relative_to_root(new_path),
        "old_sha256":old_payload["target_sha256"],"new_sha256":new_payload["target_sha256"],
        "input_status":{"old":old_payload["status"],"new":new_payload["status"]},
        "changes_database":relative_to_root(output),"change_count":total,"counts":counts,"samples":samples,
        "sqlite_quick_check":integrity,"detail_storage":"All changes are in changes.sqlite3; JSON samples are capped at 100 per entity.",
        "limitations":["Class and method changes are static DEX fingerprints, not proof of changed runtime behavior.",
                       "Resources and generic archive members use ZIP CRC/size metadata; DEX and native members also use SHA-256.",
                       "Renames appear as one removal and one addition unless a later semantic resolver links them."],
        "completed_at":utc_now()}
    combined_input=hashlib.sha256((old_payload["target_sha256"]+"\0"+new_payload["target_sha256"]).encode()).hexdigest()
    config_sha=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    diff_ev=make_evidence_v2(provider="rea-android-version-diff",kind="structural_version_diff",fidelity="static_fact",locator={"changes_database":result["changes_database"]},summary=f"Recorded {total} complete structural changes",input_sha256=combined_input,tool_versions={"rea-android-version-diff":"1.0"},config_sha256=config_sha,evidence_type="STATIC",match_quality="EXACT" if status=="VERIFIED" else "PARTIAL",session_ref=job_name,authorization_ref="local-workbench-invocation",observed_at=result["completed_at"],source_refs=[{"role":"old","sha256":old_payload["target_sha256"]},{"role":"new","sha256":new_payload["target_sha256"]}],digest=combined_input,confidence="HIGH" if status=="VERIFIED" else "MEDIUM",confidence_score=1.0 if status=="VERIFIED" else 0.7,metadata={"change_count":total,"input_status":result["input_status"]})
    result["evidence_graph_v2"]=make_evidence_graph_v2([diff_ev],generated_at=result["completed_at"])
    atomic_json(job / "diff.json", result)
    report = ["# Android 应用版本差异",f"状态：**{status}**",f"完整变化：{total} 项",f"旧版本：`{old_payload['target_sha256']}`",f"新版本：`{new_payload['target_sha256']}`","## 变化统计"]
    for entity, values in sorted(counts.items()): report.append(f"- {entity}: +{values['ADDED']} / -{values['REMOVED']} / ~{values['CHANGED']}")
    report.extend(["## 证据边界",*[f"- {item}" for item in result["limitations"]]])
    (job / "report.md").write_text("\n\n".join(report) + "\n")
    checkpoint(job,"COMPLETE","COMPLETED" if status=="VERIFIED" else "PARTIAL",old_payload,new_payload,counts); return result

def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--old-index",required=True); parser.add_argument("--new-index",required=True); parser.add_argument("--job",required=True); parser.add_argument("--resume",action="store_true"); args=parser.parse_args()
    try: result=build_diff(args.old_index,args.new_index,args.job,args.resume)
    except (OSError,ValueError,json.JSONDecodeError,sqlite3.Error) as error: print(json.dumps({"status":"FAILED","error":str(error)},ensure_ascii=False)); return 2
    print(json.dumps(result,ensure_ascii=False)); return 0 if result["status"]=="VERIFIED" else 3
if __name__=="__main__": raise SystemExit(main())
