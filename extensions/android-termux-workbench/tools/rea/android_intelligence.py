"""Evidence-first Android architecture and hotspot analysis."""
from __future__ import annotations

import hashlib
import pathlib
import re
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_SOURCE_FILES = 5000
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_PER_CATEGORY = 100

HOTSPOT_RULES = {
    "authentication": re.compile(r"\b(login|sign[ -]?in|auth(?:entication)?|oauth|password|credential|access[_ ]?token)\b", re.I),
    "network": re.compile(r"\b(okhttp|retrofit|httpurlconnection|websocket|socket|loadurl|url\s*\()", re.I),
    "cryptography": re.compile(r"\b(cipher|messagedigest|secretkeyspec|keystore|keygenerator|aes|rsa|hmac)\b", re.I),
    "root_detection": re.compile(r"(?:/system/(?:xbin|bin)/su|\bmagisk\b|\btest-keys\b|\bwhich\s+su\b|build\.tags)", re.I),
    "debug_detection": re.compile(r"\b(isDebuggerConnected|waitingForDebugger|TracerPid|ro\.debuggable|ptrace)\b", re.I),
    "device_identity": re.compile(r"\b(ANDROID_ID|TelephonyManager|getDeviceId|getImei|Build\.SERIAL|AdvertisingId)\b", re.I),
    "native_bridge": re.compile(r"\b(System\.loadLibrary|System\.load|native\s+[\w<])", re.I),
}
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.I)
LOAD_LIBRARY_PATTERN = re.compile(r"System\.loadLibrary\s*\(\s*[\"']([^\"']+)[\"']\s*\)")
NATIVE_METHOD_PATTERN = re.compile(r"\bnative\s+[\w.$<>\[\]]+\s+(\w+)\s*\(")
PACKAGE_PATTERN = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
TYPE_PATTERN = re.compile(r"\b(?:class|interface|enum|object)\s+(\w+)")


def _sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def _node_id(kind: str, value: str) -> str:
    return f"{kind}_{_sha(kind + chr(0) + value)[:16]}"


def _source_evidence(path: str, line_number: int, line: str, rule: str) -> dict:
    return {
        "path": path,
        "line": line_number,
        "matched_rule": rule,
        "line_sha256": _sha(line.rstrip()),
    }


def _manifest_components(manifest_text: str) -> tuple[list[dict], list[str]]:
    components = []
    warnings = []
    if not manifest_text:
        return components, ["MANIFEST_TEXT_UNAVAILABLE"]
    try:
        root = ET.fromstring(manifest_text)
    except ET.ParseError as error:
        return components, [f"MANIFEST_PARSE_FAILED:{error}"]
    application = root.find("application")
    if application is None:
        return components, warnings
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for item in application.findall(kind):
            name = item.get(ANDROID_NS + "name")
            if not name:
                continue
            components.append(
                {
                    "kind": kind,
                    "name": name,
                    "exported": item.get(ANDROID_NS + "exported"),
                    "permission": item.get(ANDROID_NS + "permission"),
                }
            )
    return components, warnings


def build_android_intelligence(
    apk_path: pathlib.Path,
    sources_root: pathlib.Path,
    package_data: dict,
    package_profile: dict,
) -> dict:
    apk_path = apk_path.resolve(strict=True)
    sources_root = sources_root.resolve(strict=True)
    nodes: list[dict] = []
    edges: list[dict] = []
    hotspots = {name: [] for name in HOTSPOT_RULES}
    url_origins: set[str] = set()
    warnings: list[str] = []
    class_by_library: dict[str, set[str]] = {}
    native_methods: list[dict] = []
    scanned_files = 0
    scanned_bytes = 0

    def add_node(kind: str, value: str, **properties):
        node_id = _node_id(kind, value)
        if not any(node["id"] == node_id for node in nodes):
            nodes.append({"id": node_id, "kind": kind, "value": value, **properties})
        return node_id

    def add_edge(source: str, target: str, relation: str, **evidence):
        candidate = {"source": source, "target": target, "relation": relation, **evidence}
        if candidate not in edges:
            edges.append(candidate)

    package_name = package_data.get("package_name") or "(unknown)"
    package_node = add_node("package", package_name)
    for dex in package_profile.get("dex", []):
        dex_node = add_node("dex", dex["path"], sha256=dex["sha256"], bytes=dex["bytes"])
        add_edge(package_node, dex_node, "contains")

    components, manifest_warnings = _manifest_components(
        package_data.get("manifest", {}).get("text", "")
    )
    warnings.extend(manifest_warnings)
    for component in components:
        component_node = add_node(
            "android_component",
            f"{component['kind']}:{component['name']}",
            component_type=component["kind"],
            component_name=component["name"],
            exported=component["exported"],
            permission=component["permission"],
        )
        add_edge(package_node, component_node, "declares")

    source_files = sorted(
        path
        for path in sources_root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".java", ".kt"}
    )
    if len(source_files) > MAX_SOURCE_FILES:
        warnings.append("SOURCE_FILE_LIMIT_REACHED")
        source_files = source_files[:MAX_SOURCE_FILES]
    for source in source_files:
        if source.stat().st_size > 1024 * 1024:
            warnings.append(f"SOURCE_FILE_SKIPPED_TOO_LARGE:{source.relative_to(sources_root)}")
            continue
        if scanned_bytes + source.stat().st_size > MAX_SOURCE_BYTES:
            warnings.append("SOURCE_BYTE_LIMIT_REACHED")
            break
        text = source.read_text(errors="replace")
        scanned_files += 1
        scanned_bytes += len(text.encode(errors="replace"))
        relative = source.relative_to(sources_root).as_posix()
        package_match = PACKAGE_PATTERN.search(text)
        type_match = TYPE_PATTERN.search(text)
        class_name = (
            f"{package_match.group(1)}.{type_match.group(1)}"
            if package_match and type_match
            else relative.removesuffix(source.suffix).replace("/", ".")
        )
        class_node = add_node("class", class_name, source_path=relative)
        add_edge(package_node, class_node, "contains")

        for number, line in enumerate(text.splitlines(), start=1):
            for category, pattern in HOTSPOT_RULES.items():
                if (
                    len(hotspots[category]) < MAX_EVIDENCE_PER_CATEGORY
                    and pattern.search(line)
                ):
                    hotspots[category].append(
                        _source_evidence(relative, number, line, category)
                    )
            for raw_url in URL_PATTERN.findall(line):
                parsed = urllib.parse.urlsplit(raw_url.rstrip(".,);]"))
                if parsed.scheme and parsed.netloc:
                    url_origins.add(f"{parsed.scheme.lower()}://{parsed.netloc.lower()}")
                    evidence = _source_evidence(
                        relative, number, line, "network_url"
                    )
                    if (
                        len(hotspots["network"]) < MAX_EVIDENCE_PER_CATEGORY
                        and evidence not in hotspots["network"]
                    ):
                        hotspots["network"].append(evidence)
        for library in LOAD_LIBRARY_PATTERN.findall(text):
            class_by_library.setdefault(library, set()).add(class_name)
        for method in NATIVE_METHOD_PATTERN.findall(text):
            native_methods.append({"class_name": class_name, "method_name": method})

    native_by_short_name: dict[str, str] = {}
    with zipfile.ZipFile(apk_path) as archive:
        for native in package_profile.get("native_libraries", []):
            native_path = native["path"]
            native_node = add_node(
                "native_library",
                native_path,
                abi=native["abi"],
                sha256=native["sha256"],
                page_16k=native["elf"].get("page_16k_load_alignment"),
                zip_16k=native["zip_16k_alignment"],
            )
            add_edge(package_node, native_node, "contains")
            short_name = pathlib.PurePosixPath(native_path).name
            if short_name.startswith("lib") and short_name.endswith(".so"):
                native_by_short_name[short_name[3:-3]] = native_node
            data = archive.read(native_path)
            symbols = sorted(
                {
                    value.decode("ascii", errors="ignore")
                    for value in re.findall(rb"(?:Java_[A-Za-z0-9_]{3,200}|JNI_OnLoad)", data)
                }
            )
            for symbol in symbols[:200]:
                symbol_node = add_node("jni_symbol", f"{native_path}:{symbol}", symbol=symbol)
                add_edge(native_node, symbol_node, "exports")
            if len(symbols) > 200:
                warnings.append(f"JNI_SYMBOL_LIMIT_REACHED:{native_path}")

    unresolved_libraries = []
    for library, classes in sorted(class_by_library.items()):
        native_node = native_by_short_name.get(library)
        if native_node is None:
            unresolved_libraries.append(library)
            native_node = add_node("native_library_reference", f"lib{library}.so")
        for class_name in sorted(classes):
            add_edge(_node_id("class", class_name), native_node, "loads_native")
    for method in native_methods:
        method_node = add_node(
            "native_method",
            f"{method['class_name']}.{method['method_name']}",
            **method,
        )
        add_edge(_node_id("class", method["class_name"]), method_node, "declares")

    hotspot_summary = {
        name: {
            "count": len(evidence),
            "confidence": "HEURISTIC",
            "evidence": evidence,
        }
        for name, evidence in hotspots.items()
    }
    return {
        "schema_version": 1,
        "analysis_kind": "android_architecture_and_hotspots",
        "target_sha256": package_profile["sha256"],
        "graph": {
            "nodes": sorted(nodes, key=lambda item: item["id"]),
            "edges": sorted(
                edges,
                key=lambda item: (item["source"], item["target"], item["relation"]),
            ),
        },
        "components": components,
        "hotspots": hotspot_summary,
        "network_origins": sorted(url_origins),
        "native_links": {
            "load_libraries": {
                name: sorted(classes) for name, classes in sorted(class_by_library.items())
            },
            "native_methods": native_methods,
            "unresolved_libraries": unresolved_libraries,
        },
        "verification": {
            "source_files_scanned": scanned_files,
            "source_bytes_scanned": scanned_bytes,
            "graph_nodes": len(nodes),
            "graph_edges": len(edges),
        },
        "warnings": warnings,
        "limitations": [
            "Hotspot categories are deterministic heuristics and require analyst review.",
            "No target code is executed; reflection and runtime-loaded code may be absent.",
            "JNI symbol absence does not prove no native bridge because symbols can be hidden or dynamically registered.",
            "Source evidence stores path, line, matched rule and line hash, not full source lines or credentials.",
        ],
    }
