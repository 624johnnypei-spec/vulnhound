"""VulnHound's Neo4j attack graph; importing performs no database calls.

All add_* methods return stable string keys accepted by link(). Writes use
MERGE and a unique AttackNode.key constraint protects concurrent agent writes.
Labels/types select fixed Cypher fragments; caller values are parameters.
No APOC or LLM is required. JSON exports are ordinary Python dicts/lists.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import os
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from dotenv import load_dotenv
from neo4j import Driver, GraphDatabase
from neo4j.graph import Node

__all__ = ["GraphStore", "build_seed_graph"]

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
_NODE_MERGES = {
    "Target": "MERGE (n:AttackNode:Target {key: $key})",
    "Endpoint": "MERGE (n:AttackNode:Endpoint {key: $key})",
    "Service": "MERGE (n:AttackNode:Service {key: $key})",
    "Form": "MERGE (n:AttackNode:Form {key: $key})",
    "Vulnerability": "MERGE (n:AttackNode:Vulnerability {key: $key})",
    "Finding": "MERGE (n:AttackNode:Finding {key: $key})",
    "Credential": "MERGE (n:AttackNode:Credential {key: $key})",
    "Asset": "MERGE (n:AttackNode:Asset {key: $key})",
}
_REL_MERGES = {
    "EXPOSES": "MERGE (a)-[r:EXPOSES]->(b)",
    "RUNS": "MERGE (a)-[r:RUNS]->(b)",
    "HAS_FORM": "MERGE (a)-[r:HAS_FORM]->(b)",
    "VULNERABLE_TO": "MERGE (a)-[r:VULNERABLE_TO]->(b)",
    "ENABLES": "MERGE (a)-[r:ENABLES]->(b)",
    "LEADS_TO": "MERGE (a)-[r:LEADS_TO]->(b)",
    "NEXT": "MERGE (a)-[r:NEXT]->(b)",
}
_SEVERITY_COLORS = {
    "critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
    "low": "#3b82f6", "info": "#94a3b8", "unknown": "#64748b",
}
_LABEL_COLORS = {
    "Target": "#22d3ee", "Endpoint": "#38bdf8", "Service": "#818cf8",
    "Form": "#c084fc", "Vulnerability": "#fb923c", "Finding": "#f87171",
    "Credential": "#facc15", "Asset": "#34d399",
}
_CONSTRAINT = """
    CREATE CONSTRAINT vulnhound_attack_node_key IF NOT EXISTS
    FOR (n:AttackNode) REQUIRE n.key IS UNIQUE
"""
_ATTACK_PATHS = """
    MATCH path=(t:Target)-[:EXPOSES|HAS_FORM|VULNERABLE_TO|ENABLES|LEADS_TO*1..8]->(a:Asset {type: $asset_type})
    RETURN path ORDER BY length(path) DESC
"""


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(field + " must be a non-empty string")
    return value.strip()


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {str(k): _json_value(v) for k, v in value.items()}
    if hasattr(value, "srid"):
        return {"srid": value.srid, "coordinates": [_json_value(v) for v in value]}
    if isinstance(value, (list, tuple)):
        return [_json_value(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    for method in ("iso_format", "isoformat"):
        if callable(getattr(value, method, None)):
            return getattr(value, method)()
    return str(value)


def _json(value: Any) -> str:
    return json.dumps(_json_value(value), sort_keys=True, ensure_ascii=False, allow_nan=False)


def _key(kind: str, *parts: Any) -> str:
    return kind.lower() + ":" + hashlib.sha256(_json(parts).encode()).hexdigest()


def _severity(value: Any) -> str:
    name = str(value or "unknown").strip().lower()
    name = {"med": "medium", "informational": "info", "information": "info"}.get(name, name)
    if name not in _SEVERITY_COLORS:
        raise ValueError("Unsupported severity: " + name)
    return name


def _props(props: Mapping[str, Any] | None) -> dict[str, Any]:
    if props is not None and not isinstance(props, Mapping):
        raise TypeError("props must be a mapping")
    return dict(props or {})


def _properties(props: Mapping[str, Any] | None, key: str) -> dict[str, Any]:
    result = _props(props)
    if any(not isinstance(name, str) for name in result):
        raise TypeError("property names must be strings")
    if "key" in result and result["key"] != key:
        raise ValueError("props cannot replace the stable key")
    if "severity" in result:
        result["severity"] = _severity(result["severity"])
    # Nested evidence and heterogeneous arrays are not Neo4j property values.
    for name, value in result.items():
        if isinstance(value, Mapping):
            result[name] = _json(value)
        elif isinstance(value, (list, tuple)):
            nested = any(v is None or isinstance(v, (Mapping, list, tuple)) for v in value)
            if nested or len({type(v) for v in value}) > 1:
                result[name] = _json(value)
    result["key"] = key
    return result


def _url(value: str) -> str:
    parsed = urlsplit(_text(value, "url"))
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target and endpoint URLs must be absolute HTTP(S) URLs")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs must not contain credentials")
    port = parsed.port  # Also validates malformed port values.
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    scheme = parsed.scheme.lower()
    if port is not None and (scheme, port) not in (("http", 80), ("https", 443)):
        host += ":" + str(port)
    return urlunsplit((scheme, host, parsed.path or "/", parsed.query, parsed.fragment))


def _label(node: Node) -> str:
    return next((label for label in _NODE_MERGES if label in node.labels), "Unknown")


def _name(node: Node) -> str:
    return str(node.get("name") or node.get("description") or node.get("path")
               or node.get("selector") or node.get("url") or node.get("type")
               or node.get("key") or node.element_id)


class GraphStore:
    """Synchronous, lazily connected store; usable as a context manager.

    add_endpoint creates its Target if needed. add_form/add_vulnerability
    require an existing parent key (or an unambiguous stored endpoint URL/path).
    add_finding creates a standalone node; link it to its Vulnerability.
    """

    def __init__(self, uri: str | None = None, username: str | None = None,
                 password: str | None = None, *, database: str | None = None) -> None:
        load_dotenv(_ENV_FILE, override=False)
        self.uri = uri if uri is not None else os.getenv("NEO4J_URI")
        self.username = username if username is not None else os.getenv("NEO4J_USERNAME")
        self.password = password if password is not None else os.getenv("NEO4J_PASSWORD")
        self.database = database if database is not None else os.getenv("NEO4J_DATABASE")
        self.driver: Driver | None = None
        self._lock = RLock()
        self._schema_ready = False

    def connect(self) -> GraphStore:
        """Create and verify the driver; repeated calls reuse the connection."""
        with self._lock:
            if self.driver is not None:
                return self
            missing = [name for name, value in (
                ("NEO4J_URI", self.uri), ("NEO4J_USERNAME", self.username),
                ("NEO4J_PASSWORD", self.password),
            ) if not value]
            if missing:
                raise ValueError("Missing Neo4j configuration: " + ", ".join(missing))
            driver = GraphDatabase.driver(
                self.uri, auth=(self.username, self.password),
                connection_timeout=10, connection_acquisition_timeout=15,
            )
            try:
                driver.verify_connectivity()
            except Exception:
                driver.close()
                raise
            self.driver = driver
        return self

    def verify_connectivity(self) -> bool:
        """Return True on success; propagate configuration/driver errors."""
        if self.driver is None:
            self.connect()
        else:
            self.driver.verify_connectivity()
        return True

    def close(self) -> None:
        with self._lock:
            driver, self.driver = self.driver, None
            self._schema_ready = False
            if driver is not None:
                driver.close()

    def __enter__(self) -> GraphStore:
        return self.connect()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _session(self) -> Any:
        self.connect()
        assert self.driver is not None
        return self.driver.session(database=self.database)

    def _write(self, operation: Any) -> Any:
        # Schema needs a separate transaction. Reads/connectivity never write it.
        with self._lock:
            if not self._schema_ready:
                with self._session() as session:
                    session.run(_CONSTRAINT).consume()
                self._schema_ready = True
        with self._session() as session:
            return session.execute_write(operation)

    @staticmethod
    def _upsert(tx: Any, label: str, key: str, props: Mapping[str, Any]) -> str:
        query = _NODE_MERGES[label] + "\nSET n += $props RETURN n.key AS key"
        return tx.run(query, key=key, props=_properties(props, key)).single(strict=True)["key"]

    @staticmethod
    def _link(tx: Any, from_key: str, rel: str, to_key: str,
              props: Mapping[str, Any] | None = None) -> str:
        key = _key("relationship", from_key, rel, to_key)
        query = (
            "MATCH (a:AttackNode {key: $from_key}), (b:AttackNode {key: $to_key})\n"
            + _REL_MERGES[rel] + "\nSET r += $props RETURN r.key AS key"
        )
        record = tx.run(query, from_key=from_key, to_key=to_key,
                        props=_properties(props, key)).single()
        if record is None:
            raise KeyError("Both link endpoints must exist: " + repr((from_key, to_key)))
        return record["key"]

    @staticmethod
    def _resolve(tx: Any, reference: str, labels: list[str]) -> Node:
        records = list(tx.run("""
            MATCH (n:AttackNode)
            WHERE (n.key = $reference OR n.url = $reference OR n.path = $reference)
              AND any(label IN labels(n) WHERE label IN $labels)
            RETURN n ORDER BY CASE WHEN n.key = $reference THEN 0 ELSE 1 END
            LIMIT 2
        """, reference=reference, labels=labels))
        if not records:
            raise KeyError("No matching " + "/".join(labels) + ": " + reference)
        if len(records) > 1 and records[0]["n"]["key"] != reference:
            raise ValueError("Ambiguous endpoint reference; pass the returned node key")
        return records[0]["n"]

    def wipe(self) -> None:
        """Explicitly delete ALL graph data in the selected DB; retain schema."""
        with self._session() as session:
            session.execute_write(lambda tx: tx.run("MATCH (n) DETACH DELETE n").consume())

    def upsert_entity(self, label: str, key: str, props: Mapping[str, Any] | None = None) -> str:
        """Generic node MERGE, including Service, Credential and Asset.

        Asset properties must include type, e.g. database or admin.
        The supplied key must be globally unique. Returns that key.
        """
        if label not in _NODE_MERGES:
            raise ValueError("Unsupported node label: " + str(label))
        key = _text(key, "key")
        properties = _properties(props, key)
        if label == "Asset":
            properties["type"] = _text(properties.get("type"), "Asset.type").lower()
        return self._write(lambda tx: self._upsert(tx, label, key, properties))

    def add_target(self, url: str) -> str:
        url = _url(url)
        return self.upsert_entity("Target", _key("target", url), {"url": url, "name": url})

    def add_endpoint(self, target_url: str, path: str,
                     props: Mapping[str, Any] | None = None) -> str:
        """Attach via EXPOSES. Identity includes target, endpoint URL and method.

        target_url also accepts a key returned by add_target(). An absolute
        endpoint URL must share the target's origin. This only stores metadata.
        """
        target_url, path = _text(target_url, "target_url"), _text(path, "path")
        properties = _props(props)
        method = _text(properties.get("method", "GET"), "method").upper()
        target_is_key = target_url.startswith("target:")
        if not target_is_key:
            target_url = _url(target_url)

        def write(tx: Any) -> str:
            if target_is_key:
                target = self._resolve(tx, target_url, ["Target"])
                target_key, base_url = target["key"], target.get("url")
                if not base_url:
                    raise ValueError("Target has no URL; use build_seed_graph for synthetic data")
            else:
                base_url, target_key = target_url, _key("target", target_url)
            endpoint_url = _url(urljoin(base_url.rstrip("/") + "/", path))
            if urlsplit(endpoint_url)[:2] != urlsplit(base_url)[:2]:
                raise ValueError("Endpoint origin must match its target")
            parsed = urlsplit(endpoint_url)
            endpoint_path = urlunsplit(("", "", parsed.path, parsed.query, parsed.fragment))
            if not target_is_key:
                self._upsert(tx, "Target", target_key, {"url": base_url, "name": base_url})
            key = _key("endpoint", target_key, endpoint_url, method)
            self._upsert(tx, "Endpoint", key, {
                **properties, "url": endpoint_url, "path": endpoint_path,
                "method": method, "target_key": target_key,
                "name": properties.get("name") or method + " " + endpoint_path,
            })
            self._link(tx, target_key, "EXPOSES", key)
            return key

        return self._write(write)

    def add_form(self, endpoint: str, selector: str,
                 props: Mapping[str, Any] | None = None) -> str:
        endpoint, selector = _text(endpoint, "endpoint"), _text(selector, "selector")
        properties = _props(props)

        def write(tx: Any) -> str:
            parent = self._resolve(tx, endpoint, ["Endpoint"])["key"]
            key = _key("form", parent, selector)
            self._upsert(tx, "Form", key, {
                **properties, "selector": selector, "endpoint_key": parent,
                "name": properties.get("name") or selector,
            })
            self._link(tx, parent, "HAS_FORM", key)
            return key

        return self._write(write)

    def add_vulnerability(self, endpoint_or_form: str, vuln_type: str,
                          props: Mapping[str, Any] | None = None) -> str:
        reference = _text(endpoint_or_form, "endpoint_or_form")
        vuln_type, properties = _text(vuln_type, "vuln_type"), _props(props)

        def write(tx: Any) -> str:
            parent = self._resolve(tx, reference, ["Endpoint", "Form"])["key"]
            key = _key("vulnerability", parent, vuln_type.casefold())
            self._upsert(tx, "Vulnerability", key, {
                **properties, "type": vuln_type, "parent_key": parent,
                "name": properties.get("name") or vuln_type,
            })
            self._link(tx, parent, "VULNERABLE_TO", key)
            return key

        return self._write(write)

    def add_finding(self, props: Mapping[str, Any]) -> str:
        """Store type/severity/evidence/description; accept 'med' as 'medium'.

        Identity is type + evidence + endpoint/target context. Provide context
        to distinguish identical findings on different targets, or set props.key
        explicitly. Severity/description updates do not create duplicates.
        """
        if not isinstance(props, Mapping):
            raise TypeError("props must be a mapping")
        properties = dict(props)
        finding_type = _text(properties.get("type"), "Finding.type")
        description = _text(properties.get("description"), "Finding.description")
        if "severity" not in properties or "evidence" not in properties:
            raise ValueError("Finding requires severity and evidence")
        severity = _severity(properties["severity"])
        context = {field: properties[field] for field in (
            "endpoint_key", "endpoint", "url", "target_url", "target_key", "parent_key",
        ) if field in properties}
        key = _text(properties["key"], "key") if "key" in properties else _key(
            "finding", finding_type.casefold(), properties["evidence"], context,
        )
        return self.upsert_entity("Finding", key, {
            **properties, "type": finding_type, "severity": severity,
            "description": description, "name": properties.get("name") or description[:100],
        })

    def link(self, from_key: str, REL: str, to_key: str,
             props: Mapping[str, Any] | None = None) -> str:
        """MERGE a directed schema edge. Raise KeyError for missing endpoints."""
        from_key, to_key = _text(from_key, "from_key"), _text(to_key, "to_key")
        if REL not in _REL_MERGES:
            raise ValueError("Unsupported relationship type: " + str(REL))
        properties = _properties(props, _key("relationship", from_key, REL, to_key))
        return self._write(lambda tx: self._link(tx, from_key, REL, to_key, properties))

    def attack_paths(self, asset_type: str = "database") -> list[list[dict[str, str]]]:
        """Directed Target-to-Asset paths, longest first, with at most 8 edges.

        Each path is an ordered list of {node_label, name} hops.
        RUNS and NEXT are excluded from the specified exploit-chain query.
        """
        asset_type = _text(asset_type, "asset_type").lower()
        with self._session() as session:
            return session.execute_read(lambda tx: [
                [{"node_label": _label(node), "name": _name(node)} for node in row["path"].nodes]
                for row in tx.run(_ATTACK_PATHS, asset_type=asset_type)
            ])

    def to_cytoscape(self) -> dict[str, list[dict[str, Any]]]:
        """Flat JSON: nodes have id/label/type; edges have source/target/label.

        Includes isolated nodes. For Cytoscape.js, wrap each object in {data: ...}.
        Original properties are nested too, preserving Asset.type and evidence.
        """
        def read(tx: Any) -> dict[str, list[dict[str, Any]]]:
            nodes = []
            for row in tx.run("MATCH (n:AttackNode) RETURN n ORDER BY n.key"):
                node, props = row["n"], _json_value(dict(row["n"]))
                label = _label(node)
                nodes.append({
                    **props, "id": node["key"], "label": _name(node), "type": label,
                    "color": _SEVERITY_COLORS.get(props.get("severity"), _LABEL_COLORS.get(label)),
                    "properties": props,
                })
            edges = []
            for row in tx.run("""
                MATCH (a:AttackNode)-[r]->(b:AttackNode)
                RETURN r, a.key AS source, b.key AS target ORDER BY r.key
            """):
                rel, props = row["r"], _json_value(dict(row["r"]))
                edges.append({
                    **props, "id": rel.get("key") or "edge:" + rel.element_id,
                    "source": row["source"], "target": row["target"],
                    "label": rel.type, "type": rel.type, "properties": props,
                })
            return {"nodes": nodes, "edges": edges}

        with self._session() as session:
            return session.execute_read(read)

    def summary(self) -> dict[str, Any]:
        """Return by_node_type, by_severity, total_nodes and total_edges.

        Severity counts include Finding nodes only, avoiding duplicate counts
        from linked Vulnerabilities. All known buckets appear, including zeros.
        """
        def read(tx: Any) -> dict[str, Any]:
            by_type, by_severity = dict.fromkeys(_NODE_MERGES, 0), dict.fromkeys(_SEVERITY_COLORS, 0)
            total = 0
            for row in tx.run("""
                MATCH (n:AttackNode)
                RETURN labels(n) AS labels, n.severity AS severity, count(*) AS count
            """):
                count = row["count"]
                total += count
                for label in row["labels"]:
                    if label in by_type:
                        by_type[label] += count
                if "Finding" in row["labels"]:
                    severity = row["severity"] or "unknown"
                    by_severity[severity if severity in by_severity else "unknown"] += count
            edges = tx.run("""
                MATCH (:AttackNode)-[r]->(:AttackNode) RETURN count(r) AS count
            """).single(strict=True)["count"]
            return {"by_severity": by_severity, "by_node_type": by_type,
                    "total_nodes": total, "total_edges": edges}

        with self._session() as session:
            return session.execute_read(read)

    def build_seed_graph(self) -> dict[str, str]:
        """Atomically MERGE a six-node synthetic Juice Shop attack chain.

        No attack is run. Every seed node has is_seed=True. No live URL is
        invented: optional VULNHOUND_TARGET_URL/TARGET_URL provides display
        context. Seed identities are separate from live data; nothing is wiped.
        Returns keys named target, endpoint, form, vulnerability, finding, asset.
        """
        configured_url = os.getenv("VULNHOUND_TARGET_URL") or os.getenv("TARGET_URL")
        target_url = _url(configured_url) if configured_url else None
        keys = {name: _key(name, "vulnhound-juice-shop-seed", target_url) for name in (
            "target", "endpoint", "form", "vulnerability", "finding", "asset",
        )}
        specifications = [
            ("target", "Target", {"name": "OWASP Juice Shop (demo)", "url": target_url}),
            ("endpoint", "Endpoint", {"name": "Login endpoint", "path": "/rest/user/login", "method": "POST"}),
            ("form", "Form", {"name": "Login email form", "selector": "#email"}),
            ("vulnerability", "Vulnerability", {"name": "SQL injection in login email", "type": "SQLi", "severity": "critical"}),
            ("finding", "Finding", {
                "name": "Login SQL injection enables database access", "type": "SQLi", "severity": "critical",
                "description": "Synthetic demo: injectable login input provides a route to the application database.",
                "evidence": "Seeded demonstration only; no live test or database access was performed.",
            }),
            ("asset", "Asset", {"name": "Juice Shop database", "type": "database"}),
        ]

        def write(tx: Any) -> dict[str, str]:
            for name, label, props in specifications:
                self._upsert(tx, label, keys[name], {**props, "is_seed": True})
            for source, rel, target in (
                ("target", "EXPOSES", "endpoint"), ("endpoint", "HAS_FORM", "form"),
                ("form", "VULNERABLE_TO", "vulnerability"), ("vulnerability", "ENABLES", "finding"),
                ("finding", "LEADS_TO", "asset"),
            ):
                self._link(tx, keys[source], rel, keys[target], {"is_seed": True})
            return keys

        return self._write(write)


def build_seed_graph() -> dict[str, str]:
    """Seed an environment-configured store, closing it when finished."""
    with GraphStore() as graph:
        return graph.build_seed_graph()


if __name__ == "__main__":
    load_dotenv(_ENV_FILE, override=False)
    required = ("NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD")
    if not all(os.getenv(name) for name in required) or "xxxxxxx" in os.getenv("NEO4J_URI", ""):
        print("SKIP: configure NEO4J_URI, NEO4J_USERNAME and NEO4J_PASSWORD for the seed demo.")
    else:
        with GraphStore() as graph:
            graph.build_seed_graph()
            print(json.dumps({"attack_paths": graph.attack_paths(), "summary": graph.summary()}, indent=2))
