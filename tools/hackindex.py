#!/usr/bin/env python3
# tool: hackindex.py
# kind: verdict
# area: launcher
# purpose: validate staticR hack index entries, compile them into index.json, refresh the game list
# when: before a PR merges (validate), when publishing (build), after games.toml changes (sync-games)
# inputs: entries/<game-id>/<slug>.json, registry/games.tsv, policy/refused-hosts.txt, revoked.json
# outputs: counts on stdout (--json for machine output); build writes dist/index.json; exit 0 ok, 1 failed check, 2 usage, 77 skipped (no network)
# selftest: --selftest (synthetic fixtures: a good entry; refused host, ROM URL, unknown game, bad hash, duplicate, revoked, path mismatch, unmeasured-with-evidence; payload magic; build determinism)
# status: unverified
# supersedes: -
# distinct-from: staticR bin/ tools because this repo is standalone and must run without a staticR checkout
# mismatch-exit: 1
"""staticR hack index tool. Standard library only (Python 3.11+), MIT.

    hackindex.py validate [--root DIR] [--allow-empty] [--json]
    hackindex.py build --generated YYYY-MM-DD [--expires-days N] [--out FILE] [--allow-empty]
    hackindex.py check-remote ENTRY.json...      # downloads each patch; checks size, sha256, payload
    hackindex.py sync-games PATH/TO/staticR/configs/games.toml
    hackindex.py --selftest

The format is described in docs/entry-format.md. This tool is the only definition of
"valid": the launcher's reader (staticR core) must accept everything it accepts.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import re
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = 1
SOURCE_ID = "staticr-index"
ROOT = Path(__file__).resolve().parent.parent

SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
GAME_ID = re.compile(r"[a-z0-9][a-z0-9.\-]{0,63}")
HEX = {n: re.compile(rf"[0-9a-f]{{{n}}}") for n in (8, 32, 40, 64)}
BUILD = re.compile(r"[0-9a-f]{8,40}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")

FORMATS = {"ips", "ups", "bps", "xdelta", "ppf"}
ARCHIVES = {"none", "zip"}
BASE_FORMS = {"retail", "decompressed"}
BYTE_ORDERS = {"z64", "v64", "n64"}
COMPAT = {"unmeasured", "A", "B", "C"}
# A ROM image never goes in the index, whatever the source says (policy §5c).
ROM_EXTS = (".z64", ".n64", ".v64", ".rom", ".u64", ".ndd", ".iso", ".cue", ".chd")
N64_MAGICS = (b"\x80\x37\x12\x40", b"\x37\x80\x40\x12", b"\x40\x12\x37\x80")
PATCH_MAGIC = {
    "ips": (b"PATCH",),
    "ups": (b"UPS1",),
    "bps": (b"BPS1",),
    "xdelta": (b"\xd6\xc3\xc4",),
    "ppf": (b"PPF",),
}
MAX_PATCH = 64 * 1024 * 1024

TOP_REQUIRED = {"schema", "title", "authors", "version", "game", "base", "patch", "page",
                "license_note", "compat"}
TOP_OPTIONAL = {"released", "tags", "thumbs", "redistribute", "notes"}
BASE_REQUIRED = {"name", "sha1", "form", "byte_order"}
BASE_OPTIONAL = {"crc32", "md5", "size"}
PATCH_REQUIRED = {"format", "url", "sha256", "size"}
PATCH_OPTIONAL = {"archive", "member"}


class UsageError(Exception):
    pass


@dataclass
class Report:
    entries: int = 0
    errors: list[str] = field(default_factory=list)
    by_game: dict[str, int] = field(default_factory=dict)

    def err(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")


# ---------------------------------------------------------------- repo inputs

def load_games(root: Path) -> dict[str, dict[str, str]]:
    path = root / "registry" / "games.tsv"
    if not path.is_file():
        raise UsageError(f"missing {path}: run sync-games first")
    rows = [ln.split("\t") for ln in path.read_text("utf-8").splitlines()
            if ln and not ln.startswith("#")]
    if not rows or rows[0] != ["id", "console", "status"]:
        raise UsageError(f"{path}: header must be id\\tconsole\\tstatus")
    games = {r[0]: {"console": r[1], "status": r[2]} for r in rows[1:] if len(r) == 3}
    if len(games) != len(rows) - 1:
        raise UsageError(f"{path}: malformed or duplicate rows")
    if not games:
        raise UsageError(f"{path}: no games")
    return games


def load_refused(root: Path) -> set[str]:
    path = root / "policy" / "refused-hosts.txt"
    if not path.is_file():
        raise UsageError(f"missing {path}")
    hosts = {ln.strip().lower() for ln in path.read_text("utf-8").splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")}
    if not hosts:
        raise UsageError(f"{path}: empty (the policy list must not be lost silently)")
    return hosts


def load_revoked(root: Path, rep: Report) -> list[dict]:
    path = root / "revoked.json"
    if not path.is_file():
        raise UsageError(f"missing {path}")
    try:
        data = json.loads(path.read_text("utf-8"))
    except json.JSONDecodeError as e:
        rep.err("revoked.json", f"not JSON: {e}")
        return []
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(
            data.get("revoked"), list):
        rep.err("revoked.json", "must be {\"schema\": 1, \"revoked\": [...]}")
        return []
    out = []
    for i, r in enumerate(data["revoked"]):
        w = f"revoked.json[{i}]"
        if not isinstance(r, dict) or set(r) != {"id", "patch_sha256", "date", "reason"}:
            rep.err(w, "needs exactly id, patch_sha256, date, reason")
            continue
        if not (isinstance(r["patch_sha256"], str) and HEX[64].fullmatch(r["patch_sha256"])):
            rep.err(w, "patch_sha256 must be 64 lowercase hex")
        if not (isinstance(r["date"], str) and DATE.fullmatch(r["date"])):
            rep.err(w, "date must be YYYY-MM-DD")
        out.append(r)
    return out


# ---------------------------------------------------------------- entry checks

def host_refused(host: str, refused: set[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == r or host.endswith("." + r) for r in refused)


def check_url(where: str, url: object, refused: set[str], rep: Report, rom_ok: bool) -> None:
    if not isinstance(url, str) or not url:
        rep.err(where, "must be a URL string")
        return
    if any(c.isspace() or ord(c) < 0x20 for c in url) or "\\" in url:
        rep.err(where, "has whitespace, control characters or a backslash")
        return
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        rep.err(where, "must be an https:// URL with a host")
        return
    if not re.fullmatch(r"[a-z0-9.-]+", parts.hostname) or "." not in parts.hostname:
        rep.err(where, "host must be a plain ASCII domain name (like the launcher's rule)")
        return
    if "@" in parts.netloc:
        rep.err(where, "must not carry user info (@)")
    if host_refused(parts.hostname, refused):
        rep.err(where, f"host {parts.hostname} is refused by policy (hands out ROMs)")
    if not rom_ok and urllib.parse.unquote(parts.path).lower().endswith(ROM_EXTS):
        rep.err(where, "points at a ROM image, not a patch")


def keys_ok(where: str, obj: object, required: set[str], optional: set[str],
            rep: Report) -> bool:
    if not isinstance(obj, dict):
        rep.err(where, "must be an object")
        return False
    missing = required - obj.keys()
    unknown = obj.keys() - required - optional
    if missing:
        rep.err(where, f"missing {sorted(missing)}")
    if unknown:
        rep.err(where, f"unknown fields {sorted(unknown)}")
    return not missing


def _one_of(v: object, allowed: set[str]) -> bool:
    return isinstance(v, str) and v in allowed


def nonempty_str(v: object) -> bool:
    return isinstance(v, str) and v.strip() != "" and v == v.strip()


def check_entry(path: Path, data: object, games: dict, refused: set[str],
                rep: Report) -> str | None:
    """Check one entry. Returns its id ('<game>/<slug>') or None if it can't be named."""
    rel = path.as_posix()
    game_dir, slug = path.parent.name, path.stem
    if not GAME_ID.fullmatch(game_dir) or not SLUG.fullmatch(slug):
        rep.err(rel, "path must be entries/<game-id>/<slug>.json, slug [a-z0-9-]")
        return None
    if not keys_ok(rel, data, TOP_REQUIRED, TOP_OPTIONAL, rep):
        return None
    assert isinstance(data, dict)
    if data["schema"] != SCHEMA:
        rep.err(rel, f"schema must be {SCHEMA}")
    for k in ("title", "version", "license_note"):
        if not nonempty_str(data[k]):
            rep.err(rel, f"{k} must be a non-empty trimmed string")
    if not (isinstance(data["authors"], list) and data["authors"]
            and all(nonempty_str(a) for a in data["authors"])):
        rep.err(rel, "authors must be a non-empty list of names")
    if not isinstance(data["game"], str):
        rep.err(rel, "game must be a string")
        return None
    if data["game"] != game_dir:
        rep.err(rel, f"game {data['game']!r} must match its folder {game_dir!r}")
    if data["game"] not in games:
        rep.err(rel, f"game {data['game']!r} is not in registry/games.tsv")
    if "released" in data and not (isinstance(data["released"], str)
                                   and DATE.fullmatch(data["released"])):
        rep.err(rel, "released must be YYYY-MM-DD")
    for k in ("tags", "thumbs"):
        if k in data and not (isinstance(data[k], list)
                              and all(nonempty_str(t) for t in data[k])):
            rep.err(rel, f"{k} must be a list of strings")
    for i, t in enumerate(data.get("thumbs", []) if isinstance(data.get("thumbs"), list) else []):
        check_url(f"{rel} thumbs[{i}]", t, refused, rep, rom_ok=False)
    if "redistribute" in data and not isinstance(data["redistribute"], bool):
        rep.err(rel, "redistribute must be true or false")
    check_url(f"{rel} page", data["page"], refused, rep, rom_ok=True)

    base = data["base"]
    if keys_ok(f"{rel} base", base, BASE_REQUIRED, BASE_OPTIONAL, rep):
        if not nonempty_str(base["name"]):
            rep.err(rel, "base.name must be a non-empty string")
        if not (isinstance(base["sha1"], str) and HEX[40].fullmatch(base["sha1"])):
            rep.err(rel, "base.sha1 must be 40 lowercase hex")
        if not _one_of(base["form"], BASE_FORMS):
            rep.err(rel, f"base.form must be one of {sorted(BASE_FORMS)}")
        if not _one_of(base["byte_order"], BYTE_ORDERS):
            rep.err(rel, f"base.byte_order must be one of {sorted(BYTE_ORDERS)}")
        for k, n in (("crc32", 8), ("md5", 32)):
            if k in base and not (isinstance(base[k], str) and HEX[n].fullmatch(base[k])):
                rep.err(rel, f"base.{k} must be {n} lowercase hex")
        if "size" in base and not (type(base["size"]) is int and base["size"] > 0):
            rep.err(rel, "base.size must be a positive integer")

    patch = data["patch"]
    if keys_ok(f"{rel} patch", patch, PATCH_REQUIRED, PATCH_OPTIONAL, rep):
        if not _one_of(patch["format"], FORMATS):
            rep.err(rel, f"patch.format must be one of {sorted(FORMATS)}")
        check_url(f"{rel} patch.url", patch["url"], refused, rep, rom_ok=False)
        if not (isinstance(patch["sha256"], str) and HEX[64].fullmatch(patch["sha256"])):
            rep.err(rel, "patch.sha256 must be 64 lowercase hex")
        if not (type(patch["size"]) is int and 0 < patch["size"] <= MAX_PATCH):
            rep.err(rel, f"patch.size must be an integer in 1..{MAX_PATCH}")
        archive = patch.get("archive", "none")
        if not _one_of(archive, ARCHIVES):
            rep.err(rel, f"patch.archive must be one of {sorted(ARCHIVES)}")
        elif archive == "zip":
            m = patch.get("member")
            if not nonempty_str(m):
                rep.err(rel, "patch.member is required when archive is zip")
            elif m.lower().endswith(ROM_EXTS):
                rep.err(rel, "patch.member is a ROM image, not a patch")
        elif "member" in patch:
            rep.err(rel, "patch.member only applies when archive is zip")

    compat = data["compat"]
    if isinstance(compat, dict) and _one_of(compat.get("class"), COMPAT):
        if compat["class"] == "unmeasured":
            if set(compat) != {"class"}:
                rep.err(rel, "an unmeasured compat carries only {\"class\": \"unmeasured\"}")
        else:
            mo = compat.get("measured_on")
            if set(compat) != {"class", "measured_on"} or not isinstance(mo, dict) or set(mo) != {
                    "port_build", "evidence"}:
                rep.err(rel, "a measured compat needs measured_on {port_build, evidence}")
            else:
                if not (isinstance(mo["port_build"], str) and BUILD.fullmatch(mo["port_build"])):
                    rep.err(rel, "compat.measured_on.port_build must be a commit hash")
                if not (isinstance(mo["evidence"], str) and HEX[64].fullmatch(mo["evidence"])):
                    rep.err(rel, "compat.measured_on.evidence must be an evidence sha256")
    else:
        rep.err(rel, f"compat.class must be one of {sorted(COMPAT)}")
    return f"{game_dir}/{slug}"


def check_payload(data: bytes, entry: dict) -> list[str]:
    """Check downloaded patch bytes against an entry. Empty list = ok."""
    patch = entry["patch"]
    errs = []
    if len(data) != patch["size"]:
        errs.append(f"size {len(data)} != declared {patch['size']}")
    got = hashlib.sha256(data).hexdigest()
    if got != patch["sha256"]:
        errs.append(f"sha256 {got} != declared {patch['sha256']}")
    body = data
    if patch.get("archive", "none") == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist():
                    if info.filename.lower().endswith(ROM_EXTS):
                        errs.append(f"archive holds a ROM image: {info.filename}")
                    elif z.read(info)[:4] in N64_MAGICS:
                        errs.append(f"archive member is an N64 ROM image: {info.filename}")
                body = z.read(patch["member"])
        except (zipfile.BadZipFile, KeyError) as e:
            return errs + [f"bad zip or missing member: {e}"]
    if body[:4] in N64_MAGICS:
        errs.append("payload is an N64 ROM image, not a patch")
    elif not body.startswith(PATCH_MAGIC[patch["format"]]):
        errs.append(f"payload does not start with the {patch['format']} magic")
    return errs


# ---------------------------------------------------------------- commands

def collect(root: Path) -> tuple[Report, dict[str, dict], list[dict]]:
    rep = Report()
    games = load_games(root)
    refused = load_refused(root)
    revoked = load_revoked(root, rep)
    entries: dict[str, dict] = {}
    seen_sha: dict[str, str] = {}
    edir = root / "entries"
    if not edir.is_dir():
        raise UsageError(f"missing {edir}")
    for path in sorted(edir.rglob("*")):
        if path.is_dir() or path.name == ".gitkeep":
            continue
        rel = path.relative_to(root)
        if path.suffix != ".json" or len(rel.parts) != 3:
            rep.err(rel.as_posix(), "only entries/<game-id>/<slug>.json files belong here")
            continue
        try:
            data = json.loads(path.read_text("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            rep.err(rel.as_posix(), f"not UTF-8 JSON: {e}")
            continue
        eid = check_entry(rel, data, games, refused, rep)
        if eid is None:
            continue
        rep.entries += 1
        rep.by_game[data["game"]] = rep.by_game.get(data["game"], 0) + 1
        entries[eid] = data
        sha = data.get("patch", {}).get("sha256") if isinstance(data.get("patch"), dict) else None
        if isinstance(sha, str):
            if sha in seen_sha:
                rep.err(rel.as_posix(), f"same patch sha256 as {seen_sha[sha]}")
            seen_sha[sha] = eid
    for r in revoked:
        if r.get("id") in entries:
            rep.err("revoked.json", f"{r['id']} is revoked but still in entries/")
        if r.get("patch_sha256") in seen_sha:
            rep.err("revoked.json", f"revoked patch is still listed by {seen_sha[r['patch_sha256']]}")
    return rep, entries, revoked


def emit(rep: Report, as_json: bool, extra: dict | None = None) -> None:
    out = {"entries": rep.entries, "by_game": dict(sorted(rep.by_game.items())),
           "errors": rep.errors, **(extra or {})}
    if as_json:
        print(json.dumps(out, sort_keys=True))
        return
    print(f"entries={rep.entries} errors={len(rep.errors)} "
          + " ".join(f"{g}={n}" for g, n in sorted(rep.by_game.items())))
    for k, v in (extra or {}).items():
        print(f"{k}={v}")
    for e in rep.errors:
        print(f"ERROR {e}")


def cmd_validate(a: argparse.Namespace) -> int:
    rep, _, _ = collect(a.root)
    if rep.entries == 0 and not a.allow_empty:
        rep.err("entries/", "no entries (pass --allow-empty while the index is new)")
    emit(rep, a.json)
    print("PASS" if not rep.errors else "FAIL", file=sys.stderr)
    return 1 if rep.errors else 0


def build_bytes(entries: dict[str, dict], revoked: list[dict], generated: str,
                expires_days: int) -> bytes:
    gen = dt.date.fromisoformat(generated)
    doc = {
        "schema": SCHEMA,
        "source": SOURCE_ID,
        "generated": gen.isoformat(),
        "expires": (gen + dt.timedelta(days=expires_days)).isoformat(),
        "entries": [{"id": eid, **entries[eid]} for eid in sorted(entries)],
        "revoked": sorted(revoked, key=lambda r: (r["id"], r["patch_sha256"])),
    }
    return (json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            + "\n").encode("utf-8")


def cmd_build(a: argparse.Namespace) -> int:
    if not DATE.fullmatch(a.generated):
        raise UsageError("--generated must be YYYY-MM-DD")
    if not 1 <= a.expires_days <= 365:
        raise UsageError("--expires-days must be 1..365")
    rep, entries, revoked = collect(a.root)
    if rep.entries == 0 and not a.allow_empty:
        rep.err("entries/", "no entries (pass --allow-empty while the index is new)")
    if rep.errors:
        emit(rep, a.json)
        print("FAIL: not built", file=sys.stderr)
        return 1
    blob = build_bytes(entries, revoked, a.generated, a.expires_days)
    out = a.out or (a.root / "dist" / "index.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    tmp.write_bytes(blob)
    tmp.replace(out)
    emit(rep, a.json, {"out": str(out), "sha256": hashlib.sha256(blob).hexdigest(),
                       "bytes": len(blob)})
    return 0


def cmd_check_remote(a: argparse.Namespace) -> int:
    rep = Report()
    for p in a.entries:
        data = json.loads(Path(p).read_text("utf-8"))
        url = data["patch"]["url"]
        req = urllib.request.Request(url, headers={"User-Agent": "staticr-hack-index-validator"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read(MAX_PATCH + 1)
        except OSError as e:
            print(f"SKIP {p}: cannot fetch {url}: {e}", file=sys.stderr)
            return 77
        rep.entries += 1
        for e in check_payload(body, data):
            rep.err(p, e)
    emit(rep, a.json)
    return 1 if rep.errors else 0


def cmd_sync_games(a: argparse.Namespace) -> int:
    import tomllib
    src = Path(a.games_toml)
    try:
        doc = tomllib.loads(src.read_text("utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise UsageError(f"cannot read {src}: {e}") from e
    games = doc.get("game")
    if not isinstance(games, dict) or not games:
        raise UsageError(f"{src}: no [game.<id>] tables")
    lines = ["# Generated by: tools/hackindex.py sync-games <staticR>/configs/games.toml",
             "# Do not edit by hand. status=playable means a shipped port; others are wish-list.",
             "id\tconsole\tstatus"]
    for gid in sorted(games):
        g = games[gid]
        if not GAME_ID.fullmatch(gid):
            raise UsageError(f"{src}: game id {gid!r} does not fit the index's id rule")
        lines.append(f"{gid}\t{g.get('console', '')}\t{g.get('status', '')}")
    out = a.root / "registry" / "games.tsv"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", "utf-8")
    print(f"games={len(games)} out={out}")
    return 0


# ---------------------------------------------------------------- selftest

def _fixture_entry(**over: object) -> dict:
    e = {
        "schema": 1, "title": "Fixture Hack", "authors": ["Someone"], "version": "1.0",
        "game": "oot-ntsc-1.2",
        "base": {"name": "fixture base", "sha1": "a" * 40, "form": "retail", "byte_order": "z64"},
        "patch": {"format": "ips", "url": "https://example.org/x.ips", "sha256": "b" * 64,
                  "size": 10},
        "page": "https://example.org/hack", "license_note": "synthetic fixture",
        "compat": {"class": "unmeasured"},
    }
    e.update(over)
    return e


def _tree(d: Path, entries: dict[str, dict], revoked: list | None = None) -> Path:
    (d / "registry").mkdir(parents=True)
    (d / "registry" / "games.tsv").write_text(
        "id\tconsole\tstatus\noot-ntsc-1.2\tn64\tplayable\nsm64-us\tn64\tidentity\n", "utf-8")
    (d / "policy").mkdir()
    (d / "policy" / "refused-hosts.txt").write_text("cdromance.org\n", "utf-8")
    (d / "revoked.json").write_text(json.dumps({"schema": 1, "revoked": revoked or []}), "utf-8")
    (d / "entries").mkdir()
    for rel, data in entries.items():
        p = d / "entries" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data), "utf-8")
    return d


def _validate_tree(entries: dict[str, dict], revoked: list | None = None) -> list[str]:
    with tempfile.TemporaryDirectory() as t:
        rep, _, _ = collect(_tree(Path(t), entries, revoked))
        return rep.errors


def selftest() -> int:
    good = _fixture_entry()
    cases: list[tuple[str, str, object]] = []  # (name, polarity, thunk -> bool passed)

    def case(name: str, polarity: str):
        def deco(fn):
            cases.append((name, polarity, fn))
            return fn
        return deco

    @case("good entry validates", "positive")
    def _() -> bool:
        return _validate_tree({"oot-ntsc-1.2/fixture.json": good}) == []

    @case("wish-list game (not playable) still validates", "positive")
    def _() -> bool:
        return _validate_tree({"sm64-us/fixture.json": _fixture_entry(game="sm64-us")}) == []

    negatives = {
        "refused host": _fixture_entry(page="https://www.cdromance.org/hack"),
        "ROM image URL": _fixture_entry(patch={**good["patch"], "url": "https://e.org/x.z64"}),
        "unknown game": None,
        "bad sha256": _fixture_entry(patch={**good["patch"], "sha256": "XYZ"}),
        "unmeasured with evidence": _fixture_entry(
            compat={"class": "unmeasured", "measured_on": {"port_build": "abcdef12",
                                                           "evidence": "c" * 64}}),
        "measured without evidence": _fixture_entry(compat={"class": "A"}),
        "http URL": _fixture_entry(page="http://example.org/hack"),
        "encoded dot host": _fixture_entry(page="https://cdromance%2Eorg/hack"),
        "unknown field": _fixture_entry(rom_url="https://example.org/x"),
        "zip member is a ROM": _fixture_entry(patch={**good["patch"], "archive": "zip",
                                                     "member": "Hack.z64"}),
    }
    for name, entry in negatives.items():
        if entry is None:
            continue
        cases.append((f"rejects {name}", "negative",
                      lambda e=entry: _validate_tree({"oot-ntsc-1.2/fixture.json": e}) != []))

    @case("rejects unknown game", "negative")
    def _() -> bool:
        e = _fixture_entry(game="zelda-hack-us")
        return _validate_tree({"zelda-hack-us/fixture.json": e}) != []

    @case("rejects game/folder mismatch", "negative")
    def _() -> bool:
        return _validate_tree({"sm64-us/fixture.json": good}) != []

    @case("rejects duplicate patch sha256", "negative")
    def _() -> bool:
        return _validate_tree({"oot-ntsc-1.2/a.json": good, "oot-ntsc-1.2/b.json": good}) != []

    @case("rejects a revoked entry still listed", "negative")
    def _() -> bool:
        rv = [{"id": "oot-ntsc-1.2/fixture", "patch_sha256": "d" * 64, "date": "2026-11-07",
               "reason": "synthetic"}]
        return _validate_tree({"oot-ntsc-1.2/fixture.json": good}, rv) != []

    ips = b"PATCH" + b"\x00\x00\x00\x00\x01\x41" + b"EOF"
    ent_ips = _fixture_entry(patch={**good["patch"], "sha256": hashlib.sha256(ips).hexdigest(),
                                    "size": len(ips)})

    @case("payload: matching IPS accepted", "positive")
    def _() -> bool:
        return check_payload(ips, ent_ips) == []

    @case("payload: one flipped byte rejected (mutation)", "negative")
    def _() -> bool:
        return check_payload(ips[:-1] + b"G", ent_ips) != []

    @case("payload: N64 ROM image rejected", "negative")
    def _() -> bool:
        rom = b"\x80\x37\x12\x40" + bytes(60)
        e = _fixture_entry(patch={**good["patch"], "sha256": hashlib.sha256(rom).hexdigest(),
                                  "size": len(rom)})
        return any("ROM image" in x for x in check_payload(rom, e))

    @case("payload: zip hiding a ROM rejected", "negative")
    def _() -> bool:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("hack.ips", ips)
            z.writestr("patched.bin", b"\x37\x80\x40\x12" + bytes(60))
        blob = buf.getvalue()
        e = _fixture_entry(patch={**good["patch"], "archive": "zip", "member": "hack.ips",
                                  "sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)})
        return any("ROM image" in x for x in check_payload(blob, e))

    @case("payload: declared bps but bytes are ips rejected", "negative")
    def _() -> bool:
        e = {**ent_ips, "patch": {**ent_ips["patch"], "format": "bps"}}
        return check_payload(ips, e) != []

    @case("build is deterministic and sorted", "positive")
    def _() -> bool:
        ents = {"oot-ntsc-1.2/b": good, "oot-ntsc-1.2/a": ent_ips}
        x = build_bytes(ents, [], "2026-11-07", 30)
        y = build_bytes(dict(reversed(list(ents.items()))), [], "2026-11-07", 30)
        doc = json.loads(x)
        return x == y and [e["id"] for e in doc["entries"]] == ["oot-ntsc-1.2/a", "oot-ntsc-1.2/b"] \
            and doc["expires"] == "2026-12-07"

    @case("CLI: validate exits 1 on a bad tree", "negative")
    def _() -> bool:
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            d = _tree(Path(t), {"oot-ntsc-1.2/f.json": _fixture_entry(page="http://x.org/")})
            r = subprocess.run([sys.executable, __file__, "validate", "--root", str(d)],
                               capture_output=True, text=True, check=False)
            return r.returncode == 1

    @case("CLI: validate exits 0 on a good tree", "positive")
    def _() -> bool:
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            d = _tree(Path(t), {"oot-ntsc-1.2/f.json": good})
            r = subprocess.run([sys.executable, __file__, "validate", "--root", str(d)],
                               capture_output=True, text=True, check=False)
            return r.returncode == 0

    pols = {p for _, p, _ in cases}
    if pols != {"positive", "negative"}:
        print("selftest: suite needs both polarities", file=sys.stderr)
        return 1
    failed = 0
    for name, pol, fn in cases:
        ok = fn() and fn()  # every case twice (determinism)
        print(f"{'ok  ' if ok else 'FAIL'} [{pol}] {name}")
        failed += not ok
    print(f"selftest: {len(cases) - failed}/{len(cases)} passed")
    return 1 if failed else 0


# ---------------------------------------------------------------- main

def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(prog="hackindex.py")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "build", "check-remote", "sync-games"):
        p = sub.add_parser(name)
        p.add_argument("--root", type=Path, default=ROOT)
        p.add_argument("--json", action="store_true")
        if name in ("validate", "build"):
            p.add_argument("--allow-empty", action="store_true")
        if name == "build":
            p.add_argument("--generated", required=True)
            p.add_argument("--expires-days", type=int, default=30)
            p.add_argument("--out", type=Path)
        if name == "check-remote":
            p.add_argument("entries", nargs="+")
        if name == "sync-games":
            p.add_argument("games_toml")
    a = ap.parse_args(argv)
    try:
        return {"validate": cmd_validate, "build": cmd_build, "check-remote": cmd_check_remote,
                "sync-games": cmd_sync_games}[a.cmd](a)
    except UsageError as e:
        print(f"usage error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
