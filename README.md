# staticR hack index

The list of ROM hacks the staticR launcher can show on its Mods page. It lives here, apart from the
staticR code, so a takedown or licence complaint about one entry can never reach the port code.

Status: **set up, no entries yet, not published.** The launcher's built-in "staticR hack index"
source has no URL until the first signed `index.json` is published (see `docs/next-task.md`).

## What goes in

- **Patches only** (IPS, UPS, BPS, xdelta, PPF). Never a ROM, a pre-patched ROM or a ROM pack.
  The validator refuses ROM file names and N64 ROM bytes, and `policy/refused-hosts.txt` lists
  sites that hand out ROMs; they can't appear even as a page link.
- **Links, not files.** Each entry points at the author's own download and pins its sha256 and
  size. The index carries no patch bytes unless the entry says the author allows it
  (`redistribute: true`).
- **Every game id comes from staticR's registry** (`registry/games.tsv`, generated from
  `configs/games.toml`). Games with no playable port are allowed; the launcher shows them as a wish
  list without a Play button.
- **Compatibility is measured, never claimed.** A submitter writes `"compat": {"class":
  "unmeasured"}`. A measured class (A data-only, B layout-changing, C code-changing) needs the port
  build and the evidence sha256 that measured it.

## Layout

| Path | What |
|---|---|
| `entries/<game-id>/<slug>.json` | one hack per file (format: `docs/entry-format.md`) |
| `registry/games.tsv` | game ids and port status, generated; don't edit |
| `policy/refused-hosts.txt` | hosts that can never appear |
| `revoked.json` | removed entries; launchers hide them and delete cached patches |
| `tools/hackindex.py` | validate, build, check-remote, sync-games, `--selftest` (stdlib only) |
| `dist/index.json` | build output, not committed |

## Commands

```sh
python3 tools/hackindex.py --selftest
python3 tools/hackindex.py validate               # add --allow-empty while there are no entries
python3 tools/hackindex.py build --generated 2026-11-07
python3 tools/hackindex.py check-remote entries/oot-ntsc-1.2/some-hack.json
python3 tools/hackindex.py sync-games ../staticR/configs/games.toml
```

Exit codes: 0 ok, 1 a check failed, 2 usage error, 77 skipped (no network; never a pass).

See `CONTRIBUTING.md` to add an entry and `TAKEDOWN.md` to have one removed.

Tooling is MIT (`LICENSE`). Hack titles, credits and pages belong to their authors; each entry's
`license_note` records what the author allows.
