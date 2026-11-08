# Entry format (schema 1)

One JSON file per hack at `entries/<game-id>/<slug>.json`. The entry id is `<game-id>/<slug>`;
the slug is lowercase letters, digits and `-`. `tools/hackindex.py` is the definition of valid:
unknown fields are refused, so a typo can't slip through.

```json
{
  "schema": 1,
  "title": "Example Translation",
  "authors": ["Author Name"],
  "version": "1.2",
  "released": "2021-05-02",
  "game": "oot-ntsc-1.2",
  "base": {
    "name": "Legend of Zelda, The - Ocarina of Time (USA) (Rev 2)",
    "sha1": "<40 hex, of the file the patch applies to>",
    "form": "retail",
    "byte_order": "z64",
    "crc32": "<8 hex, optional>",
    "size": 33554432
  },
  "patch": {
    "format": "bps",
    "url": "https://author.example/files/hack-1.2.zip",
    "sha256": "<64 hex, of the downloaded file>",
    "size": 40213,
    "archive": "zip",
    "member": "hack.bps"
  },
  "page": "https://author.example/hack",
  "tags": ["translation"],
  "thumbs": ["https://author.example/shot1.png"],
  "license_note": "Author allows linking; no redistribution.",
  "redistribute": false,
  "compat": {"class": "unmeasured"}
}
```

| Field | Rule |
|---|---|
| `game` | an id in `registry/games.tsv`, equal to the folder name |
| `base.sha1` | sha1 of the exact file the patch expects. `form` says whether that is the ROM as sold (`retail`) or a decompressed image (`decompressed`, OoT/MM tooling); `byte_order` is `z64`, `v64` or `n64`. The launcher converts the user's onboarded ROM to that form before checking. |
| `patch.url` | https, no user info, not a ROM file name, host not refused |
| `patch.sha256`, `patch.size` | of the downloaded bytes (the zip if `archive` is `zip`); size at most 64 MiB |
| `patch.member` | required for a zip, the patch file inside it; never a ROM name |
| `license_note` | required; what the author allows (link, mirror, nothing stated) |
| `redistribute` | `true` only if the author allows mirroring the patch; default false |
| `compat` | `{"class": "unmeasured"}`, or `{"class": "A"/"B"/"C", "measured_on": {"port_build": "<commit>", "evidence": "<sha256>"}}`. Only the classifier (staticR R1) writes a measured class. |

Classes: **A** data-only, same code and overlay layout (expected to load through a `.nrm` ROM
patch); **B** data that moves or resizes files (needs R1 measurement per port); **C** changes code
(needs its own port; shown as "Needs its own port").

## Compiled index (what the launcher reads)

`build` writes `dist/index.json`: `{"schema", "source": "staticr-index", "generated", "expires",
"entries": [{"id", ...entry}], "revoked": [...]}`, sorted, compact, byte-identical for the same
input and `--generated` date. The index expires 180 days after its date by default.

## Signing and publishing

`tools/release.sh` builds, signs and publishes a GitHub release with `index.json` and
`index.json.sig`. The launcher reads them from
`https://github.com/Rorqualx/staticr-hack-index/releases/latest/download/` and accepts the index
only when the signature checks against a key it pins:

| key | key_id | private key |
|---|---|---|
| `keys/main.pub` | 24b60ded8adbf7b2 | the maintainer's macOS Keychain (service `staticr-hack-index`) |
| `keys/backup.pub` | 475ca087cb0b43b3 | offline, with the maintainer; used only if the main key is lost |

`index.json.sig` is `{"schema": 1, "key_id": ..., "sig": <base64 Ed25519 signature of the exact
index.json bytes>}`. A new key reaches users only with a launcher release, so both keys are
pinned from the start. `hackindex.py verify dist/index.json` checks a signature locally.
