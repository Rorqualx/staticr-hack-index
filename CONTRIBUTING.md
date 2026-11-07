# Adding a hack

1. Check the hack is a **patch** (IPS, UPS, BPS, xdelta or PPF) for a game in `registry/games.tsv`,
   downloadable from the author's own page or a patch-only archive.
2. Write `entries/<game-id>/<slug>.json` (format: `docs/entry-format.md`) with
   `"compat": {"class": "unmeasured"}`. Record the base ROM's sha1 from the hack's readme or page;
   an entry without a known base hash can't be added.
3. Run `python3 tools/hackindex.py validate` and `python3 tools/hackindex.py check-remote <file>`.
   Both must exit 0.
4. Open a pull request. CI runs the same checks. A maintainer (`.github/CODEOWNERS`) approves;
   compatibility is measured by staticR's classifier before the entry is marked A, B or C.

Not accepted: ROMs or pre-patched ROMs, links to sites in `policy/refused-hosts.txt`, entries
without a licence note, and hacks whose author forbids listing.
