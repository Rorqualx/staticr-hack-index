# Next task: prove a hack loads (R0 + R1)

Status 2026-11-07: scope only, not started. Repo facts cite file:line in the staticR checkout at main
722d2655; anything else is marked hypothesis.

## Why this is next

The index exists, but it can't hold a single entry honestly yet. Every entry needs a compatibility
class, and nobody has seen any hack load on a staticR port. If data-only hacks don't load, the
index, the Browse view (R3) and the import tool (R4) have nothing to show. So R0 and R1 come
before publishing anything.

## Where things stand (repo facts)

- `install_patch` (`staticr_launcher/services/mods.py:557`) wraps only **BPS**. IPS and UPS are
  refused with a CLI hint (`mods.py:574-578`). Its docstring says "the launcher does not track ROM
  paths", but onboarding stores the normalised ROM as `<data_dir>/rom_uncompressed.z64`
  (`services/onboarding.py:30`, `onboard_rom` at :145). So the base is probably there to convert
  against (hypothesis until R0's first test reads it).
- A BPS is wrapped with no base check (`mods.py:580`). librecomp checks only the source size; its
  CRC checks are commented out (Q7 research: `librecomp/src/patcher.cpp:198, 257`). A same-size
  wrong-base patch would apply silently.
- `staticr_mods/patchfile.py` decodes IPS, UPS and BPS and can write a BPS (`make_bps`); UPS and
  BPS check CRCs, IPS has none.
- librecomp takes one ROM-patch mod at a time (`mods.cpp:1626-1638`).

## R0. Any patch installs, checked against its base

Builds:
1. `install_patch` reads the onboarded `rom_uncompressed.z64`. For IPS/UPS it applies the patch,
   then makes one BPS from the clean ROM to the result (`make_bps`) and wraps that. A BPS is
   applied once to check it before wrapping.
2. Base check for every format: the patch's source CRC (UPS/BPS) must match the stored ROM. An IPS
   has no hash, so it is accepted only when the index entry or the user's file gives a base sha1
   that matches. Otherwise the Mods page asks "base unverified, install anyway?".
3. OoT/MM (Q4 "ok"): if the base check fails against the decompressed ROM, try the retail
   compressed form. That needs the user's original file or a recompression step; R0 records which
   form matched and refuses with both hashes if neither does. (Whether a patched retail ROM still
   decompresses correctly is measured in R1, step 4.)
4. The same path is used by the QML Mods page, the console UI and the web API.

Gate (tests, no game run):
- an IPS on a synthetic fixture ROM installs as `.nrm`, and the BPS inside it gives the same target
  sha256 as applying the IPS directly;
- the same for a UPS;
- a wrong-base UPS/BPS is refused, and the message shows both hashes;
- an IPS with no base hash gets the "unverified" prompt, never a silent install;
- the QML, console and web install paths each pass one round trip;
- a second ROM-patch mod is refused with a clear message (the one-patch limit stays until stacking).

Size: about a day. Launcher only, so the rebuilt app is installed afterwards (standing rule).

## R1. Measure "loading a hack" (no new UI)

Builds:
1. `bin/hack_classify.py` (tool contract, `--selftest`): diffs a patched image against the clean
   ROM, header CRC bytes 0x10-0x17 excluded. It maps changed bytes to code ranges from a new
   `<short>.coderanges.tsv` (generated from the emit's function table, never hand-copied) and to
   DMA files for OoT/MM. Verdict: A (data only, no file moved or resized), B (a file moved or
   resized, or the ROM size changed), C (a byte inside a recompiled function's range).
2. Pick 3 real data-only patches and 1 code patch for OoT (or MM), from authors' own pages.
   Candidates get chosen at the start of R1 and listed here with their sha256.
3. Run each on the installed port: muted, in the background, under the game-run lock and a rig
   booking. Evidence:
   - the run log shows the `.nrm` ROM patch was loaded;
   - an RDRAM dump or frame capture shows the patched data (for a text hack, the new string in
     RDRAM; for a texture or level hack, a frame). It goes into the evidence store, cited by sha256;
   - the code patch is classed C and refused before launch.
4. Q4: apply a retail-compressed-base patch, let the port decompress it, and check the result. If
   it fails, retail-base OoT/MM hacks are listed as "needs a decompressed-base patch".
5. Q7 facts the stacking design needs: is `get_rom()` the decompressed image, and is the header CRC
   checked at run time?

Gate:
- the classifier's `--selftest`: a synthetic one-word change in a code range gives C (known
  positive); one text byte gives A (known negative); a moved file gives B;
- for the 3 data patches, a log line plus a capture sha256 each, or an honest negative written down
  with its evidence;
- the code patch refused, test id cited.

Size: two to three days, most of it choosing patches and capturing evidence.

## After R1: what makes the index publishable (R2)

These need your decisions, so they are listed now:

| Item | Needs |
|---|---|
| Public home for this repo (GitHub org/user), GitHub Pages or a release asset | where staticR goes public (no remote is configured today) |
| Signing key (Ed25519) and who holds it; ideally a second keyholder | you |
| Takedown contact address in `TAKEDOWN.md`; maintainer handles in `.github/CODEOWNERS` | you |
| Launcher reader: fetch with ETag, cache, signature and `expires` check, refuse an older index, apply `revoked` | staticR R2 work; the built-in row then gets its URL |
| First 10-30 entries, OoT/MM, class A from R1's classifier | R1 done |
| Whether to import metadata from the romhacking.net dump (Q8) | your answer, and possibly asking its maintainers |

## Risks

- Data-only hacks may still not load: some OoT text hacks resize files, which is class B. R1 says
  how many of the candidates are really A.
- Most OoT hacks target 1.0 or the debug ROM, but the port runs NTSC 1.2, so the first entries may
  come mostly from MM (hypothesis about the hack corpus).
- The web build has no `.nrm` loader, so hacks are desktop-only until that exists.
