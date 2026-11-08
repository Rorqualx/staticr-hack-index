# Next task: prove a hack loads (R0 + R1)

Status 2026-11-07: R0 landed (staticR main 80fc9154), R1 landed (efebd002), keep-original landed
(75347fbc). R1b (the open items) is scoped below. Repo facts cite file:line in the staticR
checkout at main 722d2655 unless a later commit is named; anything else is marked hypothesis.

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

## R1 results (2026-11-07, MM US, installed port bin e661b137)

Evidence ids are staticR evidence-store sha256 prefixes. All runs muted, background, under the
game-run lock and a rig booking.

### Base forms (measured)

| Base a patch names | What it is | Usable today? |
|---|---|---|
| port's stored ROM a1a7e48c (49128448 B) | zeldaret per-file decompressed | yes, applies as is |
| Patcher64+ "Decompressed" (CRC32 33751c40, 64 MiB) | retail d6133ace + `00` pad to 64 MiB, each present DMA file written decompressed at its vrom, header CRC recalculated (ndec.exe layout) | only by rebuilding that base from the retail ROM |
| retail compressed d6133ace (32 MiB) | the cart dump | only by applying to the retail ROM, then per-file Yaz0 decompress (reproduces a1a7e48c exactly from clean retail) |

Both conversions need the user's original retail ROM, which the launcher doesn't keep (onboarding
stores only the decompressed image). Q4: a retail-base patch does carry over (kz_practice, below),
except bytes a hack puts outside the DMA files, which the conversion drops.

### Candidates (Patcher64+ github.com/Admentus64/Patcher64Plus-Tool @ master, MM)

22 whole-ROM patches classed with `bin/hack_classify.py` against their own base:

| class | count | patches |
|---|---|---|
| A | 1 | pl.ppf (Polish text, sha256 4a7e33da…) |
| B | 1 | pirates_fortress_interior.bps (021944e0…): 3 files resized in place |
| C | 20 | master_quest (115 code bytes, 19 fns), zelda_revival, masked_quest, redux, widescreen, the 5 other language PPFs (26-61 code bytes each), and every small "Optional" PPF (chest, wallet, kegs, spin, hearts, icons, spider house, text_commands) |

Full table with sha256: evidence 0687c52c (r1-classify-table.tsv). Most small "option" hacks are
code. Only one real class-A hack was found, not three: an honest shortfall against the R1 gate.

### Runs

| What | Result | Evidence |
|---|---|---|
| Polish .nrm tagged `game_id` mm-n64-us (what R0's install_patch wrote) | refused by the host: "Mod is for a different game (mm-n64-us)". R0 bug | log in 0687c52c (run-20261107-115936) |
| same .nrm tagged mm (the seam's mod_game_id) | "Loading mod rompatch_mm_pl"; RDRAM at VI 600-2400 holds Polish bytes of files 25 + 1127 and none of the English; stock run the reverse | RDRAM 1a8958f0 (mod), 7a3e1b3d (stock) |
| pirates_fortress_interior (B) | loads; the RAM copy of dmadata (RDRAM 0x9F8B0) carries 3/3 patched rows; the scene itself is not reachable without play, so it is not shown drawing | RDRAM 44adc8b2, log b0793e4f |
| fixed install_patch, end to end | Polish installs tagged mm and loads (Polish in RDRAM); kz_practice (retail base, decompressed) refused: 17 recompiled functions | RDRAM 5453c393, bundle 0e817d80 |

### Q7 (librecomp 40868f2 source)

- `get_rom()` is the patched image: the patch applies to it and `set_rom_contents` swaps it in
  (`librecomp/src/mods.cpp:1661-1667`); PI reads come from it.
- No header CRC check at run time. The only hash is XXH3 on the stored ROM, before patching
  (`recomp.cpp:188`). A 64 MiB patched target booted (B run).

### Built (staticR main efebd002)

- `staticr_mods/hackclass.py` + `bin/hack_classify.py` (`--selftest` 16/16), ranges
  `configs/hacks/{oot,mm}.coderanges.tsv` from the installed emits (`ranges --check` detects
  stale ones). A file holding recompiled functions that moves in ROM is C: librecomp's
  `load_overlays` finds an overlay by the ROM address it is DMA'd from (`overlays.cpp:215`).
- `bin/gen-hack-support.py` bundles each port's mod id (from `host/<short>_rt64_host.cpp`, seam
  must agree; 16 ports) + gzipped ranges into the launcher. `install_patch` wraps with that id,
  refuses C, installs B only on MM (the measured port), refuses a port with no known id.

### Keep-original (staticR main 75347fbc)

User, 2026-11-07: "yes keep og". Onboarding a retail Zelda64 cart decompresses it, checks the
result against the pin and keeps the cart as `rom_original.z64`. `install_patch` picks the base by
the patch's source CRC: the stored ROM, the kept cart, or Patcher64+'s base rebuilt from the cart.
Retail MM onboards to a1a7e48c in 1.46 s. Patcher64+'s pirates_fortress_interior installs
unconverted and loads (RDRAM 887ab213, bundle 963a6400). kz_practice and master_quest are refused
for writing outside the files. The installed launcher's MM was set up again from the cart on
2026-11-07, so it keeps d6133ace.

## R1b. The open items (scope, 2026-11-07)

Four items were left open after keep-original. Measured facts cite an evidence id; everything else
is marked hypothesis.

### Facts the scope rests on

- All 18 Patcher64+ MM PPFs are PPF 3.0, image type 0, no undo data; 2 (redux, text_commands)
  carry the 1024-byte block check. PPF names no base: no CRC, no size.
- Only pl.ppf is class A. The other 17 are C (R1 table, evidence 0687c52c). Reading PPF unlocks one
  MM hack today, and the format for later ones.
- Applying a Patcher64+ PPF straight to the stored ROM gives the same image as the cart route
  for 10 of 18. One more (no_quick_spin_and_smaller_spin) differs only in the header CRC bytes it
  writes. pl differs by 14 bytes in an absent-row slot, which the cart route drops. widescreen
  moves a file past the stored ROM's end. de/es/fr/pt-BR/redux leave no findable dmadata table on
  the cart route (evidence 72ee908a). So a PPF that leaves the table alone needs no cart. One that
  moves files needs the cart route, or the table rewrite has to be followed.
- IPS, like PPF without undo data, is absolute offsets with no base check. One base-inference
  rule can serve both.
- OoT (measured 2026-11-07, evidence b0134455): a US 1.2 cart (sha1 41b3bdc4): onboarding it reproduces the port's ROM 539f3faf exactly (1.6 s).
  The installed launcher's OoT was set up again from it and keeps the cart. Patcher64+'s
  1.2 base built from it (CRC32 08e42fcb) is the source of its `us_rev2_to_us_rev1` downgrade and
  of `Decompressed/widescreen.bps`. Its OoT hacks bombiwa and master_quest target the 1.0 layout
  (b94d8af1, reached by its own downgrade chain), and gz_practice_rev0 targets the 1.0 cart
  (cd16c529). So most Patcher64+ OoT hacks are for 1.0. The one 1.2 patch read (widescreen) is
  class C (20 functions).

### Steps

| # | Item | What | Done when |
|---|---|---|---|
| 1 | Index notes | Commit this file (R1 results, keep-original, R1b) in this repo | committed |
| 2 | PPF reader | `staticr_mods/patchfile.py`: clean-room PPF 1.0/2.0/3.0 decode (block check and undo kept as data), `detect_format`, a `--selftest` fixture per version. `install_patch` takes `.ppf` | pl.ppf installs through the launcher and loads (Polish bytes in RDRAM, as R1). The 17 C patches are refused with R1's message |
| 3 | Base inference for base-less patches (PPF, IPS) | Apply to each candidate base the user has: stored ROM, kept cart, Patcher64+ base. A candidate passes when the result keeps a readable table, writes nothing outside files, and is not a no-op. Undo data or a block check, when present, must match the base. Exactly one pass → use it. Several pass → the user picks from those bases (user, 2026-11-07: "ask user to pick"). None → refuse as today | MM corpus: every PPF picks the base the R1 table says, or offers the choice. A synthetic IPS for the cart picks the cart. An ambiguous synthetic patch asks, and the picked base installs |
| 4 | Table-moving patches | Hypothesis to measure first: de/es/fr/pt-BR/redux rewrite or move dmadata. Find where the patched table is (hackclass.find_dma scans; zelda64.read_dma reads the fixed slot) and follow it in `to_port_layout` | the 5 patches map back to the port layout or are refused with a measured reason (all are class C today, so nothing new installs) |
| 5 | OoT cart | DONE 2026-11-07 (facts above, evidence b0134455) | 1.2 onboarding measured; Patcher64+ OoT bases named by CRC |
| 6 | Class-A hacks | Two more class-A hacks from a source other than RHDN (403 to scripts): another Patcher64+-like tool, or ones you point at | 2 more class-A entries measured loading, or the shortfall recorded |

Order: 1, 2+3 together (one launcher change, one land), 4 only if 3's corpus run shows the table
case matters for an A or B patch, 5 and 6 in parallel with 2+3. Cost: 2+3 is about the size of
keep-original. 4-6 are measurement first.

Out of scope: class C (code patches) needs a recompile per hack. R2 publishing decisions are below.

### R1b results (2026-11-07)

- Steps 2+3 built: staticR commit e4185190 (branch hack-r1b-ppf, not landed). PPF 1.0/2.0/3.0
  reader; an IPS or PPF is tried on every base you have (stored ROM, kept cart, Patcher64+'s
  base); one fit asks yes/no, several ask you to pick, none is refused with the reason per base.
  A PPF's own record (size, block check, undo) only rules bases out; it never skips the question.
  Measured on MM: pl.ppf asks once and builds the BPS the R1 run loaded; the other 17 Patcher64+
  PPFs are refused before any question (evidence 3f74858c).
- Step 4 skipped: all five table-moving patches (de/es/fr/pt-BR/redux) are class C.
- Step 6 (evidence 3d2cac23, candidates; 91c5798f, the run): two class-A OoT 1.2 hacks found
  outside RHDN's live site (archive.org RHDN mirror `rhdn-20210914`), both PPF 3.0 for the 1.2
  cart 41b3bdc4:
  - **Play as Ganondorf** (XModxGodX): changes files 502/503 only. Through install_patch only
    the cart fits (asked yes/no; 4.2 s to the question, 3.2 s to install: 231,321 records and
    pure-Python Yaz0). In the OoT port (muted, background): "Loading mod
    rompatch_play_as_ganondorf_in_oot"; RDRAM at VI 600-2400 holds 8/8 Ganondorf windows of
    file 502 and no Link ones; a stock run holds the reverse.
  - **Waluigi Voice Patch** alone: class A (files 3, 5, and data bytes in file 27 outside any
    recompiled function); meant to follow the Waluigi model patch (class B: rows moved out of
    order, refused); not run.
  - No class-A MM US hack found outside Patcher64+ (Razor Sword IPS, Pumkin Tower: C).
  - Most fan translations are C (Swedish, Greek: code/font changes) - measured for those two.
  - An IPS for another release can still class A (SadNES Italian: garbage text); IPS has no
    base check, so the user's yes is the only guard.

## After R1: what makes the index publishable (R2)

These need your decisions, so they are listed now:

| Item | Needs |
|---|---|
| Public home for this repo (GitHub org/user), GitHub Pages or a release asset | DONE 2026-11-07: github.com/Rorqualx/staticr-hack-index (public) |
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
