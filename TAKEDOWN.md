# Removing an entry

If you are a hack's author or a rights holder and want an entry removed, contact the maintainers
(joederasespinoza@gmail.com, or open an issue at https://github.com/Rorqualx/staticr-hack-index/issues). We aim to act within 72 hours.

A removal deletes the entry file and adds a line to `revoked.json`:

```json
{"id": "<game-id>/<slug>", "patch_sha256": "<sha256>", "date": "YYYY-MM-DD", "reason": "author request"}
```

Launchers that read the index hide revoked entries and delete any cached copy of that patch. The
validator refuses a revoked id or patch hash that is still listed.
