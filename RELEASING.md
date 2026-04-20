# Releasing (Binary Ninja Plugin Manager)

Follow [Plugin Manager 2.0](https://binary.ninja/2019/07/04/plugin-manager-2.0.html): tag a **real GitHub release** for each published version.

## Before tagging

1. Bump `"version"` in `plugin.json` if needed.
2. Validate metadata:
   ```bash
   # from Vector35/community-plugins clone:
   ./generate_plugininfo.py -v plugin.json
   ```
3. Commit and push `main`.

## Create release

**Option A — GitHub CLI**

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin main
git push origin v0.1.0
gh release create v0.1.0 --title "Pwndbg RPC Sync v0.1.0" --notes "See plugin.json version and README."
```

**Option B — git tag + GitHub web UI**

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin main
git push origin v0.1.0
```

Then: GitHub repo → **Releases** → **Draft a new release** → choose tag `v0.1.0` → publish.

**Option C — hub** (if installed), per Vector 35 blog:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
hub release create v0.1.0
```

Use the same version string as in `plugin.json`.
