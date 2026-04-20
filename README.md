# bn-pwndbg-sync

Binary Ninja plugin: localhost **XML-RPC** server for the active `BinaryView`, used by **[binja-pwndbg](https://github.com/nyxFault/binja-pwndbg)** (pwndbg/GDB) for live decompilation, IL, call trees, and symbol resolution.

## Install

Copy this entire folder into Binary Ninja’s user plugin directory and restart Binary Ninja:

| Platform | Path |
|----------|------|
| Linux | `~/.binaryninja/plugins/` |
| macOS | `~/Library/Application Support/Binary Ninja/plugins/` |
| Windows | `%APPDATA%\Binary Ninja\plugins\` |

Or symlink, for example:

```bash
ln -s "$(pwd)" ~/.binaryninja/plugins/bn-pwndbg-sync
```

## Usage

1. Open your binary in Binary Ninja.
2. **Plugins → Pwndbg Sync → Start XML-RPC Server** (default: `127.0.0.1:31337`).
3. In pwndbg, load [binja-pwndbg](https://github.com/nyxFault/binja-pwndbg) and run `bn-connect` / `bn-rpc`.

## Author

nyxFault

## License

MIT — see [LICENSE](LICENSE).
