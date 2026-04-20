# bn-pwndbg-sync

<p align="left">
  <a href="https://github.com/nyxFault/bn-pwndbg-sync/blob/main/LICENSE"><img alt="License MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="Python 3" src="https://img.shields.io/badge/python-3.x-3776ab?logo=python&logoColor=white">
  <img alt="Binary Ninja" src="https://img.shields.io/badge/Binary%20Ninja-plugin-f59e0b">
  <img alt="XML-RPC" src="https://img.shields.io/badge/API-XML--RPC-22c55e">
  <img alt="Platforms" src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey">
  <a href="https://github.com/nyxFault/binja-pwndbg"><img alt="Companion pwndbg" src="https://img.shields.io/badge/companion-binja--pwndbg-7a3cff?logo=github"></a>
</p>

Binary Ninja plugin: localhost **XML-RPC** server for the active `BinaryView`, used by **[binja-pwndbg](https://github.com/nyxFault/binja-pwndbg)** (pwndbg/GDB) for live decompilation, IL, call trees, and symbol resolution.

## Install

Copy this entire folder into Binary Ninja’s user plugin directory and restart Binary Ninja:

| Platform | Path |
|----------|------|
| Linux | `~/.binaryninja/plugins/` |
| macOS | `~/Library/Application Support/Binary Ninja/plugins/` |
| Windows | `%APPDATA%\Binary Ninja\plugins\` |

## Usage

1. Open your binary in Binary Ninja.
2. **Plugins → Pwndbg Sync → Start XML-RPC Server** (default: `127.0.0.1:31337`).
3. In pwndbg, load [binja-pwndbg](https://github.com/nyxFault/binja-pwndbg) and run `bn-connect` / `bn-rpc`.

## Author

nyxFault

## License

MIT — see [LICENSE](LICENSE).
