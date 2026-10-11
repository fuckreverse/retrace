# Vendored third-party license texts

These files are the upstream license texts for native components whose
`license_files` entries in `../native-components.json` must resolve on any
machine (CI runners included) — the previous entries referenced machine-local
Homebrew paths or a pre-migration repository layout.

| Directory  | Component | Source (pinned branch) |
|------------|-----------|------------------------|
| `qbdi/`    | QBDI | https://github.com/QBDI/QBDI/blob/master/LICENSE.txt |
| `llvm/`    | LLVM 19.1.5 (Apache-2.0 WITH LLVM-exception) | https://github.com/llvm/llvm-project/blob/release/19.x/llvm/LICENSE.TXT |
| `triton/`  | Triton | https://github.com/jonathansalwan/Triton/blob/master/LICENSE.txt |
| `z3/`      | Z3 | https://github.com/Z3Prover/z3/blob/master/LICENSE.txt |
| `yara/`    | YARA | https://github.com/VirusTotal/yara/blob/master/COPYING |
| `openssl/` | OpenSSL 3.x | https://github.com/openssl/openssl/blob/master/LICENSE.txt |
| `libmagic/`| libmagic (file) | https://github.com/file/file/blob/master/COPYING |
| `jansson/` | Jansson | https://github.com/akheron/jansson/blob/master/LICENSE |
| `lz4/`     | LZ4 (lib/) | https://github.com/lz4/lz4/blob/dev/lib/LICENSE |

When bumping one of these components, refresh the corresponding text from the
upstream repository. Components whose licenses come from FetchContent sources
(`../../../_deps/*-src/...`) do not need vendoring — their license files are
downloaded with the sources at configure time.
