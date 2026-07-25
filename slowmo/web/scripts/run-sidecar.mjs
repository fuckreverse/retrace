#!/usr/bin/env node
// run-sidecar.mjs — cross-platform dispatcher for the tenet sidecar prep scripts.
//
// `pnpm sidecar` / `pnpm sidecar:debug` need to work unmodified on macOS,
// Linux, and Windows dev machines and CI runners. The actual sidecar
// preparation logic lives in three platform-specific scripts (each owns its
// own dynamic-library discovery/rewrite mechanism — install_name_tool/@rpath
// on macOS, patchelf/$ORIGIN on Linux, DLL-next-to-exe on Windows); this
// wrapper just picks the right one based on `process.platform` and forwards
// argv (e.g. `--debug`/`--release`) unchanged.
//
// Kept as a thin dispatcher rather than merging the three scripts: each
// platform's dependency-resolution approach is different enough (Mach-O
// otool/install_name_tool vs. ELF ldd/patchelf vs. PE dumpbin) that a single
// shared script would need three parallel code paths anyway.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const srcTauriScripts = path.join(scriptDir, '..', 'src-tauri', 'scripts');
const forwardedArgs = process.argv.slice(2);

let command;
let args;

switch (process.platform) {
  case 'darwin':
    command = 'bash';
    args = [path.join(srcTauriScripts, 'prepare-sidecar.sh'), ...forwardedArgs];
    break;
  case 'linux':
    command = 'bash';
    args = [path.join(srcTauriScripts, 'prepare-sidecar-linux.sh'), ...forwardedArgs];
    break;
  case 'win32': {
    // -File args: forward --debug/--release through to the .ps1's -BuildType
    // switch by mapping flag names, since prepare-sidecar-windows.ps1 takes a
    // named -BuildType parameter (Debug/RelWithDebInfo/Release) rather than
    // the bash scripts' positional --debug/--release flags.
    const buildType = forwardedArgs.includes('--debug')
      ? 'Debug'
      : forwardedArgs.includes('--release')
        ? 'Release'
        : 'RelWithDebInfo';
    command = 'powershell';
    args = [
      '-ExecutionPolicy', 'Bypass',
      '-File', path.join(srcTauriScripts, 'prepare-sidecar-windows.ps1'),
      '-BuildType', buildType,
    ];
    break;
  }
  default:
    console.error(`error: no sidecar prep script for platform '${process.platform}'`);
    process.exit(1);
}

const result = spawnSync(command, args, { stdio: 'inherit' });
if (result.error) {
  console.error(`error: failed to launch '${command}': ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);
