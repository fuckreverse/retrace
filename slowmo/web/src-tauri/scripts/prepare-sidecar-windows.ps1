#Requires -Version 5.1
<#
prepare-sidecar-windows.ps1 —— 为 Tauri Windows 打包准备 tenet C++ 后端 sidecar。

阶段：
  1. 复用 tools/tenet/build 固定目录，以指定配置增量编译 tenet target。
  2. 确定 Tauri target triple，并复制最终 tenet.exe。
  3. 用 dumpbin（若可用）解析依赖，同时扫描 build 目录中的 DLL；把非系统 DLL
     复制到 binaries 根目录，与 sidecar 同级。
  4. 复用 collect_licenses.py 生成并校验第三方许可证材料。
  5. 输出 sidecar、DLL 和许可证统计。

Windows 没有 macOS rpath/RUNPATH 的等价机制。Windows 加载器会优先在可执行文件
所在目录查找 DLL，因此 DLL 必须与 tenet-<target-triple>.exe 同级，无需改写二进制。
Triton 和 YARA 在 Windows 默认关闭；若以后启用，只要其 DLL 出现在 build 目录或
可解析的 PATH 中，本脚本也会按相同规则收集。

用法：
  powershell -ExecutionPolicy Bypass -File .\prepare-sidecar-windows.ps1
  powershell -ExecutionPolicy Bypass -File .\prepare-sidecar-windows.ps1 -BuildType Release

默认 BuildType 为 RelWithDebInfo。脚本幂等：会覆盖本脚本管理的 sidecar、DLL 和
许可证输出，但绝不会创建或删除 CMake build 目录。
#>

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'RelWithDebInfo', 'Release')]
    [string]$BuildType = 'RelWithDebInfo'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ── 平台检测 ────────────────────────────────────────────────────────────────
# Windows PowerShell 5.1 没有 $IsWindows；PowerShell 6+ 才提供该变量。
$isWindowsPlatform = $false
$isWindowsVariable = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
if ($null -ne $isWindowsVariable) {
    $isWindowsPlatform = [bool]$isWindowsVariable.Value
} elseif ($PSVersionTable.PSObject.Properties.Name -contains 'Platform') {
    $isWindowsPlatform = $PSVersionTable.Platform -eq 'Win32NT'
} else {
    $isWindowsPlatform = $env:OS -eq 'Windows_NT'
}

if (-not $isWindowsPlatform) {
    throw '错误：prepare-sidecar-windows.ps1 只能在 Windows 上运行。'
}

# ── 路径 ────────────────────────────────────────────────────────────────────
$ScriptDir = $PSScriptRoot
$SrcTauriDir = [System.IO.Path]::GetFullPath((Join-Path $ScriptDir '..'))
$TenetDir = [System.IO.Path]::GetFullPath((Join-Path $SrcTauriDir '..\..'))
$BuildDir = Join-Path $TenetDir 'build'
$BinOutDir = Join-Path $SrcTauriDir 'binaries'
$LicenseOutDir = Join-Path $BinOutDir 'licenses'
$LicenseManifest = Join-Path $SrcTauriDir 'licenses\native-components.json'
$LicenseCollector = Join-Path $ScriptDir 'collect_licenses.py'
$WebDir = [System.IO.Path]::GetFullPath((Join-Path $SrcTauriDir '..'))

Write-Host '==> tenet Windows sidecar 准备脚本'
Write-Host "    TENET_DIR  = $TenetDir"
Write-Host "    BUILD_DIR  = $BuildDir"
Write-Host "    BUILD_TYPE = $BuildType"

if (-not (Test-Path -LiteralPath $BuildDir -PathType Container)) {
    throw "错误：固定构建目录 $BuildDir 不存在。请先按仓库约定初始化 tools/tenet/build；本脚本不会创建其他 build 目录。"
}

# ── 1. 编译 tenet（复用固定 build 目录，禁止新建）──────────────────────────
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if ($null -eq $cmake) {
    throw '错误：找不到 cmake，请先安装 CMake 并加入 PATH。'
}

$cachePath = Join-Path $BuildDir 'CMakeCache.txt'
if (-not (Test-Path -LiteralPath $cachePath -PathType Leaf)) {
    throw "错误：$cachePath 不存在。固定 build 目录尚未完成 CMake 配置。"
}

$cacheText = Get-Content -LiteralPath $cachePath -Raw
$isMultiConfig = ($cacheText -match '(?m)^CMAKE_CONFIGURATION_TYPES:') -or
    ($cacheText -match '(?m)^CMAKE_GENERATOR:INTERNAL=(Visual Studio|Xcode|Ninja Multi-Config)')

Write-Host "==> 以 $BuildType 增量编译 tenet ..."
if ($isMultiConfig) {
    # Visual Studio / Ninja Multi-Config：配置在构建时通过 --config 选择。
    & $cmake.Source --build $BuildDir --target tenet --config $BuildType --parallel
} else {
    # Ninja 等单配置生成器：先在同一固定目录更新 CMAKE_BUILD_TYPE，再构建。
    & $cmake.Source -S $TenetDir -B $BuildDir "-DCMAKE_BUILD_TYPE=$BuildType"
    if ($LASTEXITCODE -ne 0) {
        throw "错误：CMake 配置失败，退出码 $LASTEXITCODE。"
    }
    & $cmake.Source --build $BuildDir --target tenet --parallel
}
if ($LASTEXITCODE -ne 0) {
    throw "错误：tenet 编译失败，退出码 $LASTEXITCODE。"
}

# 多配置生成器通常输出 build/<Config>/tenet.exe，单配置生成器通常直接输出
# build/tenet.exe。只在这两个约定位置查找，避免误拿测试目录中的同名旧产物。
$tenetCandidates = @(
    (Join-Path (Join-Path $BuildDir $BuildType) 'tenet.exe'),
    (Join-Path $BuildDir 'tenet.exe')
)
$TenetBin = $tenetCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if ($null -eq $TenetBin) {
    throw "错误：编译后未在预期位置找到 tenet.exe：$($tenetCandidates -join ', ')"
}

# ── 2. 确定 target triple（Tauri sidecar 命名规则）─────────────────────────
$TargetTriple = $null
$rustc = Get-Command rustc -ErrorAction SilentlyContinue
if ($null -ne $rustc) {
    $rustVersion = & $rustc.Source -vV
    if ($LASTEXITCODE -eq 0) {
        $hostLine = $rustVersion | Where-Object { $_ -match '^host:\s*(.+)$' } | Select-Object -First 1
        if ($null -ne $hostLine) {
            $TargetTriple = ([regex]::Match($hostLine, '^host:\s*(.+)$')).Groups[1].Value.Trim()
        }
    }
}

if ([string]::IsNullOrWhiteSpace($TargetTriple)) {
    switch ($env:PROCESSOR_ARCHITECTURE.ToUpperInvariant()) {
        'AMD64' { $TargetTriple = 'x86_64-pc-windows-msvc' }
        'ARM64' { $TargetTriple = 'aarch64-pc-windows-msvc' }
        default { throw "错误：无法根据 PROCESSOR_ARCHITECTURE='$env:PROCESSOR_ARCHITECTURE' 推断 Windows target triple。" }
    }
}
Write-Host "==> target triple: $TargetTriple"

New-Item -ItemType Directory -Path $BinOutDir -Force | Out-Null

# 清理上次由本脚本放在根目录的 Windows sidecar 和 DLL；保留其他平台产物及目录。
Get-ChildItem -LiteralPath $BinOutDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^tenet-.+-pc-windows-(msvc|gnu)\.exe$' -or $_.Extension -ieq '.dll' } |
    Remove-Item -Force

$FinalBin = Join-Path $BinOutDir "tenet-$TargetTriple.exe"
Copy-Item -LiteralPath $TenetBin -Destination $FinalBin -Force

# ── 3. 收集非系统 DLL 依赖 ─────────────────────────────────────────────────
#
# 策略是“两路合并”：
#   A. 始终扫描 build 目录树中的 *.dll，覆盖 CMake/vcpkg/FetchContent 常见布局；
#   B. dumpbin 可用时，从 tenet.exe 和已发现 DLL 递归读取 /dependents，并尝试在
#      引用文件目录、build 目录索引和 PATH 中定位额外 DLL。
#
# zstd、mimalloc 是常见的 Windows 动态依赖；Triton/YARA 默认在 Windows 为 OFF，
# 正常构建不应需要它们。若显式启用，其 DLL 仍会被上述通用逻辑收集。

function Test-IsSystemDllPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $windowsRoot = [System.IO.Path]::GetFullPath($env:WINDIR).TrimEnd('\')
    return $fullPath.StartsWith($windowsRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-IsSystemDllName {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Name -match '^(api-ms-win-|ext-ms-win-)') {
        return $true
    }

    # dumpbin 只给出 DLL 文件名时，先排除稳定的 Windows 系统组件；其余名称仍会
    # 经路径检查，绝不会从 %WINDIR%（System32/SysWOW64 等）复制。
    $systemNames = @(
        'advapi32.dll', 'bcrypt.dll', 'bcryptprimitives.dll', 'cabinet.dll',
        'comctl32.dll', 'comdlg32.dll', 'crypt32.dll', 'd3d11.dll', 'dbghelp.dll',
        'gdi32.dll', 'imm32.dll', 'iphlpapi.dll', 'kernel32.dll', 'msvcrt.dll',
        'ntdll.dll', 'ole32.dll', 'oleaut32.dll', 'powrprof.dll', 'rpcrt4.dll',
        'secur32.dll', 'setupapi.dll', 'shell32.dll', 'shlwapi.dll', 'user32.dll',
        'userenv.dll', 'version.dll', 'winhttp.dll', 'winmm.dll', 'winspool.drv',
        'ws2_32.dll', 'wtsapi32.dll'
    )
    return $systemNames -contains $Name.ToLowerInvariant()
}

function Import-VsDeveloperEnvironment {
    # 优先使用 PATH 中的 vswhere；否则检查 Visual Studio Installer 默认位置。
    $vswhereCommand = Get-Command vswhere.exe -ErrorAction SilentlyContinue
    $vswherePath = if ($null -ne $vswhereCommand) {
        $vswhereCommand.Source
    } else {
        Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    }

    if (-not (Test-Path -LiteralPath $vswherePath -PathType Leaf)) {
        return $false
    }

    $installationPath = & $vswherePath -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installationPath)) {
        return $false
    }

    $vsDevCmd = Join-Path ($installationPath | Select-Object -First 1) 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $vsDevCmd -PathType Leaf)) {
        return $false
    }

    # 批处理脚本无法直接修改父 PowerShell 环境；让 cmd 输出完整环境，再逐项导入。
    $environmentLines = & $env:ComSpec /s /c "`"$vsDevCmd`" -no_logo >nul && set"
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    foreach ($line in $environmentLines) {
        if ($line -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
        }
    }
    return $true
}

$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
if ($null -eq $dumpbin) {
    if (Import-VsDeveloperEnvironment) {
        $dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    }
}
if ($null -eq $dumpbin) {
    Write-Warning '未找到 dumpbin.exe。请从 Developer PowerShell for VS 运行，或安装 Visual C++ Build Tools。将回退为扫描 build 目录下全部 DLL；无法自动发现仅存在于外部 PATH 的间接依赖。'
} else {
    Write-Host "    dumpbin = $($dumpbin.Source)"
}

# 以 DLL 文件名建立 build 索引。Windows 加载器同样按名称解析，因此名称比较不区分大小写。
$buildDlls = @(Get-ChildItem -LiteralPath $BuildDir -Filter '*.dll' -File -Recurse -ErrorAction SilentlyContinue)
$dllIndex = @{}
foreach ($dll in $buildDlls) {
    $key = $dll.Name.ToLowerInvariant()
    if (-not $dllIndex.ContainsKey($key)) {
        $dllIndex[$key] = $dll.FullName
    } elseif ($dllIndex[$key] -ne $dll.FullName) {
        Write-Warning "build 目录中存在同名 DLL，使用第一个：$($dllIndex[$key])；忽略：$($dll.FullName)"
    }
}

function Find-DllByName {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ReferrerDirectory
    )

    if (Test-IsSystemDllName -Name $Name) {
        return $null
    }

    $localCandidate = Join-Path $ReferrerDirectory $Name
    if ((Test-Path -LiteralPath $localCandidate -PathType Leaf) -and -not (Test-IsSystemDllPath -Path $localCandidate)) {
        return [System.IO.Path]::GetFullPath($localCandidate)
    }

    $indexKey = $Name.ToLowerInvariant()
    if ($dllIndex.ContainsKey($indexKey)) {
        $indexedPath = $dllIndex[$indexKey]
        if (-not (Test-IsSystemDllPath -Path $indexedPath)) {
            return $indexedPath
        }
    }

    foreach ($pathEntry in ($env:PATH -split [System.IO.Path]::PathSeparator)) {
        if ([string]::IsNullOrWhiteSpace($pathEntry)) {
            continue
        }
        $candidate = Join-Path $pathEntry $Name
        if ((Test-Path -LiteralPath $candidate -PathType Leaf) -and -not (Test-IsSystemDllPath -Path $candidate)) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }
    return $null
}

function Get-DumpbinDependents {
    param([Parameter(Mandatory = $true)][string]$BinaryPath)

    if ($null -eq $dumpbin) {
        return @()
    }

    $output = & $dumpbin.Source /nologo /dependents $BinaryPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "dumpbin 无法解析 '$BinaryPath'，将继续处理其他文件。"
        return @()
    }

    return @($output | ForEach-Object {
        $match = [regex]::Match($_.ToString(), '(?i)^\s*([^\s:]+\.dll)\s*$')
        if ($match.Success) { $match.Groups[1].Value }
    } | Sort-Object -Unique)
}

# 待复制集合先包含 build 树中的全部非系统 DLL；随后用 dumpbin 队列补充 PATH 中的依赖。
$sourceByName = @{}
foreach ($dll in $buildDlls) {
    if (-not (Test-IsSystemDllPath -Path $dll.FullName)) {
        $key = $dll.Name.ToLowerInvariant()
        if (-not $sourceByName.ContainsKey($key)) {
            $sourceByName[$key] = $dll.FullName
        }
    }
}

$scanQueue = New-Object 'System.Collections.Generic.Queue[string]'
$scanQueue.Enqueue($TenetBin)
foreach ($sourcePath in @($sourceByName.Values)) {
    $scanQueue.Enqueue($sourcePath)
}
$scannedPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

while ($scanQueue.Count -gt 0) {
    $binary = $scanQueue.Dequeue()
    if (-not $scannedPaths.Add($binary)) {
        continue
    }
    $referrerDirectory = Split-Path -Parent $binary
    foreach ($dependencyName in (Get-DumpbinDependents -BinaryPath $binary)) {
        if (Test-IsSystemDllName -Name $dependencyName) {
            continue
        }
        $dependencyPath = Find-DllByName -Name $dependencyName -ReferrerDirectory $referrerDirectory
        if ($null -eq $dependencyPath) {
            Write-Warning "无法定位非系统依赖 '$dependencyName'（引用自 '$binary'）。请把对应 DLL 放入 build 目录或加入 PATH。"
            continue
        }
        $key = $dependencyName.ToLowerInvariant()
        if (-not $sourceByName.ContainsKey($key)) {
            $sourceByName[$key] = $dependencyPath
            $scanQueue.Enqueue($dependencyPath)
        }
    }
}

Write-Host '==> 复制非系统 DLL 到 sidecar 同目录 ...'
foreach ($entry in $sourceByName.GetEnumerator() | Sort-Object Key) {
    $destination = Join-Path $BinOutDir ([System.IO.Path]::GetFileName($entry.Value))
    Write-Host "    $([System.IO.Path]::GetFileName($entry.Value)) <- $($entry.Value)"
    Copy-Item -LiteralPath $entry.Value -Destination $destination -Force
}
$DllCount = $sourceByName.Count

# Windows 不需要 install_name_tool/rpath 重写。正式发布时的 Authenticode 签名需要
# signtool.exe 和发布证书，属于 CI/发布流程，不在本地 sidecar 准备脚本中处理。

# ── 4. 生成第三方许可证资源 ────────────────────────────────────────────────
Write-Host '==> 生成并校验第三方许可证材料 ...'
$python = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $python) {
    $python = Get-Command python3 -ErrorAction SilentlyContinue
}
if ($null -eq $python) {
    throw '错误：找不到 python 或 python3，无法运行 collect_licenses.py。'
}

& $python.Source $LicenseCollector `
    --manifest $LicenseManifest `
    --lib-dir $BinOutDir `
    --web-dir $WebDir `
    --src-tauri-dir $SrcTauriDir `
    --output $LicenseOutDir
if ($LASTEXITCODE -ne 0) {
    throw "错误：第三方许可证生成失败，退出码 $LASTEXITCODE。"
}

# ── 5. 汇总 ────────────────────────────────────────────────────────────────
$LicenseFileCount = @(Get-ChildItem -LiteralPath $LicenseOutDir -File -Recurse -ErrorAction SilentlyContinue).Count
Write-Host '==> 完成。'
Write-Host "    sidecar 二进制: $FinalBin"
Write-Host "    已复制 DLL:     $DllCount 个（与 sidecar 同目录）"
Write-Host "    许可证目录:     $LicenseOutDir（$LicenseFileCount 个文件）"
