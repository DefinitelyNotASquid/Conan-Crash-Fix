# Builds out\winmm.dll with llvm-mingw (https://github.com/mstorsjo/llvm-mingw, the ucrt x86_64 build).
#   .\build.ps1 -Toolchain C:\path\to\llvm-mingw-<version>-ucrt-x86_64
param([Parameter(Mandatory = $true)][string]$Toolchain)
$ErrorActionPreference = 'Stop'
$bin = Join-Path (Resolve-Path $Toolchain) 'bin'
$out = Join-Path $PSScriptRoot 'out'
$obj = Join-Path $out 'obj'
New-Item -ItemType Directory -Force $obj | Out-Null
$minhook = Join-Path $PSScriptRoot 'third_party\minhook\src'
$objects = @()
foreach ($source in @('buffer.c', 'hook.c', 'trampoline.c', 'hde\hde64.c')) {
    $object = Join-Path $obj ([IO.Path]::GetFileNameWithoutExtension($source) + '.o')
    & (Join-Path $bin 'x86_64-w64-mingw32-clang.exe') -O2 -c (Join-Path $minhook $source) -o $object
    if ($LASTEXITCODE) { throw "MinHook compilation failed: $source" }
    $objects += $object
}
& (Join-Path $bin 'x86_64-w64-mingw32-clang++.exe') -std=c++17 -O2 -Wall -Wextra -Werror -static -DUNICODE -D_UNICODE -shared `
    (Join-Path $PSScriptRoot 'src\BattlEyeFix.cpp') (Join-Path $PSScriptRoot 'src\BattlEyeFix.def') @objects -lbcrypt `
    -o (Join-Path $out 'winmm.dll')
if ($LASTEXITCODE) { throw 'Compilation failed' }
Get-FileHash (Join-Path $out 'winmm.dll') -Algorithm SHA256 | Format-List Path, Hash
