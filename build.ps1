$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
$src = Join-Path $root "src"
$outExe = Join-Path $root "PixelTunnel.exe"

$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$wpf = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF"

if (-not (Test-Path $csc)) {
    throw "csc.exe not found at $csc (.NET Framework 4.x required)"
}

$refs = @(
    "System.dll",
    "System.Core.dll",
    "System.Data.dll",
    "System.Drawing.dll",
    "System.Windows.Forms.dll",
    "System.Xaml.dll",
    "System.Net.Http.dll",
    "System.IO.Compression.dll",
    "System.IO.Compression.FileSystem.dll",
    "$wpf\WindowsBase.dll",
    "$wpf\PresentationCore.dll",
    "$wpf\PresentationFramework.dll"
) -join ","

Write-Host "Building PixelTunnel.exe from open source..."
& $csc /nologo /target:winexe /optimize+ /platform:x64 `
    "/win32icon:$src\pixel.ico" `
    "/win32manifest:$src\app.manifest" `
    "/resource:$src\pixel.ico,PixelTunnel.pixel.ico" `
    "/out:$outExe" `
    "/reference:$refs" `
    "$src\PixelTunnelNext.cs" `
    "$src\PixelCoreEngineV3.cs"

if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE"
}

Write-Host "OK: $outExe ($((Get-Item $outExe).Length) bytes)"
