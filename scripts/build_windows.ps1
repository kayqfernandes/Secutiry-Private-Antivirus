$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
$pythonRoot = (& python -c "import sys; print(sys.prefix)").Trim()
$tclZip = Get-ChildItem -LiteralPath (Join-Path $pythonRoot "tcl") -Filter "libtcl*.zip" -ErrorAction SilentlyContinue | Select-Object -First 1
$tkZip = Get-ChildItem -LiteralPath (Join-Path $pythonRoot "tcl") -Filter "libtk*.zip" -ErrorAction SilentlyContinue | Select-Object -First 1
$runtimeRoot = $null
$originalTclLibrary = $env:TCL_LIBRARY
$originalTkLibrary = $env:TK_LIBRARY
try {
    # Some Windows Python distributions ship Tcl/Tk resources in ZIP files.
    # PyInstaller cannot discover those until they are extracted and exposed to its hook.
    if ($tclZip -and $tkZip -and (-not $env:TCL_LIBRARY -or -not (Test-Path (Join-Path $env:TCL_LIBRARY "init.tcl")))) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $runtimeRoot = Join-Path $env:TEMP ("security-analyzer-tcl-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $runtimeRoot | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory($tclZip.FullName, $runtimeRoot)
        [System.IO.Compression.ZipFile]::ExtractToDirectory($tkZip.FullName, $runtimeRoot)
        $env:TCL_LIBRARY = Join-Path $runtimeRoot "tcl_library"
        $env:TK_LIBRARY = Join-Path $runtimeRoot "tk_library"
    }
    python -m PyInstaller `
        --noconfirm `
        --clean `
        --onedir `
        --windowed `
        --icon NONE `
        --name AnalisadorSegurancaPessoal `
        --distpath dist `
        --workpath build `
        --specpath build `
        app.py
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller terminou com código $LASTEXITCODE."
    }
} finally {
    if ($null -eq $originalTclLibrary) { Remove-Item Env:TCL_LIBRARY -ErrorAction SilentlyContinue }
    else { $env:TCL_LIBRARY = $originalTclLibrary }
    if ($null -eq $originalTkLibrary) { Remove-Item Env:TK_LIBRARY -ErrorAction SilentlyContinue }
    else { $env:TK_LIBRARY = $originalTkLibrary }
    Pop-Location
}
