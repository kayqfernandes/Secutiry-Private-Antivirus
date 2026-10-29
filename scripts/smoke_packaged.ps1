$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$executable = Join-Path $repoRoot "dist\AnalisadorSegurancaPessoal\AnalisadorSegurancaPessoal.exe"
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Executável empacotado não encontrado: $executable"
}

$process = Start-Process -FilePath $executable -ArgumentList "--self-check" -PassThru
if (-not $process.WaitForExit(60000)) {
    $process.Kill()
    throw "O teste do executável excedeu 60 segundos."
}
if ($process.ExitCode -ne 0) {
    throw "O teste do executável terminou com código $($process.ExitCode)."
}
