param(
    [string]$ServiceName = "SecretBroker",
    [string]$DisplayName = "Secret Broker",
    [string]$BinaryPath = "C:\Program Files\SecretBroker\secret-broker.exe",
    [string]$DataDir = "C:\ProgramData\SecretBroker",
    [string]$DbPath = "C:\ProgramData\SecretBroker\secret-broker.db",
    [string]$Bind = "127.0.0.1:4815",
    [string]$Mode = "enforce",
    [Parameter(Mandatory = $true)][string]$ClientApiKey,
    [Parameter(Mandatory = $true)][string]$ApproverApiKey
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    throw "Binary not found at $BinaryPath"
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

[Environment]::SetEnvironmentVariable("SECRET_BROKER_BIND", $Bind, "Machine")
[Environment]::SetEnvironmentVariable("SECRET_BROKER_DB", $DbPath, "Machine")
[Environment]::SetEnvironmentVariable("SECRET_BROKER_MODE", $Mode, "Machine")
[Environment]::SetEnvironmentVariable("SECRET_BROKER_CLIENT_API_KEY", $ClientApiKey, "Machine")
[Environment]::SetEnvironmentVariable("SECRET_BROKER_APPROVER_API_KEY", $ApproverApiKey, "Machine")

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

New-Service `
    -Name $ServiceName `
    -DisplayName $DisplayName `
    -BinaryPathName "`"$BinaryPath`"" `
    -StartupType Automatic | Out-Null

sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe description $ServiceName "Zero-trust secret broker for OpenClaw and other agent runtimes" | Out-Null
Start-Service $ServiceName

Write-Host "Installed and started $ServiceName"
Write-Host "Database path: $DbPath"
