# SecurePay lab — PowerShell
Set-Location $PSScriptRoot\..
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
New-Item -ItemType Directory -Force -Path logs | Out-Null
docker compose up -d
Write-Host "Command Center: http://localhost:9000"
Write-Host "SOC engine:     http://localhost:8010"
Write-Host "Keycloak:       http://localhost:8081"
Write-Host "Grafana:        http://localhost:3000"
Write-Host "Pour les APIs paiement: docker compose --profile app up -d --build"
