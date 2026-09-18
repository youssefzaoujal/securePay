<#
# InjectChaos — démonstration résilience fail-closed (Toxiproxy).
#
# Pré-requis :
#   docker compose --profile app --profile chaos up -d \
#     -e FRAUD_SERVICE_URL=http://toxiproxy:18003 \
#     -e TOKENIZATION_SERVICE_URL=http://toxiproxy:18002 \
#     -e PAYMENT_SERVICE_URL=http://toxiproxy:18001
#
# (toxiproxy charge automatiquement infra/chaos/proxies.json)
#
# Usage :
#   powershell -File scripts/inject_chaos.ps1 FraudDown
#   powershell -File scripts/inject_chaos.ps1 RecoverAll
#
# Scénarios : FraudDown | TokenDown | PaymentLatency | RecoverAll
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("FraudDown", "TokenDown", "PaymentLatency", "RecoverAll")]
  [string]$Scenario
)

$Toxiproxy = "http://localhost:8474"
$Http = "http://localhost:8000/api/v1/payments"
$Token = $env:PAYTEST_TOKEN

function Invoke-Toxic($proxy, $name, $type, $attrs) {
  $body = @{
    type       = $type
    name       = $name
    toxicity   = 1.0
    attributes = $attrs
  } | ConvertTo-Json -Depth 4
  Invoke-RestMethod -Method Post -Uri "$Toxiproxy/proxies/$proxy/toxics" -Body $body -ContentType "application/json"
  Write-Host "[chaos] $name injecté sur $proxy" -ForegroundColor Cyan
}

function Assert-FailClosed {
  Write-Host "`n==> Paiement 250.00 EUR pendant la panne..." -ForegroundColor Yellow
  $payload = @{
    amount       = 250.00
    currency     = "EUR"
    card_number  = "4111111111111111"
    card_expiry  = "12/29"
    card_cvv     = "123"
    merchant_id  = "merchant-api"
  } | ConvertTo-Json
  try {
    $resp = Invoke-RestMethod -Method Post -Uri $Http -Headers @{ Authorization = "Bearer $Token" } -Body $payload -ContentType "application/json"
    Write-Host "[FAIL] approve silencieux sous panne !?" -ForegroundColor Red
  } catch {
    $code = [int]$_.Exception.Response.StatusCode
    $ok = ($code -ge 500) -and ($code -ne 200)
    $color = if ($ok) { "Green" } else { "Red" }
    Write-Host "[cloud] statut $code => fail-closed dans la zone 5xx (jamais approve)" -ForegroundColor $color
  }
}

switch ($Scenario) {
  "FraudDown"      { Invoke-Toxic "fraud-check" "fraud-timeout" "timeout"  @{ timeout = 12000; jitter = 0 } }
  "TokenDown"      { Invoke-Toxic "tokenize-cde" "token-connreset" "reset_peer" @{} }
  "PaymentLatency" { Invoke-Toxic "payment-process" "payment-latency" "latency" @{ latency = 5000; jitter = 0 } }
  "RecoverAll" {
    foreach ($p in @("fraud-check", "tokenize-cde", "payment-process")) {
      Invoke-RestMethod -Method Delete -Uri "$Toxiproxy/proxies/$p/toxics"
      Write-Host "[chaos] toxics supprimés sur $p" -ForegroundColor Cyan
    }
    Write-Host "[chaos] système récupéré" -ForegroundColor Green
    return
  }
}

if ($Scenario -ne "RecoverAll") {
  Assert-FailClosed
  Start-Sleep 2
  Write-Host "`n==> Récupération..." -ForegroundColor Cyan
  powershell -File $PSCommandPath RecoverAll
}