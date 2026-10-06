param (
    [Parameter(Mandatory=$true)][string]$TargetIP,
    [Parameter(Mandatory=$true)][ValidateSet("baseline", "bruteforce", "aftermath")][string]$Scenario
)

function Is-PrivateIP {
    param([string]$ip)
    if ($ip -match "^10\.\d+\.\d+\.\d+$") { return $true }
    if ($ip -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$") { return $true }
    if ($ip -match "^192\.168\.\d+\.\d+$") { return $true }
    return $false
}

if (-not (Is-PrivateIP $TargetIP)) {
    Write-Host "Error: $TargetIP is not a valid private IPv4 address." -ForegroundColor Red
    exit 1
}

Write-Host "========================================="
Write-Host "        FRIEND ATTACK SIMULATOR (WIN)    "
Write-Host "========================================="
Write-Host "Target IP: $TargetIP"
Write-Host "Scenario:  $Scenario"
Write-Host "========================================="
$confirm = Read-Host "Type YES to confirm you have consent from the target owner"
if ($confirm -cne "YES") {
    Write-Host "Aborted."
    exit 1
}

switch ($Scenario) {
    "baseline" {
        Write-Host "[+] Testing ping..."
        Test-Connection -ComputerName $TargetIP -Count 3 -ErrorAction SilentlyContinue
        Write-Host "[+] Testing HTTP (port 8000)..."
        Test-NetConnection -ComputerName $TargetIP -Port 8000
        Write-Host "[+] Testing SSH (port 22)..."
        Test-NetConnection -ComputerName $TargetIP -Port 22
    }
    "bruteforce" {
        Write-Host "[+] Running wrong-password SSH attempts..."
        Write-Host "Since Windows doesn't easily script SSH passwords without 3rd party tools,"
        Write-Host "Run this command manually 6 times rapidly:"
        Write-Host "ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=no nosuchuser@$TargetIP"
    }
    "aftermath" {
        Write-Host "[+] Post-block baseline check"
        Test-Connection -ComputerName $TargetIP -Count 3 -ErrorAction SilentlyContinue
        Test-NetConnection -ComputerName $TargetIP -Port 8000
        Test-NetConnection -ComputerName $TargetIP -Port 22
    }
}
