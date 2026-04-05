# ==========================================
# CONFIGURATION - ENTER YOUR API KEYS HERE
# ==========================================
$ShodanApiKey = "YOUR_SHODAN_API_KEY_HERE"
$AbuseIPDBApiKey = "YOUR_ABUSEIPDB_API_KEY_HERE"

# The specific query you provided
$ShodanQuery = "hash:1321444670"
$MaxAgeDays = 90
$OutputFile = "DualPositiveIPs.txt"

# ==========================================

if ($ShodanApiKey -eq "YOUR_SHODAN_API_KEY_HERE" -or $AbuseIPDBApiKey -eq "YOUR_ABUSEIPDB_API_KEY_HERE") {
    Write-Host "[!] Please set your API keys in the script before running." -ForegroundColor Yellow
    exit
}

# 1. Query Shodan API (With Pagination)
Write-Host "[*] Starting Shodan query: $ShodanQuery" -ForegroundColor Cyan

$AllIpsToCheck = @()
$ShodanPage = 1
$KeepPaginating = $true
$TotalExpected = 0

while ($KeepPaginating) {
    $ShodanUrl = "https://api.shodan.io/shodan/host/search?key=$ShodanApiKey&query=$ShodanQuery&page=$ShodanPage"
    
    try {
        Write-Host "[*] Fetching Shodan results page $ShodanPage..." -ForegroundColor DarkCyan
        $ShodanResponse = Invoke-RestMethod -Uri $ShodanUrl -Method Get
        
        # On the first page, grab the total expected results
        if ($ShodanPage -eq 1) {
            $TotalExpected = $ShodanResponse.total
            Write-Host "[*] Shodan reports $TotalExpected total results across all pages." -ForegroundColor Cyan
        }

        # Extract IPs from the current page and append to our master list
        if ($ShodanResponse.matches) {
            $AllIpsToCheck += @($ShodanResponse.matches.ip_str)
        }

        # Check if we've retrieved all the IPs
        if ($AllIpsToCheck.Count -ge $TotalExpected -or $ShodanResponse.matches.Count -eq 0) {
            $KeepPaginating = $false
        } else {
            $ShodanPage++
            # Shodan API limits requests to 1 per second, so we must sleep
            Start-Sleep -Seconds 1
        }
    }
    catch {
        Write-Host "[!] Shodan API Error on page ${ShodanPage}: $_" -ForegroundColor Red
        $KeepPaginating = $false # Stop paginating on error
    }
}

if ($AllIpsToCheck.Count -eq 0) {
    Write-Host "[-] No IPs found to process. Exiting." -ForegroundColor Yellow
    exit
}

# 2. Setup AbuseIPDB Request Parameters
$AbuseHeaders = @{
    "Accept" = "application/json"
    "Key"    = $AbuseIPDBApiKey
}

Write-Host ("-" * 50)
Write-Host "[*] Starting AbuseIPDB cross-reference for $($AllIpsToCheck.Count) IPs..." -ForegroundColor Cyan
Write-Host ("-" * 50)

$MaliciousIps = @()

# 3. Check each IP against AbuseIPDB
foreach ($Ip in $AllIpsToCheck) {
    $AbuseUrl = "https://api.abuseipdb.com/api/v2/check?ipAddress=$Ip&maxAgeInDays=$MaxAgeDays"
    
    try {
        $AbuseResponse = Invoke-RestMethod -Uri $AbuseUrl -Method Get -Headers $AbuseHeaders
        $Data = $AbuseResponse.data
        
        if ($Data.totalReports -gt 0) {
            Write-Host "[+] MATCH FOUND: $Ip | Abuse Confidence Score: $($Data.abuseConfidenceScore)% | Reports (Last $MaxAgeDays days): $($Data.totalReports)" -ForegroundColor Red
            $MaliciousIps += $Ip
        }
        else {
            Write-Host "[-] Clean: $Ip (No reports in $MaxAgeDays days)" -ForegroundColor Green
        }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        
        # Check if the error is a Rate Limit / 429 error
        if ($ErrorMessage -match "429" -or $ErrorMessage -match "Too Many Requests") {
            Write-Host "[!] ABUSEIPDB RATE LIMIT REACHED (429)! Stopping checks early to save gathered data..." -ForegroundColor Magenta
            break # This exits the foreach loop early, moving straight to Step 4
        } else {
            # Standard error handling for timeouts or bad IPs
            Write-Host "[!] AbuseIPDB Request Error for ${Ip}: $_" -ForegroundColor Yellow
        }
    }
    
    # Add a small delay to respect rate limits (500 milliseconds)
    Start-Sleep -Milliseconds 500
}

Write-Host ("-" * 50)
Write-Host "[*] Scan Complete (or halted early). Found $($MaliciousIps.Count) IPs cross-referenced on both platforms." -ForegroundColor Cyan

# 4. Save results to a text file
if ($MaliciousIps.Count -gt 0) {
    # Out-File saves the array of IPs, one per line
    $MaliciousIps | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "[*] Saved $($MaliciousIps.Count) dual-positive IPs to $OutputFile in the current directory." -ForegroundColor Green
} else {
    Write-Host "[-] No dual-positive IPs to save." -ForegroundColor Yellow
}
