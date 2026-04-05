# Shodan-AbuseIPDB Correlator

A PowerShell script that cross-references infrastructure found on Shodan with recent malicious activity reports from AbuseIPDB. 

It takes a Shodan query, paginates through the results to extract the IPs, and checks if they've been reported on AbuseIPDB within the last 90 days.

## Features

* **Auto-pagination:** Grabs all IPs from Shodan, bypassing the 100-result page limit.
* **Rate-limit handling:** Includes API delays. If you hit your AbuseIPDB daily limit (429 error), the script catches it, stops querying, and safely saves whatever matches it already found.
* **Clean output:** Appends all dual-positive IPs to a flat text file (`DualPositiveIPs.txt`) for easy import into blocklists or SIEMs.

## Setup

1. Get API keys for [Shodan](https://account.shodan.io/) and [AbuseIPDB](https://www.abuseipdb.com/).
2. Open `ShodanCheck.ps1` and add your keys to the config block:
   ```powershell
   $ShodanApiKey = "YOUR_SHODAN_API_KEY_HERE"
   $AbuseIPDBApiKey = "YOUR_ABUSEIPDB_API_KEY_HERE"
   ```
3. *(Optional)* Update the `$ShodanQuery` or `$MaxAgeDays` variables to fit your needs.

## Usage

Run the script from a PowerShell terminal. If execution policies block it, allow local scripts first:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\ShodanCheck.ps1
```

## Output

The script prints color-coded progress to the console. When finished, it writes matching IPs to `DualPositiveIPs.txt` (one IP per line):

```text
192.0.2.45
203.0.113.8
198.51.100.99
```
