function Start-PSAmsiClient {
    <#

    .SYNOPSIS

    Conducts a series of PSAmsiScans retrieved from a PSAmsiServer.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: New-PSAmsiScanner, Invoke-PSAmsiScan
    Optional Dependencies: none

    .DESCRIPTION

    Start-PSAmsiClient retrieves PSAmsiScan requests from a PSAmsiServer and
    checks them against the client's AMSI AntiMalware Provider using Invoke-PSAmsiScan.

    .PARAMETER ServerUri

    Specifies the URI of the PSAmsiServer to retreive requests from.

    .PARAMETER AlertLimit

    Specifies the maximum amount of AMSI alerts this client is allowed to generate.

    .PARAMETER Delay

    Specifies the amount of time (in seconds) to wait between AMSI alerts.

    .PARAMETER PSAmsiScanner

    Specifies the PSAmsiScanner to use for AMSI scans.

    .PARAMETER FindAmsiSignatures

    Specifies that the PSAmsiScan should find and return the AMSI signatures found in the script
    in addition to the result of the scan.

    .PARAMETER GetMinimallyObfuscated

    Specifies that the PSAmsiScan should minimally obfuscate the script until it is no longer flagged by AMSI.

    .EXAMPLE

    Start-PSAmsiClient -ServerUri http://10.100.100.10

    .EXAMPLE

    Start-PSAmsiClient -ServerUri http://example.com -AlertLimit 10 -Delay 3600 -FindAmsiSignatures

    .EXAMPLE

    Start-PSAmsiClient -ServerUri http://example.com -Delay 60 -GetMinimallyObfuscated

    .NOTES

    Start-PSAmsiClient is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>

    Param(
        [Parameter(Position = 0, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ServerUri,

        [Parameter(Position = 1)]
        [ValidateRange(0, [Int]::MaxValue)]
        [Int] $AlertLimit = 0,

        [Parameter(Position = 2)]
        [ValidateRange(0, [Int]::MaxValue)]
        [Int] $Delay = 0,

        [Parameter(Position = 3)]
        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner,

        [Switch] $FindAmsiSignatures,

        [Switch] $GetMinimallyObfuscated
    )

    $CreatedPSAmsiScanner = $False
    # Create the PSAmsiScanner to be used by the PSAmsiClient, if not provided one.
    If (-not $PSAmsiScanner) {
        $CreatedPSAmsiScanner = $True
        $PSAmsiScanner = New-PSAmsiScanner -AlertLimit $AlertLimit -Delay $Delay
    } Else {
        $PSAmsiScanner.AlertLimit = $AlertLimit
        $PSAmsiScanner.Delay = $Delay
    }

    # Use the system web proxy, if one exists
    (New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

    # Retrieve the PSAmsiScanRequests from the PSAmsiScanServer
    $PSAmsiScanRequestObj = Invoke-RestMethod -Uri $ServerUri -TimeoutSec 0
    
    # Read CachedAmsiScanResults, PSAmsiServer will provide cached results from other PSAmsiScanClients, if any.
    $CachedAmsiScanResults = @{}
    $Result = $PSAmsiScanRequestObj.CachedAmsiScanResults | Get-Member -MemberType Properties | % {
        $CachedAmsiScanResults.Add($_.Name, $PSAmsiScanRequestObj.CachedAmsiScanResults.($_.Name))
    }
    Write-Verbose "[Start-PSAmsiClient] Received $($CachedAmsiScanResults.Count) cached scan results from PSAmsiServer"
    Write-Verbose "[Start-PSAmsiClient] Received $($PSAmsiScanRequestObj.PSAmsiScanRequests.Count) PSAmsiScanRequests from PSAmsiServer"
    # Have the PSAmsiScanner use any cached scan results provided from the server
    $PSAmsiScanner.ScanCache = $CachedAmsiScanResults

    # Iterate through PSAmsiScanRequests, calling Invoke-PSAmsiScan for each one
    $PSAmsiScanRequests = $PSAmsiScanRequestObj.PSAmsiScanRequests
    If ($FindAmsiSignatures -and $GetMinimallyObfuscated) {
        $PSAmsiScanResults = $PSAmsiScanRequests | % { Invoke-PSAmsiScan -ScriptName $_.ScriptName -ScriptString $_.ScriptString -PSAmsiScanner $PSAmsiScanner -FindAmsiSignatures -GetMinimallyObfuscated -IncludeStatus }
    } ElseIf ($FindAmsiSignatures) {
        $PSAmsiScanResults = $PSAmsiScanRequests | % { Invoke-PSAmsiScan -ScriptName $_.ScriptName -ScriptString $_.ScriptString -PSAmsiScanner $PSAmsiScanner -FindAmsiSignatures -IncludeStatus }
    } ElseIf ($GetMinimallyObfuscated) {
        $PSAmsiScanResults = $PSAmsiScanRequests | % { Invoke-PSAmsiScan -ScriptName $_.ScriptName -ScriptString $_.ScriptString -PSAmsiScanner $PSAmsiScanner -GetMinimallyObfuscated -IncludeStatus }
    } Else {
        $PSAmsiScanResults = $PSAmsiScanRequests | % { Invoke-PSAmsiScan -ScriptName $_.ScriptName -ScriptString $_.ScriptString -PSAmsiScanner $PSAmsiScanner -IncludeStatus }
    }

    # If any PSAmsiScanRequests are not complete due to AlertLimit, then provide CachedAmsiScanResults to PSAmsiScanServer
    # Otherwise, we will just give an empty object to reduce network traffic
    $UnfinishedPSAmsiScanRequests = @()
    $UnfinishedPSAmsiScanRequests += $PSAmsiScanResults | ? { -not $_.RequestCompleted }
    
    If ($UnfinishedPSAmsiScanRequests.Count -gt 0) {
        Write-Verbose "[Start-PSAmsiClient] $($UnfinishedPSAmsiScanRequests.Count) PSAmsiScanRequest(s) were not completed. Sending $($PSAmsiScanner.ScanCache.Count) cached scan results back to PSAmsiServer."
        $PSAmsiScanResultObj = [PSCustomObject] @{ PSAmsiScanResults = $PSAmsiScanResults; CachedAmsiScanResults = $PSAmsiScanner.ScanCache }
    }
    Else {
        $PSAmsiScanResultObj = [PSCustomObject] @{ PSAmsiScanResults = $PSAmsiScanResults; CachedAmsiScanResults = @{} }
    }

    # We can now dispose the PSAmsiScanner object, if we created it
    If ($CreatedPSAmsiScanner) {
        $PSAmsiScanner.Dispose()
    }

    # Convert the results to JSON and POST them back to the PSAmsiServer
    $JsonString = $PSAmsiScanResultObj | ConvertTo-Json -Depth 4 -Compress
    $Response = Invoke-RestMethod -Method Post -Uri $ServerUri -Body $JsonString -TimeoutSec 0
}