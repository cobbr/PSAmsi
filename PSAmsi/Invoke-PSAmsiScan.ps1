function Invoke-PSAmsiScan {
    <#

    .SYNOPSIS

    Conducts a PSAmsiScan on a given script.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: New-PSAmsiScanner, Find-AmsiSignatures, Out-MinimallyObfuscated
    Optional Dependencies: none

    .DESCRIPTION

    Invoke-PSAmsiScan conducts a PSAmsiScan on a given script, and optionally provides the AMSI signatures
    within the script and/or a minimally obfuscated copy of the script that is no longer flagged by AMSI.

    .PARAMETER ScriptString

    The string containing the script to be scanned.

    .PARAMETER ScriptBlock

    The ScriptBlock containing the script to be scanned.

    .PARAMETER ScriptPath

    The Path to the script to be scanned.

    .PARAMETER ScriptUri

    The URI of the script to be scanned.

    .PARAMETER ScriptName

    The name of the script to be scanned.

    .PARAMETER AlertLimit

    Specifies the maximum amount of AMSI alerts this scan is allowed to generate.

    .PARAMETER Delay

    Specifies the amount of time (in seconds) to wait between AMSI alerts.

    .PARAMETER PSAmsiScanner

    Specifies the PSAmsiScanner to use for AMSI scans.

    .PARAMETER FindAmsiSignatures

    Specifies that the PSAmsiScan should find and return the AMSI signatures found in the script
    in addition to the result of the scan.

    .PARAMETER GetMinimallyObfuscated

    Specifies that the PSAmsiScan should minimally obfuscate the script until it is
    no longer flagged by AMSI.

    .OUTPUTS

    PSCustomObject

    .EXAMPLE

    Invoke-PSAmsiScan -ScriptString "Write-Host test"

    .EXAMPLE

    Invoke-PSAmsiScan -ScriptString "Write-Host test" -FindAmsiSignatures  -AlertLimit 15 -Delay 3

    .EXAMPLE

    Invoke-PSAmsiScan -ScriptString "Write-Host test" -GetMinimallyObfuscated

    .NOTES

    Invoke-PSAmsiScan is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    [CmdletBinding(DefaultParameterSetName = "ByString")] Param(
        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptName,

        [Parameter(Position = 2)]
        [ValidateRange(0,[Int]::MaxValue)]
        [Int] $AlertLimit = 0,

        [Parameter(Position = 3)]
        [ValidateRange(0,[Int]::MaxValue)]
        [Int] $Delay = 0,

        [Parameter(Position = 4)]
        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner,

        [Switch] $FindAmsiSignatures,

        [Switch] $GetMinimallyObfuscated,

        [Switch] $IncludeStatus
    )
    Begin {
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            # Create a PSAmsiScanner
            $PSAmsiScanner = New-PSAmsiScanner -AlertLimit $AlertLimit -Delay $Delay
            $CreatedPSAmsiScanner = $True
        }
        Else {
            If ($AlertLimit -gt 0) {
                $PSAmsiScanner.AlertLimit = $AlertLimit
                $PSAmsiScanner.AlertLimitEnabled = $True
            }
            $PSAmsiScanner.Delay = $Delay
        }
    }

    Process {
        If ($ScriptBlock) { $ScriptString = $ScriptBlock -as [String] }
        ElseIf ($ScriptPath) { $ScriptString = Get-Content -Path $ScriptPath -Raw }
        ElseIf ($ScriptUri) { $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri) }

        # Scan the given ScriptString
        $ScriptIsFlagged = Test-ContainsAmsiSignatures -ScriptString $ScriptString -PSAmsiScanner $PSAmsiScanner
        $PSAmsiScanResult = [PSCustomObject] @{ ScriptIsFlagged = $ScriptIsFlagged } 
        If ($FindAmsiSignatures) {
            $AmsiSignatures = @()
            If ($ScriptIsFlagged) {
                Write-Verbose "[Invoke-PSAmsiScan] Finding Amsi Signatures in the Script."
                $AmsiSignatures = Find-AmsiSignatures -ScriptString $ScriptString -PSAmsiScanner $PSAmsiScanner
                # Use Find-AmsiSignatures to retreive the exact strings flagged by AMSI
                Write-Verbose "[Invoke-PSAmsiScan] Found $($AmsiSignatures.Count) Amsi Signatures in the Script."
            }
            $PSAmsiScanResult | Add-Member -Name 'AmsiSignatures' -Value $AmsiSignatures -MemberType NoteProperty
        }
        If ($GetMinimallyObfuscated) {
            Write-Verbose "[Invoke-PSAmsiScan] Getting MinimallyObfuscated copy of Script"
            # Use Get-MinimallyObfuscated to retrieve a minimally obfuscated copy of the ScriptString
            # that is not flagged by AMSI
            $MinimallyObfuscated = $ScriptString
            If ($ScanResult -and (-not $PSAmsiScanner.AlertLimitReached)) {
                If ($AmsiSignatures) {
                    $MinimallyObfuscated = Get-MinimallyObfuscated -ScriptString $ScriptString -AmsiSignatures $AmsiSignatures -PSAmsiScanner $PSAmsiScanner
                } Else {
                    $MinimallyObfuscated = Get-MinimallyObfuscated -ScriptString $ScriptString -PSAmsiScanner $PSAmsiScanner
                }
            }
            $PSAmsiScanResult | Add-Member -Name 'MinimallyObfuscated' -Value $MinimallyObfuscated -MemberType NoteProperty
        }
        
        If ($IncludeStatus -or $PSAmsiScanner.AlertLimitEnabled) {
            If ($PSAmsiScanner.AlertLimitReached) {
                Write-Verbose "[Invoke-PSAmsiScan] AlertLimit reached during execution. Reporting scan as not completed."
            }
            $PSAmsiScanResult | Add-Member -Name 'RequestCompleted' -Value (-not $PSAmsiScanner.AlertLimitReached) -MemberType NoteProperty
        }
        If ($ScriptName) {
            $PSAmsiScanResult | Add-Member -Name 'ScriptName' -Value $ScriptName -MemberType NoteProperty
        }
        $PSAmsiScanResult
    }

    End {
        # Dispose the PSAmsiScanner when done, if it was created within this function
        If ($CreatedPSAmsiScanner) {
            $PSAmsiScanner.Dispose()
        }
    }
}