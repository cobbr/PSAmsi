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

function Find-AmsiSignatures {
    <#

    .SYNOPSIS

    Finds the AMSI signatures within a script that are flagged as malware by AMSI.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: New-PSAmsiScanner, Find-AmsiAstSignatures, Find-AmsiPSTokenSignatures

    .DESCRIPTION

    Find-AmsiSignatures finds the AMSI signatures within a script that are flagged as malware
    by the current AMSI AntiMalware Provider.

    .PARAMETER AbstractSyntaxTree

    Specifies the root Ast of an AbstractSyntaxTree that represents the script to get AMSI
    signatures from.

    .PARAMETER PSTokens

    Specifies the PSTokens that represents the script to get AMSI signatures from.

    .PARAMETER ScriptString

    Specifies the string containing the script to get AMSI signatures from.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing the script to get AMSI signatures from.

    .PARAMETER ScriptPath

    Specifies the Path to the script to get AMSI signatures from.

    .PARAMETER ScriptUri

    Specifies the URI of the script to get AMSI signatures from.

    .PARAMETER PSAmsiScanner

    Specifies the PSAmsiScanner to use to scan for finding AMSI signatures.

    .OUTPUTS

    String[]

    .EXAMPLE

    Find-AmsiSignatures "Write-Host example"

    Find-AmsiSignatures $AST $PSTokens

    @('Write-Host example1', 'Write-Host example2', 'Write-Host example3') | Find-AmsiSignatures

    .NOTES

    Find-AmsiSignatures is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    [CmdletBinding(DefaultParameterSetName = "ByString")] Param(
        [Parameter(ParameterSetName = "ByComponents", Position = 0, Mandatory)]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree,

        [Parameter(ParameterSetName = "ByComponents", Position = 1, Mandatory)]
        [System.Management.Automation.PSToken[]] $PSTokens,

        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri,

        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner
    )
    Begin {
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            $PSAmsiScanner = New-PSAmsiScanner
            $CreatedPSAmsiScanner = $True
        }
    }
    Process {
        If ($ScriptString) {
            $AmsiFlaggedAsts = Find-AmsiAstSignatures -ScriptString $ScriptString -PSAmsiScanner $PSAmsiScanner
            $AmsiFlaggedCommentTokens = Find-AmsiPSTokenSignatures -ScriptString $ScriptString -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        } ElseIf ($ScriptBlock) {
            $AmsiFlaggedAsts = Find-AmsiAstSignatures -ScriptBlock $ScriptBlock -PSAmsiScanner $PSAmsiScanner
            $AmsiFlaggedCommentTokens = Find-AmsiPSTokenSignatures -ScriptBlock $ScriptBlock -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        } ElseIf ($ScriptPath) {
            $AmsiFlaggedAsts = Find-AmsiAstSignatures -ScriptPath $ScriptPath -PSAmsiScanner $PSAmsiScanner
            $AmsiFlaggedCommentTokens = Find-AmsiPSTokenSignatures -ScriptPath $ScriptPath -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        } ElseIf ($ScriptUri) {
            $AmsiFlaggedAsts = Find-AmsiAstSignatures -ScriptUri $ScriptUri -PSAmsiScanner $PSAmsiScanner
            $AmsiFlaggedCommentTokens = Find-AmsiPSTokenSignatures -ScriptUri $ScriptUri -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        } ElseIf ($AbstractSyntaxTree -and $PSTokens) {
            $AmsiFlaggedAsts = Find-AmsiAstSignatures -AbstractSyntaxTree $AbstractSyntaxTree -PSAmsiScanner $PSAmsiScanner
            $AmsiFlaggedCommentTokens = Find-AmsiPSTokenSignatures -PSTokens $PSTokens -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        }

        # Create objects with the flagged string and it's position within the script
        $AmsiFlaggedObjs = $AmsiFlaggedAsts | % { [PSCustomObject] @{ Content = $_.Extent.Text; Position = $_.Extent.StartOffset } }
        $AmsiFlaggedObjs += $AmsiFlaggedCommentTokens | % { [PSCustomObject] @{ Content = $_.Content; Position = $_.Start } }

        # Sort the flagged strings by length, to make de-duplication easier
        $AmsiFlaggedObjs = $AmsiFlaggedObjs | Sort-Object { $_.Content.Length }

        # Add strings to array one at a time, only adding if the new string
        # is not contained by a string already present in array.
        # TODO possibly make this better by finding parent asts and eliminating. And tokens don't really need this treatment, right?
        $NonDuplicates = @()
        ForEach ($AmsiFlaggedObj in $AmsiFlaggedObjs) {
            $Duplicates = $NonDuplicates | ? { $AmsiFlaggedObj.Content.Contains($_.Content) }
            If ($Duplicates.Count -eq 0) {
                $NonDuplicates += $AmsiFlaggedObj
            }
        }

        # Sort by descending position in ScriptString, to make obfuscation easier
        $NonDuplicates | Sort-Object -Descending { $_.Position} | % { $_.Content }
    }
    End {
        If ($CreatedPSAmsiScanner) {
            $PSAmsiScanner.Dispose()
        }
    }
}

function Test-ContainsAmsiSignatures {
    <#

    .SYNOPSIS

    Tests if any AMSI signatures are contained in a given script.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Test-ContainsAmsiAstSignatures, Test-ContainsAmsiPSTokenSignatures
    Optional Dependencies: New-PSAmsiScanner

    .DESCRIPTION

    Test-ContainsAmsiSignatures tests if any AMSI signatures are contained in a given script. This function
    is much quicker than a full Find-AmsiSignatures search.

    .PARAMETER AbstractSyntaxTree

    Specifies the root Ast of an AbstractSyntaxTree that represents the script to get AMSI
    signatures from.

    .PARAMETER PSTokens

    Specifies the PSTokens that represents the script to get AMSI signatures from.

    .PARAMETER ScriptString

    Specifies the string containing the script to get AMSI signatures from.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing the script to get AMSI signatures from.

    .PARAMETER ScriptPath

    Specifies the Path to the script to get AMSI signatures from.

    .PARAMETER ScriptUri

    Specifies the URI of the script to get AMSI signatures from.

    .PARAMETER PSAmsiScanner

    Specifies the PSAmsiScanner to use to scan for finding AMSI signatures.

    .OUTPUTS

    String[]

    .EXAMPLE

    Test-ContainsAmsiSignatures "Write-Host example"

    Test-ContainsAmsiSignatures $AST $PSTokens

    @('Write-Host example1', 'Write-Host example2', 'Write-Host example3') | Test-ContainsAmsiSignatures

    .NOTES

    Test-ContainsAmsiSignatures is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    [CmdletBinding(DefaultParameterSetName = "ByString")] Param(
        [Parameter(ParameterSetName = "ByComponents", Position = 0, Mandatory)]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree,

        [Parameter(ParameterSetName = "ByComponents", Position = 1, Mandatory)]
        [System.Management.Automation.PSToken[]] $PSTokens,

        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri,

        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner
    )
    Begin {
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            $PSAmsiScanner = New-PSAmsiScanner
            $CreatedPSAmsiScanner = $True
        }
    }
    Process {
        If ($ScriptBlock) { $ScriptString = $ScriptBlock -as [String] }
        ElseIf ($ScriptPath) { $ScriptString = Get-Content -Path $ScriptPath -Raw }
        ElseIf ($ScriptUri) { $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri) }

        $ContainsAstSignatures = Test-ContainsAmsiAstSignatures -ScriptString $ScriptString -PSAmsiScanner $PSAmsiScanner
        If ($ContainsAstSignatures) { $True }
        Else {
            $ContainsPSTokenSignatures = Test-ContainsAmsiPSTokenSignatures -ScriptString $ScriptString -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
            If ($ContainsPSTokenSignatures) { $True }
            Else { $False }
        }
    }
    End {
        If ($CreatedPSAmsiScanner) {
            $PSAmsiScanner.Dispose()
        }
    }
}

function Find-AmsiAstSignatures {
    <#

    .SYNOPSIS

    Finds the Asts that contain AMSI signatures within an AbstractSyntaxTree.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: New-PSAmsiScanner, Get-Ast

    .DESCRIPTION

    Find-AmsiAstSignatures finds the Asts that contain AMSI signatures within an AbstactSyntaxTree.

    .PARAMETER AbstractSyntaxTree

    Specifies the root Ast that represents the script to find Asts that contain AMSI signatures.

    .PARAMETER ScriptString

    Specifies the string containing the script to find Asts that contain AMSI signatures.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing the script to find Asts that contain AMSI signatures.

    .PARAMETER ScriptPath

    Specifies the Path containing the script to find Asts that contain AMSI signatures.

    .PARAMETER ScriptUri

    Specifies the Uri of the script to find Asts that contain AMSI signatures.

    .PARAMETER PSAmsiScanner

    Specifies the PSAmsiScanner to use to scan to find Asts that contain AMSI signatures.

    .OUTPUTS

    System.Management.Automation.Language.Ast[]

    .EXAMPLE

    Find-AmsiAstSignatures -Ast $AbstractSyntaxTree

    .EXAMPLE

    Find-AmsiAstSignatures "Write-Host example"

    .EXAMPLE

    Find-AmsiAstSignatures { Write-Host example }

    .EXAMPLE

    Find-AmsiAstSignatures -ScriptPath $ScriptPath

    .EXAMPLE

    @($Ast1, $Ast2, $Ast3) | Find-AmsiAstSignatures

    .EXAMPLE

    Get-ChildItem /path/to/scripts -Recurse -Include *.ps1 | Find-AmsiAstSignatures

    .EXAMPLE

    @('Write-Host example1', 'Write-Host example2', 'Write-Host example3') | Find-AmsiAstSignatures

    .EXAMPLE
    
    @({ Write-Host example1 }, { Write-Host example2 }, { Write-Host example3 }) | Find-AmsiAstSignatures

    .NOTES

    Find-AmsiAstSignatures is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    [CmdletBinding(DefaultParameterSetName="ByString")] Param(
        [Parameter(ParameterSetName="ByAst", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree,

        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri,

        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner
    )
    Begin {
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            $PSAmsiScanner = New-PSAmsiScanner
            $CreatedPSAmsiScanner = $True
        }
    }

    Process {
        # Get the Ast object, if given a different ParameterSetName
        If ($ScriptString) { $AbstractSyntaxTree = Get-Ast -ScriptString $ScriptString }
        ElseIf ($ScriptBlock) { $AbstractSyntaxTree = Get-Ast -ScriptBlock $ScriptBlock }
        ElseIf ($ScriptPath) { $AbstractSyntaxTree = Get-Ast -ScriptPath $ScriptPath }
        ElseIf ($ScriptUri) { $AbstractSyntaxTree = Get-Ast -ScriptUri $ScriptUri }
        
        $AbstractSyntaxTree.FindAll(
        {
            param($ast) (
                # This Ast has text
                ($ast.Extent.Text) -and
                # And it is flagged by AMSI
                ($PSAmsiScanner.GetPSAmsiScanResult($ast.Extent.Text))
            )
        }, $True)
    }
    End {
        If ($CreatedPSAmsiScanner) {
            $PSAmsiScanner.Dispose()
        }
    }
}

function Test-ContainsAmsiAstSignatures {
    <#

    .SYNOPSIS

    Tests if any Ast AMSI signatures are contained within an AbstractSyntaxTree.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: New-PSAmsiScanner, Get-Ast

    .DESCRIPTION

    Test-ContainsAmsiAstSignatures tests if any Ast AMSI signatures are contained within an AbstractSyntaxTree.
    This function is much quicker than a full Find-AmsiAstSignatures search.

    .PARAMETER AbstractSyntaxTree

    Specifies the root Ast that represents the script to find Asts that contain AMSI signatures.

    .PARAMETER ScriptString

    Specifies the string containing the script to find Asts that contain AMSI signatures.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing the script to find Asts that contain AMSI signatures.

    .PARAMETER ScriptPath

    Specifies the Path containing the script to find Asts that contain AMSI signatures.

    .PARAMETER ScriptUri

    Specifies the Uri of the script to find Asts that contain AMSI signatures.

    .PARAMETER PSAmsiScanner

    Specifies the PSAmsiScanner to use to scan to find Asts that contain AMSI signatures.

    .OUTPUTS

    System.Management.Automation.Language.Ast[]

    .EXAMPLE

    Test-ContainsAmsiAstSignatures -Ast $AbstractSyntaxTree

    .EXAMPLE

    Test-ContainsAmsiAstSignatures "Write-Host example"

    .EXAMPLE

    Test-ContainsAmsiAstSignatures { Write-Host example }

    .EXAMPLE

    Test-ContainsAmsiAstSignatures -ScriptPath $ScriptPath

    .EXAMPLE

    @($Ast1, $Ast2, $Ast3) | Test-ContainsAmsiAstSignatures

    .EXAMPLE

    Get-ChildItem /path/to/scripts -Recurse -Include *.ps1 | Test-ContainsAmsiAstSignatures

    .EXAMPLE

    @('Write-Host example1', 'Write-Host example2', 'Write-Host example3') | Test-ContainsAmsiAstSignatures

    .EXAMPLE
    
    @({ Write-Host example1 }, { Write-Host example2 }, { Write-Host example3 }) | Test-ContainsAmsiAstSignatures

    .NOTES

    Test-ContainsAmsiAstSignatures is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    [CmdletBinding(DefaultParameterSetName="ByString")] Param(
        [Parameter(ParameterSetName="ByAst", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree,

        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri,

        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner
    )
    Begin {
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            $PSAmsiScanner = New-PSAmsiScanner
            $CreatedPSAmsiScanner = $True
        }
    }

    Process {
        # Get the Ast object, if given a different ParameterSetName
        If ($ScriptString) { $AbstractSyntaxTree = Get-Ast -ScriptString $ScriptString }
        ElseIf ($ScriptBlock) { $AbstractSyntaxTree = Get-Ast -ScriptBlock $ScriptBlock }
        ElseIf ($ScriptPath) { $AbstractSyntaxTree = Get-Ast -ScriptPath $ScriptPath }
        ElseIf ($ScriptUri) { $AbstractSyntaxTree = Get-Ast -ScriptUri $ScriptUri }

        # Use the Find function to find first matching ScriptBlockAst flagged by AMSI
        $FirstFlagged = $AbstractSyntaxTree.Find(
        {
            param($ast) (
                $ast -is [System.Management.Automation.Language.ScriptBlockAst] -AND
                # This Ast has text
                ($ast.Extent.Text) -AND
                # And it is flagged by AMSI
                ($PSAmsiScanner.GetPSAmsiScanResult($ast.Extent.Text))
            )
        }, $True)
        If ($FirstFlagged) { $True }
        Else { $False }
    }
    End {
        If ($CreatedPSAmsiScanner) {
            $PSAmsiScanner.Dispose()
        }
    }
}

function Find-AmsiPSTokenSignatures {
    <#
    .SYNOPSIS

    Finds the PSTokens within a script that contain AMSI signatures that are flagged by AMSI.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: New-PSAmsiScanner, Get-PSTokens

    .DESCRIPTION

    Find-AmsiPSTokenSignatures finds the PSTokens within a script that contain AMSI signatures.

    .PARAMETER PSTokens

    Specifies the list of PSTokens that represent the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER ScriptString

    Specifies the string containing the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER ScriptPath

    Specifies the Path containing the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER ScriptUri

    Specifies the URI of the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER PSAmsiScanner

    Specifies the PSAmsiScanner to use to find PSTokens that contain AMSI signatures.

    .PARAMETER FilterPSTokenTypes

    Specifies to only get PSTokens that have a PSTokenType in the provided list.

    .OUTPUTS

    System.Management.Automation.PSToken[]

    .EXAMPLE

    Find-AmsiPSTokenSignatures -PSTokens $PSTokens -FilterTokenTypes @('Comment', 'String')

    .EXAMPLE

    Find-AmsiPSTokenSignatures "Write-Host example"

    .EXAMPLE

    Find-AmsiPSTokenSignatures { Write-Host example }

    .EXAMPLE

    Find-AmsiPSTokenSignatures -ScriptPath $ScriptPath -FilterPSTokenTypes Comment

    .EXAMPLE

    @($PSTokens1, $PSTokens2, $PSTokens3) | Find-AmsiPSTokenSignatures

    .EXAMPLE

    Get-ChildItem /path/to/scripts -Recurse -Include *.ps1 | Find-AmsiPSTokenSignatures

    .EXAMPLE

    @('Write-Host example1', 'Write-Host example2', 'Write-Host example3') | Find-AmsiPSTokenSignatures

    .EXAMPLE

    @({ Write-Host example1 }, { Write-Host example2 }, { Write-Host example3 }) | Find-AmsiPSTokenSignatures

    .NOTES

    Find-AmsiPSTokenSignatures is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>

    [CmdletBinding(DefaultParameterSetName="ByString")] Param(
        [Parameter(ParameterSetName = "ByPSTokens", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken[]] $PSTokens,

        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri,

        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSTokenType[]] $FilterPSTokenTypes = @('String', 'Member', 'CommandArgument', 'Command', 'Variable', 'Type', 'Comment')
    )
    Begin {
        If (-not $PSAmsiScanner) {
            $PSAmsiScanner = New-PSAmsiScanner
        }
    }

    Process {
        # Get the PSTokens that represent the script, if not provided
        If ($ScriptString) { $PSTokens = Get-PSTokens -ScriptString $ScriptString }
        ElseIf ($ScriptBlock) { $PSTokens = Get-PSTokens -ScriptBlock $ScriptBlock }
        ElseIf ($ScriptPath) { $PSTokens = Get-PSTokens -ScriptPath $ScriptPath }
        ElseIf ($ScriptUri) { $PSTokens = Get-PSTokens -ScriptUri $ScriptUri }

        # Filter given tokens by type, and check if Token content is flagged by AMSI
        $AmsiFlaggedPSTokens = $PSTokens | ? { $_.Type -in $FilterPSTokenTypes } | ? { $PSAmsiScanner.GetPSAmsiScanResult($_.Content) }
        $AmsiFlaggedPSTokens
    }

}

function Test-ContainsAmsiPSTokenSignatures {
    <#
    .SYNOPSIS

    Tests if any PSTokens within a script contain AMSI signatures that are flagged by AMSI.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: New-PSAmsiScanner, Get-PSTokens

    .DESCRIPTION

    Test-ContainsAmsiPSTokenSignatures tests if any PSTokens within a script contain AMSI signatures that are flagged by AMSI.
    This function is much quicker than a full Find-AmsiPSTokenSignatures search.

    .PARAMETER PSTokens

    Specifies the list of PSTokens that represent the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER ScriptString

    Specifies the string containing the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER ScriptPath

    Specifies the Path containing the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER ScriptUri

    Specifies the URI of the script to find PSTokens from that contain AMSI signatures.

    .PARAMETER PSAmsiScanner

    Specifies the PSAmsiScanner to use to find PSTokens that contain AMSI signatures.

    .PARAMETER FilterPSTokenTypes

    Specifies to only get PSTokens that have a PSTokenType in the provided list.

    .OUTPUTS

    System.Management.Automation.PSToken[]

    .EXAMPLE

    Test-ContainsAmsiPSTokenSignatures -PSTokens $PSTokens -FilterTokenTypes @('Comment', 'String')

    .EXAMPLE

    Test-ContainsAmsiPSTokenSignatures "Write-Host example"

    .EXAMPLE

    Test-ContainsAmsiPSTokenSignatures { Write-Host example }

    .EXAMPLE

    Test-ContainsAmsiPSTokenSignatures -ScriptPath $ScriptPath -FilterPSTokenTypes Comment

    .EXAMPLE

    @($PSTokens1, $PSTokens2, $PSTokens3) | Test-ContainsAmsiPSTokenSignatures

    .EXAMPLE

    Get-ChildItem /path/to/scripts -Recurse -Include *.ps1 | Test-ContainsAmsiPSTokenSignatures

    .EXAMPLE

    @('Write-Host example1', 'Write-Host example2', 'Write-Host example3') | Test-ContainsAmsiPSTokenSignatures

    .EXAMPLE

    @({ Write-Host example1 }, { Write-Host example2 }, { Write-Host example3 }) | Test-ContainsAmsiPSTokenSignatures

    .NOTES

    Test-ContainsAmsiPSTokenSignatures is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>

    [CmdletBinding(DefaultParameterSetName="ByString")] Param(
        [Parameter(ParameterSetName = "ByPSTokens", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken[]] $PSTokens,

        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri,

        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSTokenType[]] $FilterPSTokenTypes = @('String', 'Member', 'CommandArgument', 'Command', 'Variable', 'Type', 'Comment')
    )
    Begin {
        If (-not $PSAmsiScanner) {
            $PSAmsiScanner = New-PSAmsiScanner
        }
    }

    Process {
        # Get the PSTokens that represent the script, if not provided
        If ($ScriptString) { $PSTokens = Get-PSTokens -ScriptString $ScriptString }
        ElseIf ($ScriptBlock) { $PSTokens = Get-PSTokens -ScriptBlock $ScriptBlock }
        ElseIf ($ScriptPath) { $PSTokens = Get-PSTokens -ScriptPath $ScriptPath }
        ElseIf ($ScriptUri) { $PSTokens = Get-PSTokens -ScriptUri $ScriptUri }

        # Filter given tokens by type, and check if Token content is flagged by AMSI
        $AmsiFlaggedPSTokens = $PSTokens | ? { $_.Type -in $FilterPSTokenTypes } | % { 
            $Result = $PSAmsiScanner.GetPSAmsiScanResult($_.Content)
            If ($Result) {
                $True
                break
            }
        }
    }

}

function Get-Ast {
    <#

    .SYNOPSIS

    Gets the root Ast for a given script.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: none

    .DESCRIPTION

    Get-Ast gets the AbstractSyntaxTree that represents a given script.

    .PARAMETER ScriptString

    Specifies the String containing a script to get the AbstractSyntaxTree of.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing a script to get the AbstractSyntaxTree of.

    .PARAMETER ScriptPath

    Specifies the Path to a file containing the script to get the AbstractSyntaxTree of.

    .PARAMETER ScriptUri

    Specifies the URI of the script to get the AbstractSyntaxTree of.

    .OUTPUTS

    System.Management.Automation.Language.Ast

    .EXAMPLE

    Get-Ast "Write-Host example"

    .EXAMPLE

    Get-Ast {Write-Host example}

    .EXAMPLE

    Get-Ast -ScriptPath Write-Example.ps1

    .EXAMPLE

    Get-ChildItem /path/to/scripts -Recurse -Include *.ps1 | Get-Ast

    .EXAMPLE

    @('Write-Host example1', 'Write-Host example2', 'Write-Host example3') | Get-Ast

    .EXAMPLE

    @({ Write-Host example1 }, { Write-Host example2 }, { Write-Host example3 }) | Get-Ast

    .NOTES

    Get-Ast is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    [CmdletBinding(DefaultParameterSetName = "ByString")] Param(
        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri
    )
    Process {
        If ($ScriptBlock) { $ScriptString = $ScriptBlock -as [String] }
        ElseIf ($ScriptPath) { $ScriptString = Get-Content -Path $ScriptPath -Raw }
        ElseIf ($ScriptUri) { $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri) }

        # Parse script and return root Ast
        [Management.Automation.Language.ParseError[]] $ParseErrors = @()
        $Ast = [Management.Automation.Language.Parser]::ParseInput($ScriptString, $null, [ref] $null, [ref] $ParseErrors)
        $Ast
    }
}

function Get-PSTokens {
    <#

    .SYNOPSIS

    Gets the PSTokens for a given script.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: none

    .DESCRIPTION

    Get-PSTokens gets the PSTokens that represent a given script.

    .PARAMETER ScriptString

    Specifies the String containing a script to get the PSTokens from.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing a script to get the PSTokens from.

    .PARAMETER ScriptPath

    Specifies the Path to a file containing the script to get the PSTokens from.

    .PARAMETER ScriptUri

    Specifies the URI of the script to get the PSTokens from.

    .OUTPUTS

    System.Management.Automation.PSToken[]

    .EXAMPLE

    Get-PSTokens "Write-Host example"

    .EXAMPLE

    Get-PSTokens {Write-Host example}

    .EXAMPLE

    Get-PSTokens -ScriptPath Write-Example.ps1

    .EXAMPLE

    Get-ChildItem /path/to/scripts -Recurse -Include *.ps1 | Get-PSTokens

    .EXAMPLE

    @('Write-Host example1', 'Write-Host example2', 'Write-Host example3') | Get-PSTokens

    .EXAMPLE

    @({ Write-Host example1 }, { Write-Host example2 }, { Write-Host example3 }) | Get-PSTokens

    .NOTES

    Get-PSTokens is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    [CmdletBinding(DefaultParameterSetName = "ByString")] Param(
        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri
    )
    Process {
        If ($ScriptBlock) { $ScriptString = $ScriptBlock -as [String] }
        ElseIf ($ScriptPath) { $ScriptString = Get-Content -Path $ScriptPath -Raw }
        ElseIf ($ScriptUri) { $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri) }

        # Tokenize script and return PSTokens
        [Management.Automation.PSParseError[]] $PSParseErrors = @()
        $PSTokens = [Management.Automation.PSParser]::Tokenize($ScriptString, [ref]$PSParseErrors)
        $PSTokens
    }
}

class PowerShellObfuscator {

    $ObfuscationCache = @{}

    PowerShellObfuscator() {}

    PowerShellObfuscator([HashTable] $ObfuscationCache) {
        $this.ObfuscationCache = $ObfuscationCache
    }

    [String] GetMinimallyObfuscated([String] $ScriptString, [Object] $PSAmsiScanner, [String[]] $AmsiSignatures) {
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            $CreatedPSAmsiScanner = $True
            $PSAmsiScanner = New-PSAmsiScanner
        } ElseIf (-not $PSAmsiScanner.GetType().Name -eq 'PSAmsiScanner') {
            throw "PSAmsiScanner must be of type [PSAmsiScanner]"
        }

        If ($this.ObfuscationCache.Contains($ScriptString)) { return $this.ObfuscationCache[$ScriptString] }

        $PSTokens = Get-PSTokens -ScriptString $ScriptString
        $OriginalScript = $ScriptString

        # Get all the AmsiFlaggedStrings that we must obfuscate, if they were not provided
        If (-not $AmsiSignatures) {
            # No need to get the AbstractSyntaxTree unless we must search for AmsiFlaggedStrings
            $AbstractSyntaxTree = Get-Ast -ScriptString $ScriptString
            $AmsiSignatures = Find-AmsiSignatures -Ast $AbstractSyntaxTree -PSTokens $PSTokens -PSAmsiScanner $PSAmsiScanner
        }

        ForEach($AmsiSignature in $AmsiSignatures) {
            If ($this.ObfuscationCache.Contains($AmsiSignature)) { continue }

            # Reset the ScriptString for each FlaggedString obfuscation iteration, so token indices are correct
            # We will actually replace w/ all obfuscated values at the end
            $ScriptString = $OriginalScript
            $ObfuscationSuccessful = $False
            $ObfuscationLevel = 0
            # Iterate obuscation levels until obfuscation succeeds
            While ((-not $ObfuscationSuccessful) -and ($ObfuscationLevel -lt 4)) {
                
                $ObfuscationLevel++
                
                $MatchingTokenArrays = Get-MatchingPSTokens -SearchString $OriginalScript -SignatureString $AmsiSignature -PSTokens $PSTokens
                
                # If no matching tokens are found, skip obfuscation
                If (-not $MatchingTokenArrays) { break }
                
                ForEach ($MatchingTokenArray in $MatchingTokenArrays) {
                    # If obfuscation already found for this string, skip it
                    If ($this.ObfuscationCache.Contains($MatchingTokenArray.MatchingString)) { continue }

                    $MatchingTokens = $MatchingTokenArray.MatchingTokens
                    
                    $DoneObfuscating = $False
                    $TokenIndex = 0
                    # Obfuscate the tokens until the string is no longer flagged
                    While (-not $DoneObfuscating) {
                        $MatchingToken = $MatchingTokens[$TokenIndex]
                    
                        If ($MatchingToken.Type -eq 'Comment') {
                            $this.ObfuscationCache[$MatchingTokenArray.MatchingString] = ""
                            $DoneObfuscating = $True
                            $ObfuscationSuccessful = $True
                        }
                        # Only obfuscate the following token types
                        ElseIf ($MatchingToken.Type -in @('String', 'Member', 'CommandArgument', 'Command', 'Variable')) {
                            $ScriptString = Out-ObfuscatedPSToken -ScriptString $ScriptString -PSTokens $MatchingTokens -Index $TokenIndex -ObfuscationLevel $ObfuscationLevel
                            
                            # Calculate the replacement string for the current AmsiFlaggedString, based on current obfuscation
                            $ReplacementString = $ScriptString.Substring($MatchingTokenArray.StartIndex, $MatchingTokenArray.Length + ($ScriptString.Length - $OriginalScript.Length))
                            # Check if this current replacement string is still flagged
                            If (-not (Get-PSAmsiScanResult -ScriptString $ReplacementString -PSAmsiScanner $PSAmsiScanner)) {
                                # Done obfuscating if the resulting string is no longer flagged
                                $DoneObfuscating = $True
                                $ObfuscationSuccessful = $True
                                $this.ObfuscationCache[$MatchingTokenArray.MatchingString] = $ReplacementString
                            }
                        }
                        # If we've run through all the strings and the string is still flagged, obfuscation fails
                        If (($TokenIndex -ge ($MatchingTokens.Count-1))) { $DoneObfuscating = $True }
                    
                        Else { $TokenIndex++ }
                    }
                }
            }
        }

        $this.ObfuscationCache.Keys | % {
            # Replace all the strings at the end
            $ScriptString = $ScriptString.Replace($_, $this.ObfuscationCache[$_])
        }

        If ($CreatedPSAmsiScanner) {
            $PSAmsiScanner.Dispose()
        }
        $this.ObfuscationCache[$OriginalScript] = $ScriptString
        return $ScriptString
    }

    [String] GetMinimallyObfuscated([String] $ScriptString, [Object] $PSAmsiScanner) {
        return $this.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner, $null)
    }

    [String] GetMinimallyObfuscated([String] $ScriptString) {
        return $this.GetMinimallyObfuscated($ScriptString, $null, $null)
    }

    [String] GetMinimallyObfuscated([ScriptBlock] $ScriptBlock, [Object] $PSAmsiScanner, [String[]] $AmsiSignatures) {
        $ScriptString = $ScriptBlock -as [String]
        return $this.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner, $AmsiSignatures)
    }

    [String] GetMinimallyObfuscated([ScriptBlock] $ScriptBlock, [Object] $PSAmsiScanner) {
        return $this.GetMinimallyObfuscated($ScriptBlock, $PSAmsiScanner, $null)
    }

    [String] GetMinimallyObfuscated([ScriptBlock] $ScriptBlock) {
        return $this.GetMinimallyObfuscated($ScriptBlock, $null, $null)
    }

    [String] GetMinimallyObfuscated([IO.FileInfo] $ScriptPath, [Object] $PSAmsiScanner, [String[]] $AmsiSignatures) {
        $ScriptString = Get-Content $ScriptPath -Raw
        return $this.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner, $AmsiSignatures)
    }

    [String] GetMinimallyObfuscated([IO.FileInfo] $ScriptPath, [Object] $PSAmsiScanner) {
        return $this.GetMinimallyObfuscated($ScriptPath, $PSAmsiScanner, $null)
    }

    [String] GetMinimallyObfuscated([IO.FileInfo] $ScriptPath) {
        return $this.GetMinimallyObfuscated($ScriptPath, $null, $null)
    }

    [String] GetMinimallyObfuscated([Uri] $ScriptUri, [Object] $PSAmsiScanner, [String[]] $AmsiSignatures) {
        $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri)
        return $this.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner, $AmsiSignatures)
    }

    [String] GetMinimallyObfuscated([Uri] $ScriptUri, [Object] $PSAmsiScanner) {
        return $this.GetMinimallyObfuscated($ScriptUri, $PSAmsiScanner, $null)
    }

    [String] GetMinimallyObfuscated([Uri] $ScriptUri) {
        $ScriptString = (Invoke-WebRequest $ScriptUri).Content
        return $this.GetMinimallyObfuscated($ScriptString, $null, $null)
    }
}

function Get-MatchingPSTokens {
    <#

    .SYNOPSIS

    Gets the PSTokens from a script that contains a portion of an AMSI signature.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: none

    .DESCRIPTION

    Get-MatchingPSTokens gets the tokens from a script that contains a portion of an AMSI signature.

    .PARAMETER SearchString

    The string containing the script to search for the AMSI signature.

    .PARAMETER SignatureString

    The string containing the AMSI signature to search for in the SearchString.

    .PARAMETER PSTokens

    The PSTokens that make up the SearchString script.

    .OUTPUTS

    PSCustomObject

    .EXAMPLE

    $AmsiSignatures = Find-AmsiSignatures -ScriptString $ScriptString
    Get-MatchingPSTokens -SearchString $ScriptString -SignatureString $AmsiSignatures[0] -PSTokens (Get-PSTokens -ScriptString $ScriptString)

    .NOTES

    Get-MatchingPSTokens is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    [CmdletBinding()] Param (
        [String] $SearchString,
        [String] $SignatureString,
        [System.Management.Automation.PSToken[]] $PSTokens
    )
    $MinIndex = $SearchString.IndexOf($SignatureString)

    While ($MinIndex -ne -1) {
        $MaxIndex = $MinIndex + $SignatureString.Length
        $MatchingTokens = $PSTokens | ? {
            $StartIndex = $_.Start
            $EndIndex = $_.Start + $_.Length
            If ($StartIndex -ge $MinIndex -AND $EndIndex -le $MaxIndex) { $True }
            ElseIf ($EndIndex -ge $MinIndex -AND $EndIndex -le $MaxIndex) { $True }
            ElseIf ($StartIndex -ge $MinIndex -AND $StartIndex -le $MaxIndex) { $True }
            ElseIf ($StartIndex -le $MinIndex -AND $EndIndex -ge $MaxIndex) { $True }
        }
        If ($MatchingTokens.Count -gt 1) {
            $Start = $MatchingTokens[0].Start
            $Length = $MatchingTokens[$MatchingTokens.Count-1].Start + $MatchingTokens[$MatchingTokens.Count-1].Length - $Start
            $MatchingString = $SearchString.Substring($Start, $Length)
            [PSCustomObject] @{ MatchingTokens = ($MatchingTokens | Sort-Object -Descending { $_.Start }); MatchingString = $MatchingString; StartIndex = $Start; Length = $Length}
        } ElseIf ($MatchingTokens.Count -eq 1) {
            [PSCustomObject] @{ MatchingTokens = $MatchingTokens; MatchingString = $SearchString.Substring($MatchingTokens.Start, $MatchingTokens.Length); StartIndex = $MatchingTokens.Start; Length = $MatchingTokens.Length }
        }
        $MinIndex = $SearchString.IndexOf($SignatureString, $MinIndex+1)
    }
}

function Out-ObfuscatedPSToken {
     <#
        .SYNOPSIS

        Obfuscates a single PSToken within a script.

        Author: Daniel Bohannon (@danielhbohannon)
        Modified By: Ryan Cobb (@cobbr_io)
        License: Apache License, Version 2.0
        Required Dependencies: none
        Optional Dependencies: Out-ObfuscatedStringTokenLevel1, Out-RandomCaseToken, Out-ObfuscatedWithTicks,
                               Out-ObfuscatedMemberTokenLevel3, Out-ObfuscatedCommandArgumentTokenLevel3,
                               Out-ObfuscatedCommandTokenLevel2, Out-ObfuscatedVariableTokenLevel1, Out-ObfuscatedTypeToken,
                               Out-RemoveComments

        .DESCRIPTION

        Out-ObfuscatedPSToken obfuscates a specified token within a script and returns
        the resulting script.

        .PARAMETER ScriptString

        The ScriptString that contains the token to be obfuscated.

        .PARAMETER PSTokens

        The set of PSTokens that represents the given ScriptString.

        .PARAMETER Index

        The index of the specified token to be obfuscated within the PSTokens array.

        .OUTPUTS

        String

        .EXAMPLE
        
        Out-ObfuscatedPSToken -ScriptString "Write-Host example" -PSTokens $(Get-PSTokens "Write-Host example") -Index 2

        .NOTES

        Out-ObfuscatedPSToken is a modified version of the original Out-ObfuscatedTokenCommand function included in
        Invoke-Obfuscation. The original description of Out-ObfuscatedTokenCommand is as follows:
        Out-ObfuscatedTokenCommand orchestrates the tokenization and application of all token-based obfuscation functions to provided PowerShell script and places obfuscated tokens back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. If no $TokenTypeToObfuscate is defined then Out-ObfuscatedTokenCommand will automatically perform ALL token obfuscation functions in random order at the highest obfuscation level.
        This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

        .LINK

        http://www.danielbohannon.com

    #>
    param(
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken[]] $PSTokens,

        [Parameter(Position = 2, Mandatory)]
        [ValidateRange(0, [Int]::MaxValue)]
        [Int] $Index,

        [Parameter(Position = 3)]
        [ValidateRange(1, 4)]
        [Int] $ObfuscationLevel = 1

    )
    $PSToken = $PSTokens[$Index]
    If (($PSToken.Type -eq 'String')) {
        # If String $Token immediately follows a period (and does not begin $ScriptString) then do not obfuscate as a String.
        # In this scenario $Token is originally a Member token that has quotes added to it.
        # E.g. both InvokeCommand and InvokeScript in $ExecutionContext.InvokeCommand.InvokeScript
        If (($PSToken.Start -gt 0) -AND ($ScriptString.SubString($PSToken.Start-1,1) -eq '.')) {
            Continue
        }
            
        # Set valid obfuscation levels for current token type.
        $ValidObfuscationLevels = @(1,2)

        # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
        If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 

        # The below Parameter Binding Validation Attributes cannot have their string values formatted with the -f format operator unless treated as a scriptblock.
        # When we find strings following these Parameter Binding Validation Attributes then if we are using a -f format operator we will treat the result as a scriptblock.
        # Source: https://technet.microsoft.com/en-us/library/hh847743.aspx
        $ParameterValidationAttributesToTreatStringAsScriptblock  = @()
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'alias'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'allownull'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'allowemptystring'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'allowemptycollection'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatecount'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatelength'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatepattern'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'validaterange'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatescript'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'validateset'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatenotnull'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatenotnullorempty'

        $ParameterValidationAttributesToTreatStringAsScriptblock += 'helpmessage'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'confirmimpact'
        $ParameterValidationAttributesToTreatStringAsScriptblock += 'outputtype'

        Switch ($ObfuscationLevel) {
            1 {$ScriptString = Out-ObfuscatedStringTokenLevel1 $ScriptString $PSToken 1}
            2 {$ScriptString = Out-ObfuscatedStringTokenLevel1 $ScriptString $PSToken 2}
        }

    }
    ElseIf ($PSToken.Type -eq 'Member') {
        # Set valid obfuscation levels for current token type.
        $ValidObfuscationLevels = @(1,2,3,4)
            
        # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
        If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}

        # The below Parameter Attributes cannot be obfuscated like other Member Tokens, so we will only randomize the case of these tokens.
        # Source 1: https://technet.microsoft.com/en-us/library/hh847743.aspx
        $MemberTokensToOnlyRandomCase  = @()
        $MemberTokensToOnlyRandomCase += 'mandatory'
        $MemberTokensToOnlyRandomCase += 'position'
        $MemberTokensToOnlyRandomCase += 'parametersetname'
        $MemberTokensToOnlyRandomCase += 'valuefrompipeline'
        $MemberTokensToOnlyRandomCase += 'valuefrompipelinebypropertyname'
        $MemberTokensToOnlyRandomCase += 'valuefromremainingarguments'
        $MemberTokensToOnlyRandomCase += 'helpmessage'
        $MemberTokensToOnlyRandomCase += 'alias'
        # Source 2: https://technet.microsoft.com/en-us/library/hh847872.aspx
        $MemberTokensToOnlyRandomCase += 'confirmimpact'
        $MemberTokensToOnlyRandomCase += 'defaultparametersetname'
        $MemberTokensToOnlyRandomCase += 'helpuri'
        $MemberTokensToOnlyRandomCase += 'supportspaging'
        $MemberTokensToOnlyRandomCase += 'supportsshouldprocess'
        $MemberTokensToOnlyRandomCase += 'positionalbinding'

        $MemberTokensToOnlyRandomCase += 'ignorecase'

        Switch ($ObfuscationLevel) {
            1 {$ScriptString = Out-RandomCaseToken             $ScriptString $PSToken}
            2 {$ScriptString = Out-ObfuscatedWithTicks         $ScriptString $PSToken}
            3 {$ScriptString = Out-ObfuscatedMemberTokenLevel3 $ScriptString $PSTokens $Index 1}
            4 {$ScriptString = Out-ObfuscatedMemberTokenLevel3 $ScriptString $PSTokens $Index 2}
        }
    }
    ElseIf ($PSToken.Type -eq 'CommandArgument') {
        # Set valid obfuscation levels for current token type.
        $ValidObfuscationLevels = @(1,2,3,4)
            
        # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
        If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 

        Switch($ObfuscationLevel)
        {
            1 {$ScriptString = Out-RandomCaseToken                      $ScriptString $PSToken}
            2 {$ScriptString = Out-ObfuscatedWithTicks                  $ScriptString $PSToken}
            3 {$ScriptString = Out-ObfuscatedCommandArgumentTokenLevel3 $ScriptString $PSToken 1}
            4 {$ScriptString = Out-ObfuscatedCommandArgumentTokenLevel3 $ScriptString $PSToken 2}
        }
    }
    ElseIf ($PSToken.Type -eq 'Command') {
        # Set valid obfuscation levels for current token type.
        $ValidObfuscationLevels = @(1,2,3)
            
        # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
        If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}

        # If a variable is encapsulated in curly braces (e.g. ${ExecutionContext}) then the string inside is treated as a Command token.
        # So we will force tick obfuscation (option 1) instead of splatting (option 2) as that would cause errors.
        If(($PSToken.Start -gt 1) -AND ($ScriptString.SubString($PSToken.Start-1,1) -eq '{') -AND ($ScriptString.SubString($PSToken.Start+$PSToken.Length,1) -eq '}')) {
            $ObfuscationLevel = 1
        }
            
        Switch($ObfuscationLevel) {
            1 {$ScriptString = Out-ObfuscatedWithTicks          $ScriptString $PSToken}
            2 {$ScriptString = Out-ObfuscatedCommandTokenLevel2 $ScriptString $PSToken 1}
            3 {$ScriptString = Out-ObfuscatedCommandTokenLevel2 $ScriptString $PSToken 2}
        }
    }
    ElseIf ($PSToken.Type -eq 'Variable') {
        $ScriptString = Out-ObfuscatedVariableTokenLevel1 $ScriptString $PSToken
    }
    ElseIf ($PSToken.Type -eq 'Type') {
        # Set valid obfuscation levels for current token type.
        $ValidObfuscationLevels = @(1,2)
            
        # If invalid obfuscation level is passed to this function then default to lowest obfuscation level available for current token type.
        If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Select-Object -First 1}

        # The below Type value substrings are part of Types that cannot be direct Type casted, so we will not perform direct Type casting on Types containing these values.
        $TypesThatCannotByDirectTypeCasted  = @()
        $TypesThatCannotByDirectTypeCasted += 'directoryservices.accountmanagement.'
        $TypesThatCannotByDirectTypeCasted += 'windows.clipboard'

        Switch ($ObfuscationLevel) {
            1 {$ScriptString = Out-ObfuscatedTypeToken $ScriptString $PSToken 1}
            2 {$ScriptString = Out-ObfuscatedTypeToken $ScriptString $PSToken 2}
        }
    }
    ElseIf ($PSToken.Type -eq 'Comment') {
        $ScriptString = Out-RemoveComments $ScriptString $PSTokens[$Index]
    }

    $ScriptString
}

function New-PowerShellObfuscator {
    <#

    .SYNOPSIS

    Creates a [PowerShellObfuscator] object for obfuscating PowerShell scripts to pass AMSI scans.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PowerShellObfuscator
    Optional Dependencies: none

    .DESCRIPTION

    New-PowerShellObfuscator creates a [PowerShellObfuscator] object for obfuscating PowerShell scripts to pass AMSI scans.

    .PARAMETER ObfuscationCache

    Specify an ObfuscationCache that is a Hastable correlating AMSI signatures to known successful obfuscated version that pass AMSI scans.

    .OUTPUTS

    PowerShellObfuscator

    .EXAMPLE

    $Obfuscator = New-PowerShellObfuscator

    .NOTES

    New-PowerShellObfuscator is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNull()]
        [HashTable] $ObfuscationCache = @{}
    )
    [PowerShellObfuscator]::new($ObfuscationCache)
}

function Get-MinimallyObfuscated {
    <#
    .SYNOPSIS

    Gets a minimally obfuscated copy of a script that passes AMSI scans.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PowerShellObfuscator, New-PowerShellObfuscator
    Optional Dependencies: none

    .DESCRIPTION

    Get-MinimallyObfuscated gets a minimally obfuscated copy of a script that passes AMSI scans.

    .PARAMETER ScriptString

    Specifies the string containing the original script to be minimally obfuscated.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing the original script to be minimally obfuscated.

    .PARAMETER ScriptPath

    Specifies the Path to the original script to be minimally obfuscated.

    .PARAMETER ScriptUri

    The URI of the original script to be minimally obfuscated.

    .PARAMETER AmsiSignatures

    Specify the AMSI signatures that need to be obfuscated. These
    strings will be found manually, if not provided.

    .PARAMETER PSAmsiScanner

    Specifies the PSAmsiScanner to use for AMSI scans.

    .PARAMETER Obfuscator

    Specifies the PowerShellObfuscator to use for obfuscation.

    .OUTPUTS

    String

    .EXAMPLE

    Get-MinimallyObfuscated -ScriptString "Write-Host example"

    .EXAMPLE

    Get-MinamallyObfuscated -ScriptBlock { Write-Host "example" }
        
    .EXAMPLE
        
    Get-MinimallyObfuscated -ScriptPath ./Write-Example.ps1

    .NOTES

    New-PowerShellObfuscator is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

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

        [Parameter(Position = 1)]
        [String[]] $AmsiSignatures,

        [Parameter(Position = 2)]
        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [Object] $PSAmsiScanner,

        [Parameter(Position = 3)]
        [ValidateScript({$_.GetType().Name -eq 'PowerShellObfuscator'})]
        [Object] $Obfuscator
    )
    Begin {
        If (-not $Obfuscator) { $Obfuscator = New-PowerShellObfuscator }
    }
    Process {
        If ($ScriptString) { $Obfuscator.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner, $AmsiSignatures) }
        ElseIf ($ScriptBlock) { $Obfuscator.GetMinimallyObfuscated($ScriptBlock, $PSAmsiScanner, $AmsiSignatures) }
        ElseIf ($ScriptPath) { $Obfuscator.GetMinimallyObfuscated($ScriptPath, $PSAmsiScanner, $AmsiSignatures) }
        ElseIf ($ScriptUri) { $Obfuscator.GetMinimallyObfuscated($ScriptUri, $PSAmsiScanner, $AmsiSignatures) }
    }
}

#Requires -Version 2

########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule
{
<#
.SYNOPSIS
Creates an in-memory assembly and module
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION
When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.
.PARAMETER ModuleName
Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.
.EXAMPLE
$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS
Creates a .NET type for an unmanaged Win32 function.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION
Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).
The 'func' helper function can be used to reduce typing when defining
multiple function definitions.
.PARAMETER DllName
The name of the DLL.
.PARAMETER FunctionName
The name of the target function.
.PARAMETER EntryPoint
The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.
.PARAMETER ReturnType
The return type of the function.
.PARAMETER ParameterTypes
The function parameters.
.PARAMETER NativeCallingConvention
Specifies the native calling convention of the function. Defaults to
stdcall.
.PARAMETER Charset
If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.
.PARAMETER SetLastError
Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.
.PARAMETER Module
The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER Namespace
An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)
$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')
.NOTES
Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189
When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($EntryPoint) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName,
                [Reflection.PropertyInfo[]] @(),
                [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
.SYNOPSIS
Creates an in-memory enumeration for use in your PowerShell session.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION
The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.
.PARAMETER Module
The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER FullName
The fully-qualified name of the enum.
.PARAMETER Type
The type of each enum element.
.PARAMETER EnumElements
A hashtable of enum elements.
.PARAMETER Bitfield
Specifies that the enum should be treated as a bitfield.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}
.NOTES
PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS
Creates an in-memory struct for use in your PowerShell session.
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION
The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.
One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.
.PARAMETER Module
The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.
.PARAMETER FullName
The fully-qualified name of the struct.
.PARAMETER StructFields
A hashtable of fields. Use the 'field' helper function to ease
defining each field.
.PARAMETER PackingSize
Specifies the memory alignment of fields.
.PARAMETER ExplicitLayout
Indicates that an explicit offset for each field will be specified.
.PARAMETER CharSet
Dictates which character set marshaled strings should use.
.EXAMPLE
$Mod = New-InMemoryModule -ModuleName Win32
$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}
$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}
# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout
.NOTES
PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout,

        [System.Runtime.InteropServices.CharSet]
        $CharSet = [System.Runtime.InteropServices.CharSet]::Ansi
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    switch($CharSet)
    {
        Ansi
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
        }
        Auto
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        Unicode
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        s}
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

If ((gci env: | ? { $_.Name -eq 'OS' }).Value -eq 'Windows_NT' -AND
(Get-CimInstance Win32_OperatingSystem).Version.StartsWith('10')) {
    # Create an InMemoryModule, AMSINativeMethods, and AMSI_Result enum using PSReflect written by Matt Graeber (@mattifestation)
    $Module = New-InMemoryModule -ModuleName AMSI

    $FunctionDefinitions = @(
       (func amsi AmsiInitialize ([UInt32]) @([String], [Int64].MakeByRefType()) -SetLastError),
       (func amsi AmsiUninitialize ([Void]) @([IntPtr]) -SetLastError),
       (func amsi AmsiOpenSession ([UInt32]) @([IntPtr], [Int64].MakeByRefType()) -SetLastError),
       (func amsi AmsiCloseSession ([Void]) @([IntPtr], [IntPtr]) -SetLastError),
       (func amsi AmsiScanBuffer ([UInt32]) @([IntPtr], [IntPtr], [UInt32], [String], [IntPtr], [Int32].MakeByRefType()) -SetLastError),
       (func amsi AmsiScanString ([UInt32]) @([IntPtr], [String], [String], [IntPtr], [Int32].MakeByRefType()) -SetLastError)
    )

    $AMSI_Result = psenum $Module AMSI.AMSI_RESULT UInt32 @{
       AMSI_RESULT_CLEAN = 0
       AMSI_RESULT_NOT_DETECTED = 1
       AMSI_RESULT_DETECTED = 32768
    }

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'AMSI.NativeMethods'
    $AMSINativeMethods = $Types['amsi']
}

function AmsiInitialize {
    <#

    .SYNOPSIS

    Initializes an AmsiContext to conduct AMSI scans.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSReflect, AMSINativeMethods
    Optional Dependencies: none

    .DESCRIPTION

    AmsiInitialize initializes an AmsiContext to conduct AMSI scans by calling the function
    decribed here: https://msdn.microsoft.com/en-us/library/windows/desktop/dn889862(v=vs.85).aspx 

    .PARAMETER appName

    The name of the App that will be submitting AMSI scan requests.

    .PARAMETER amsiContext

    A reference to the amsiContext that will be set by this function.

    .OUTPUTS

    Int

    .EXAMPLE

    $AmsiContext = [IntPtr]::Zero
    AmsiInitialize -appName "PSAmsi" -amsiContext ([ref]$AmsiContext)

    .NOTES

    AmsiInitialize is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $appName,

        [Parameter(Position = 1, Mandatory)]
        [ref] $amsiContext
    )

    $HResult = $AMSINativeMethods::AmsiInitialize($appName, $amsiContext)

    If ($HResult -ne 0) {
        throw "AmsiInitialize Error: $($HResult). AMSI may not be enabled on your system."
    }

    $HResult
}

function AmsiOpenSession {
    <#

    .SYNOPSIS

    Opens an AmsiSession associated with an AmsiContext to conduct AMSI scans.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSReflect, AMSINativeMethods
    Optional Dependencies: none

    .DESCRIPTION

    AmsiOpenSession opens an AmsiSession assocaited with an AmsiContext by calling the function
    decribed here: https://msdn.microsoft.com/en-us/library/windows/desktop/dn889863(v=vs.85).aspx 

    .PARAMETER amsiContext

    A pointer to the AmsiContext for which this AmsiSession will be associated.

    .PARAMETER session

    A reference to the AmsiSession that will be set by this function.

    .OUTPUTS

    Int

    .EXAMPLE

    $AmsiSession = [IntPtr]::Zero
    AmsiInitialize -amsiContext $AmsiContext -session ([ref]$AmsiSession)

    .NOTES

    AmsiOpenSession is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [IntPtr] $amsiContext,

        [Parameter(Position = 1, Mandatory)]
        [ref] $session
    )

    $HResult = $AMSINativeMethods::AmsiOpenSession($amsiContext, $session)

    If ($HResult -ne 0) {
        throw "AmsiOpenSession Error: $($HResult)"
    }

    $HResult
}

function AmsiScanString {
    <#

    .SYNOPSIS

    Submits a string to by scanned by the AntiMalware Provider.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSReflect, AMSINativeMethods
    Optional Dependencies: none

    .DESCRIPTION

    AmsiScanString submits a string to be scanned by the AntiMalware provider by calling the function
    decribed here: https://msdn.microsoft.com/en-us/library/windows/desktop/dn889866(v=vs.85).aspx

    .PARAMETER amsiContext

    A pointer to the AmsiContext this scan is associated with.

    .PARAMETER string

    The string to be scanned for malware.

    .PARAMETER contentName

    The name of the content to be scanned.

    .PARAMETER session

    A pointer to the AmsiSession this scan is a part of.

    .PARAMETER result

    A reference to the result of the scan that will be set by this function.

    .OUTPUTS

    Int

    .EXAMPLE

    $AmsiResult = $AMSI_Result::AMSI_RESULT_NOT_DETECTED
    AmsiScanString $AmsiContext $ScriptString $ContentName $AmsiSession -result ([ref]$AmsiResult)

    .NOTES

    AmsiScanString is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [IntPtr] $amsiContext,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $string,

        [Parameter(Position = 2, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $contentName,

        [Parameter(Position = 3, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [IntPtr] $session,

        [Parameter(Position = 4, Mandatory)]
        [ref] $result
    )

    $HResult = $AMSINativeMethods::AmsiScanString($amsiContext, $string, $contentName, $session, $result)

    If ($HResult -ne 0) {
        throw "AmsiScanString Error: $($HResult)"
    }

    $HResult
}

function AmsiScanBuffer {
    <#

    .SYNOPSIS

    Submits a buffer to by scanned by the AntiMalware Provider.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSReflect, AMSINativeMethods
    Optional Dependencies: none

    .DESCRIPTION

    AmsiScanBuffer submits a buffer to be scanned by the AntiMalware provider by calling the function
    decribed here: https://msdn.microsoft.com/en-us/library/windows/desktop/dn889865(v=vs.85).aspx

    .PARAMETER amsiContext

    A pointer to the AmsiContext this scan is associated with.

    .PARAMETER buffer

    A pointer to the buffer to be scanned for malware.

    .PARAMETER length

    The length of the buffer to be scanned for malware.

    .PARAMETER contentName

    The name of the content to be scanned.

    .PARAMETER session

    A pointer to the AmsiSession this scan is a part of.

    .PARAMETER result

    A reference to the result of the scan that will be set by this function.

    .OUTPUTS

    Int

    .EXAMPLE

    $AmsiResult = $AMSI_Result::AMSI_RESULT_NOT_DETECTED
    AmsiScanBuffer $AmsiContext $Buffer $Length $ContentName $AmsiSession -result ([ref]$AmsiResult)

    .NOTES

    AmsiScanBuffer is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [IntPtr] $amsiContext,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [IntPtr] $buffer,

        [Parameter(Position = 2, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Int] $length,

        [Parameter(Position = 3, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $contentName,

        [Parameter(Position = 4, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [IntPtr] $session,

        [Parameter(Position = 5, Mandatory)]
        [ref] $result
    )

    $HResult = $AMSINativeMethods::AmsiScanString($amsiContext, $buffer, $length, $contentName, $session, $result)

    If ($HResult -ne 0) {
        throw "AmsiScanBuffer Error: $($HResult)"
    }

    $HResult
}

function AmsiResultIsMalware {
    <#

    .SYNOPSIS

    Determines if a previous AmsiScan detected malware, based on it's AmsiResult.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSReflect, AMSI_Result
    Optional Dependencies: none

    .DESCRIPTION

    AmsiResultIsMalware takes the result from an AmsiScanString or AmsiScanBuffer scan and 
    uses the AMSI_Result enum to determine if the scan detected malware.

    .PARAMETER AMSIRESULT

    The result from a AmsiScanString or AmsiScanBuffer call.

    .OUTPUTS

    Bool

    .EXAMPLE

    $AmsiResult = $AMSI_Result::AMSI_RESULT_NOT_DETECTED
    AmsiScanString $Context $Content $ContentName $Session -result ([ref]$AmsiResult)
    AmsiResultIsMalware -AMSIRESULT $AmsiResult

    .NOTES

    AmsiResultIsMalware is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateSet(0, 1, 32768)]
        [UInt32] $AMSIRESULT
    )

    If(($AMSIRESULT -ne $AMSI_Result::AMSI_RESULT_CLEAN) -and
    ($AMSIRESULT -ne $AMSI_Result::AMSI_RESULT_NOT_DETECTED)) {
        $True
    }
    Else { $False }
}

function AmsiCloseSession {
    <#

    .SYNOPSIS

    Closes an AmsiSession opened with AmsiOpenSession.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSReflect, AMSINativeMethods
    Optional Dependencies: none

    .DESCRIPTION

    AmsiCloseSession closes an AmsiSession opened with AmsiOpenSession by calling the function
    decribed here: https://msdn.microsoft.com/en-us/library/windows/desktop/dn889861(v=vs.85).aspx

    .PARAMETER amsiContext

    A pointer to the AmsiContext for which this AmsiSession is associated.

    .PARAMETER session

    A pointer to the AmsiSession to be closed.

    .OUTPUTS

    None

    .EXAMPLE

    $AmsiSession = [IntPtr]::Zero
    AmsiOpenSession -amsiContext $AmsiContext -session ([ref]$AmsiSession)
    AmsiCloseSession -amsiConext $AmsiContext -session $AmsiSession

    .NOTES

    AmsiCloseSession is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [IntPtr] $amsiContext,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [IntPtr] $session
    )

    $HResult = $AMSINativeMethods::AmsiCloseSession($amsiContext, $session)
}

function AmsiUninitialize {
    <#

    .SYNOPSIS

    Uninitializes an AmsiContext initialized with AmsiInitialize.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSReflect, AMSINativeMethods
    Optional Dependencies: none

    .DESCRIPTION

    AmsiUninitialize uninitializes an AmsiContext initialized with AmsiInitialize by calling
    the function decribed here: https://msdn.microsoft.com/en-us/library/windows/desktop/dn889867(v=vs.85).aspx

    .PARAMETER amsiContext

    A pointer to the AmsiContext to be uninitialized.

    .OUTPUTS

    None

    .EXAMPLE

    $AmsiContext = [IntPtr]::Zero
    AmsiInitialize -appName "PSAmsi" -amsiContext ([ref]$AmsiContext)
    AmsiUninitialize -amsiConext $AmsiContext

    .NOTES

    AmsiUninitialize is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, Mandatory)]
        [IntPtr] $amsiContext
    )

    $HResult = $AMSINativeMethods::AmsiUninitialize($amsiContext)
}

class PSAmsiScanner : System.IDisposable {
    [ValidateNotNull()]
    [String] $PSAmsiScannerAppName = "PSAmsi"

    [ValidateNotNull()]
    [Bool] $CacheEnabled = $True
    [ValidateNotNull()]
    [HashTable] $ScanCache = @{}

    [ValidateNotNull()]
    [String[]] $ScanBlacklist = @()
    [ValidateNotNull()]
    [String[]] $ScanWhitelist = @()
    [Bool] $OnlyUseBlacklist = $False

    [ValidateNotNull()]
    [Bool] $AlertLimitEnabled = $False
    [ValidateNotNull()]
    [Bool] $AlertLimitReached = $False
    [ValidateRange(0,[Int]::MaxValue)]
    [Int] $AlertLimit = 0
    [ValidateRange(0, [Int]::MaxValue)]
    [Int] $AlertCount = 0
    [ValidateRange(0, [Int]::MaxValue)]
    [Int] $Delay = 0

    hidden [Long] $AmsiContext
    hidden [Long] $AmsiSession

    # InitAmsi initializes items shared by all Constructors
    hidden InitAmsi() {
        $TempContext = [IntPtr]::Zero
        $TempSession = [IntPtr]::Zero
        $Result = AmsiInitialize -appName $this.PSAmsiScannerAppName -amsiContext ([ref] $TempContext)
        $Result = AmsiOpenSession -amsiContext $TempContext -session ([ref] $TempSession)
        $this.AmsiContext = $TempContext
        $this.AmsiSession = $TempSession
    }

    # Default constructor
    PSAmsiScanner() {
        $this.InitAmsi()
    }

    # Constructor - Specify AppName
    PSAmsiScanner([String] $PSAmsiScannerAppName) {
        $this.PSAmsiScannerAppName = $PSAmsiScannerAppName
        $this.InitAmsi()
    }

    # Constructor - Specify if Cache is enabled.
    PSAmsiScanner([Bool] $CacheEnabled) {
        $this.CacheEnabled = $CacheEnabled
        $this.InitAmsi()
    }

    # Constructor - Specify the ScanCache to use.
    PSAmsiScanner([HashTable] $ScanCache) {
        $this.ScanCache = $ScanCache
        $this.InitAmsi()
    }

    # Constructor - Specify an AlertLimit.
    PSAmsiScanner([Int] $AlertLimit) {
        If ($AlertLimit -gt 0) {
            $this.AlertLimitEnabled = $True
            $this.AlertLimit = $AlertLimit
        }
        $this.InitAmsi()
    }

    # Constructor - Specify a ScanBlacklist and a ScanWhitelist.
    PSAmsiScanner([String[]] $ScanBlacklist, [String[]] $ScanWhitelist) {
        $this.ScanBlacklist = $ScanBlacklist
        $this.ScanWhitelist = $ScanWhitelist
        $this.InitAmsi()
    }

    # Constructor - Specify a ScanBlacklist and if the scanner should only use the Blacklist, w/o doing AMSI scanning.
    PSAmsiScanner([String[]] $ScanBlacklist, $OnlyUseBlacklist) {
        $this.ScanBlacklist = $ScanBlacklist
        $this.OnlyUseBlacklist = $OnlyUseBlacklist
        $this.InitAmsi()
    }

    # Constructor - Specify an AlertLimit and a Delay.
    PSAmsiScanner([Int] $AlertLimit, [Int] $Delay) {
        $this.Delay = $Delay
        If ($AlertLimit -gt 0) {
            $this.AlertLimitEnabled = $True
            $this.AlertLimit = $AlertLimit
        }
        $this.InitAmsi()
    }

    # Constructor - Specify an AppName, an AlertLimit, and a Delay.
    PSAmsiScanner([String] $PSAmsiScannerAppName, [Int] $AlertLimit, [Int] $Delay) {
        $this.PSAmsiScannerAppName = $PSAmsiScannerAppName
        $this.Delay = $Delay
        If ($AlertLimit -gt 0) {
            $this.AlertLimitEnabled = $True
            $this.AlertLimit = $AlertLimit
        }
        $this.InitAmsi()
    }

    # Constructor - Specify an AppName, if the Cache is enabled, an AlertLimit, and a Delay.
    PSAmsiScanner([String] $PSAmsiScannerAppName, [Bool] $CacheEnabled, [Int] $AlertLimit, [Int] $Delay) {
        $this.PSAmsiScannerAppName = $PSAmsiScannerAppName
        $this.CacheEnabled = $CacheEnabled
        If ($AlertLimit -gt 0) {
            $this.AlertLimitEnabled = $True
            $this.AlertLimit = $AlertLimit
        }
        $this.Delay = $Delay
        $this.InitAmsi()
    }

    # Constructor - Specify an AppName, the ScanCache to use, an AlertLimit, and a Delay.
    PSAmsiScanner([String] $PSAmsiScannerAppName, [HashTable] $ScanCache, [Int] $AlertLimit, [Int] $Delay) {
        $this.PSAmsiScannerAppName = $PSAmsiScannerAppName
        $this.ScanCache = $this.ScanCache
        $this.CacheEnabled = $True
        If ($AlertLimit -gt 0) {
            $this.AlertLimitEnabled = $True
            $this.AlertLimit = $AlertLimit
        }
        $this.Delay = $Delay
        $this.InitAmsi()
    }

    # Constructor - Specify an AppName, the ScanCache to use, an AlertLimit, a Delay, a ScanBlacklist, and a ScanWhitelist.
    PSAmsiScanner([String] $PSAmsiScannerAppName, [HashTable] $ScanCache, [Int] $AlertLimit, [Int] $Delay, [String[]] $ScanBlacklist, [String[]] $ScanWhitelist) {
        $this.ScanBlacklist = $ScanBlacklist
        $this.ScanWhitelist = $ScanWhitelist
        $this.PSAmsiScannerAppName = $PSAmsiScannerAppName
        $this.ScanCache = $this.ScanCache
        $this.CacheEnabled = $True
        If ($AlertLimit -gt 0) {
            $this.AlertLimitEnabled = $True
            $this.AlertLimit = $AlertLimit
        }
        $this.Delay = $Delay
        $this.InitAmsi()
    }

    [Void] Dispose() {
        $this.Dispose($true)
        [System.GC]::SuppressFinalize($this)
    }

    [Void] Dispose([Bool] $Disposing) {
        If ($Disposing) {
            [IntPtr] $TempContext = $this.AmsiContext
            [IntPtr] $TempSession = $this.AmsiSession
            $Result = AmsiCloseSession -amsiContext $TempContext -session $TempSession
            $Result = AmsiUninitialize $TempContext
        }
    }

    [Bool] GetPSAmsiScanResult([String] $ScriptString, [String] $PSAmsiContentName) {
        If (-not $ScriptString) {
            return $False
        }

        $HashCode = $ScriptString.GetHashCode() -as [String]
        If (($ScriptString.ToLower() -in $this.ScanBlacklist) -or ($ScriptString.ToLower().GetHashCode() -in $this.ScanBlacklist)) { return $True }
        ElseIf ($this.OnlyUseBlacklist) { return $False }
        If (($ScriptString -in $this.ScanWhitelist) -or ($HashCode -in $this.ScanWhitelist)) { return $False }

        If ($this.CacheEnabled -and ($this.ScanCache.Contains($HashCode))) {
            return $this.ScanCache.Get_Item($HashCode)
        }

        # If we have reached our global alert limit, we will not conduct a scan. Instead, we return false, but this does
        # not guarantee the given string will not be flagged.
        If ($this.AlertLimitReached) {
            return $False
        }
        Else {
            # 1 is AMSI_RESULT_NOT_DETECTED
            $AmsiResult = 1
            $IsFlaggedAsMalware = $False
            [IntPtr] $TempContext = $this.AmsiContext
            [IntPtr] $TempSession = $this.AmsiSession
            $Result = AmsiScanString -amsiContext $TempContext -string $ScriptString -contentName $this.PSAmsiScannerAppName -session $TempSession -result ([ref]$AmsiResult)
            If (AmsiResultIsMalware -AMSIRESULT $AmsiResult) {
                $IsFlaggedAsMalware = $True
            }

            If ($this.CacheEnabled) {
                $this.ScanCache.Set_Item($HashCode, $IsFlaggedAsMalware)
            }

            If ($IsFlaggedAsMalware) {
                If ($this.Delay -gt 0) {
                    Write-Verbose "Delaying for $($this.Delay) second(s)..."
                    Start-Sleep -Seconds $this.Delay
                }
                $this.AlertCount++
                If ($this.AlertLimitEnabled -and $this.AlertCount -ge $this.AlertLimit) { $this.AlertLimitReached = $True }
            }

            return $IsFlaggedAsMalware
        }
    }

    [Bool] GetPSAmsiScanResult([ScriptBlock] $ScriptBlock, [String] $PSAmsiContentName) {
        $ScriptString = $ScriptBlock -as [String]
        return $this.GetPSAmsiScanResult($ScriptString, $PSAmsiContentName)
    }

    [Bool] GetPSAmsiScanResult([IO.FileInfo] $ScriptPath, [String] $PSAmsiContentName) {
        $ScriptString = Get-Content $ScriptPath -Raw
        return $this.GetPSAmsiScanResult($ScriptString, $PSAmsiContentName)
    }

    [Bool] GetPSAmsiScanResult([Uri] $ScriptUri, [String] $PSAmsiContentName) {
        $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri)
        return $this.GetPSAmsiScanResult($ScriptString, $PSAmsiContentName)
    }

    [Bool] GetPSAmsiScanResult([String] $ScriptString) {
        return $this.GetPSAmsiScanResult($ScriptString, $this.PSAmsiScannerAppName)
    }

    [Bool] GetPSAmsiScanResult([ScriptBlock] $ScriptBlock) {
        return $this.GetPSAmsiScanResult($ScriptBlock, $this.PSAmsiScannerAppName)
    }

    [Bool] GetPSAmsiScanResult([IO.FileInfo] $ScriptPath) {
        return $this.GetPSAmsiScanResult($ScriptPath, $this.PSAmsiScannerAppName)
    }

    [Bool] GetPSAmsiScanResult([Uri] $ScriptUri) {
        return $this.GetPSAmsiScanResult($ScriptUri, $this.PSAmsiScannerAppName)
    }

    [Void] ResetPSAmsiScanCache() {
        $this.ScanCache = @{}
    }
}

function New-PSAmsiScanner {
<#
    .SYNOPSIS

    Creates a new PSAmsiScanner object for conducting PSAmsi scans.
    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSAmsiScanner
    Optional Dependencies: none

    .DESCRIPTION

    New-PSAmsiScanner creates a new PSAmsiScanner object for conducting PSAmsi scans.

    .PARAMETER AppName

    The name of the Application that will be submitting PSAmsi scans through the PSAmsiScanner.

    .PARAMETER AlertLimit

    Specifies the maximum amount of AMSI alerts this PSAmsiScanner is allowed to generate.

    .PARAMETER Delay

    Specifies the amount of time (in seconds) this PSAmsiScanner will wait between generated AMSI alerts.

    .PARAMETER ScanCache

    Specify a pre-computed hashtable of cached PSAmsiScanResults that this PSAmsiScanner will use.

    .PARAMETER DisableCache

    Disabled the caching and use of cached PSAmsiScanResults for this PSAmsiScanner. Every request will guaranteed
    to be submitted to the AMSI AntiMawlare provider if caching is disabled. Default is cache enabled.

    .OUTPUTS

    PSAmsiScanner

    .EXAMPLE

    New-PSAmsiScanner

    .EXAMPLE

    New-PSAmsiScanner -AppName "PSAmsi" -AlertLimit 100 -Delay 1

    .NOTES

    New-PSAmsiScanner is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $AppName = "PSAmsi",

        [Parameter(Position = 1)]
        [ValidateRange(0, [Int]::MaxValue)]
        [Int] $AlertLimit = 0,

        [Parameter(Position = 2)]
        [ValidateRange(0,[Int]::MaxValue)]
        [Int] $Delay = 0,

        [Parameter(Position = 3)]
        [ValidateNotNull()]
        [HashTable] $ScanCache = @{},

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [String[]] $ScanBlacklist = @(),

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [String[]] $ScanWhitelist = @(),

        [Switch] $DisableCache,

        [Switch] $OnlyUseBlacklist
    )
    If ($DisableCache) {
        $PSAmsiScanner = [PSAmsiScanner]::new($AppName, $False, $AlertLimit, $Delay, $ScanBlacklist, $ScanWhitelist)
    }
    Else {
        $PSAmsiScanner = [PSAmsiScanner]::new($AppName, $ScanCache, $AlertLimit, $Delay, $ScanBlacklist, $ScanWhitelist)
    }
    If ($OnlyUseBlacklist) { $PSAmsiScanner.OnlyUseBlacklist = $True }

    $PSAmsiScanner
}

function Get-PSAmsiScanResult {
<#
    .SYNOPSIS

    Gets the result of a PSAmsiScan on a given string using a given PSAmsiScanner.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSAmsiScanner
    Optional Dependencies: none

    .DESCRIPTION

    Get-PSAmsiScanResult gets the result of a PSAmsiScan on a given string using a given PSAmsiScanner
    to determine if the current AMSI AntiMalware Provider detects the string as malicious.

    .PARAMETER ScriptString

    The string containing the script to be scanned.

    .PARAMETER ScriptBlock

    The ScriptBlock containing the script to be scanned.

    .PARAMETER ScriptPath

    The Path to the script to be scanned.

    .PARAMETER ScriptUri

    The URI of the script to be scanned.

    .OUTPUTS

    PSCustomObject

    .EXAMPLE

    Get-PSAmsiScanResult -ScriptString "Write-Host example"

    .EXAMPLE

    Get-PSAmsiScanResult -ScriptBlock { Write-Host test }

    .EXAMPLE

    Get-PSAmsiScanResult -ScriptPath ./Example.ps1

    .EXAMPLE

    Get-PSAmsiScanResult -ScriptUri 'http://example.com/Example.ps1'

    .NOTES
    
    Get-PSAmsiScanResult is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>

    [CmdletBinding(DefaultParameterSetName = "ByString")] Param (
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

        [Parameter(Position = 1)]
        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String] $ContentName
    )
    Begin {
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            $PSAmsiScanner = New-PSAmsiScanner
            $CreatedPSAmsiScanner = $True
        }
    }
    Process {
        If ($ScriptString) {
            If ($ContentName) { $PSAmsiScanner.GetPSAmsiScanResult($ScriptString, $ContentName) }
            Else { $PSAmsiScanner.GetPSAmsiScanResult($ScriptString) }
        }
        ElseIf ($ScriptBlock) {
            If ($ContentName) { $PSAmsiScanner.GetPSAmsiScanResult($ScriptBlock, $ContentName) }
            Else { $PSAmsiScanner.GetPSAmsiScanResult($ScriptBlock) }
        }
        ElseIf ($ScriptPath) {
            If ($ContentName) { $PSAmsiScanner.GetPSAmsiScanResult((Get-ChildItem $ScriptPath), $ContentName) }
            Else { $PSAmsiScanner.GetPSAmsiScanResult((Get-ChildItem $ScriptPath)) }
        }
        ElseIf ($ScriptUri) {
            If ($ContentName) { $PSAmsiScanner.GetPSAmsiScanResult($ScriptUri) }
            Else { $PSAmsiScanner.GetPSAmsiScanResult($ScriptUri) }
        }
    }
    End {
        If ($CreatedPSAmsiScanner) {
            $PSAmsiScanner.Dispose()
        }
    }
}

function Reset-PSAmsiScanCache {
<#
    .SYNOPSIS

    Resets the ScanCache of a given PSAmsiScanner.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSAmsiScanner
    Optional Dependencies: none

    .DESCRIPTION

    Reset-PSAmsiScanCache resets the ScanCache of a given PSAmsiScanner so all
    new requests will return fresh responses from the AMSI AntiMalware Provider.
    
    .EXAMPLE

    Reset-PSAmsiScanCache

    .NOTES

    Reset-PSAmsiScanCache is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.
    
    #>

    Param (
        [Parameter(Position = 0, Mandatory)] [ValidateNotNull()]
        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner
    )
    $PSAmsiScanner.ResetPSAmsiScanCache()
}

#   This file is part of Invoke-Obfuscation.
#
#   Copyright 2017 Daniel Bohannon <@danielhbohannon>
#         while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.



Function Out-ObfuscatedStringCommand
{
<#
.SYNOPSIS

Master function that orchestrates the application of all string-based obfuscation functions to provided PowerShell script.

Invoke-Obfuscation Function: Out-ObfuscatedStringCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-EncapsulatedInvokeExpression (located in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedStringCommand orchestrates the application of all string-based obfuscation functions (casting ENTIRE command to a string a performing string obfuscation functions) to provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. If no $ObfuscationLevel is defined then Out-ObfuscatedStringCommand will automatically choose a random obfuscation level.
The available ObfuscationLevel/function mappings are:
1 --> Out-StringDelimitedAndConcatenated
2 --> Out-StringDelimitedConcatenatedAndReordered
3 --> Out-StringReversed

.PARAMETER ScriptBlock

Specifies a scriptblock containing your payload.

.PARAMETER Path

Specifies the path to your payload.

.PARAMETER ObfuscationLevel

(Optional) Specifies the obfuscation level for the given input PowerShell payload. If not defined then Out-ObfuscatedStringCommand will automatically choose a random obfuscation level. 
The available ObfuscationLevel/function mappings are:
1 --> Out-StringDelimitedAndConcatenated
2 --> Out-StringDelimitedConcatenatedAndReordered
3 --> Out-StringReversed

.EXAMPLE

C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 1

IEX ((('Write-H'+'ost x'+'lcHello'+' Wor'+'ld!xlc -F'+'oregroundC'+'o'+'lor Gre'+'en'+'; Write-Host '+'xlcObf'+'u'+'sc'+'ation '+'Rocks!xl'+'c'+' '+'-'+'Foregrou'+'nd'+'C'+'olor Green')  -Replace 'xlc',[Char]39) )

C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 2

IEX( (("{17}{1}{6}{19}{14}{3}{5}{13}{16}{11}{20}{15}{10}{12}{2}{4}{8}{18}{7}{9}{0}" -f ' Green','-H',' ',' ','R','-Foregr','ost qR9He','!qR9 -Foregr','o','oundColor','catio',' ','n','oundColor','qR9','bfus',' Green; Write-Host','Write','cks','llo World!','qR9O')).Replace('qR9',[String][Char]39))

C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 3

$I4 ="noisserpxE-ekovnI|)93]rahC[]gnirtS[,'1Yp'(ecalpeR.)'ne'+'erG roloCd'+'nuo'+'rgero'+'F- 1'+'Y'+'p!s'+'kcoR'+' noit'+'a'+'cs'+'ufbO'+'1'+'Yp '+'tsoH'+'-etirW'+' ;'+'neer'+'G '+'rol'+'oCdnu'+'orger'+'o'+'F'+'-'+' 1'+'Yp'+'!dlroW '+'olleH1Yp '+'t'+'s'+'oH-et'+'irW'( " ;$I4[ -1 ..- ($I4.Length ) ] -Join '' | Invoke-Expression

.NOTES

Out-ObfuscatedStringCommand orchestrates the application of all string-based obfuscation functions (casting ENTIRE command to a string a performing string obfuscation functions) to provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. If no $ObfuscationLevel is defined then Out-ObfuscatedStringCommand will automatically choose a random obfuscation level.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [ValidateSet('1', '2', '3')]
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $ObfuscationLevel = (Get-Random -Input @(1..3)) # Default to random obfuscation level if $ObfuscationLevel isn't defined
    )

    # Either convert ScriptBlock to a String or convert script at $Path to a String.
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }

    # Set valid obfuscation levels for current token type.
    $ValidObfuscationLevels = @(0,1,2,3)
    
    # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
    If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}  
    
    Switch($ObfuscationLevel)
    {
        0 {Continue}
        1 {$ScriptString = Out-StringDelimitedAndConcatenated $ScriptString}
        2 {$ScriptString = Out-StringDelimitedConcatenatedAndReordered $ScriptString}
        3 {$ScriptString = Out-StringReversed $ScriptString}
        default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for String Obfuscation."; Exit}
    }

    Return $ScriptString
}


Function Out-StringDelimitedAndConcatenated
{
<#
.SYNOPSIS

Generates delimited and concatenated version of input PowerShell command.

Invoke-Obfuscation Function: Out-StringDelimitedAndConcatenated
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-ConcatenatedString (located in Out-ObfuscatedTokenCommand.ps1), Out-EncapsulatedInvokeExpression (located in Out-ObfuscatedStringCommand.ps1), Out-RandomCase (located in Out-ObfuscatedToken.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-StringDelimitedAndConcatenated delimits and concatenates an input PowerShell command. The purpose is to highlight to the Blue Team that there are more novel ways to encode a PowerShell command other than the most common Base64 approach.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER PassThru

(Optional) Outputs the option to not encapsulate the result in an invocation command.

.EXAMPLE

C:\PS> Out-StringDelimitedAndConcatenated "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"

(('Write-Ho'+'s'+'t'+' {'+'0'+'}'+'Hell'+'o Wor'+'l'+'d!'+'{'+'0'+'} -Foreground'+'Color G'+'ree'+'n; Writ'+'e-'+'H'+'ost {0}Obf'+'usc'+'a'+'tion R'+'o'+'ck'+'s!{'+'0} -Fo'+'reg'+'ro'+'undColor'+' '+'Gree'+'n')-F[Char]39) | Invoke-Expression

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedStringCommand function with the corresponding obfuscation level since Out-Out-ObfuscatedStringCommand will handle calling this current function where necessary.
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 1
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,

        [Switch]
        $PassThru
    )

    # Characters we will substitute (in random order) with randomly generated delimiters.
    $CharsToReplace = @('$','|','`','\','"',"'")
    $CharsToReplace = (Get-Random -Input $CharsToReplace -Count $CharsToReplace.Count)

    # If $ScriptString does not contain any characters in $CharsToReplace then simply return as is.
    $ContainsCharsToReplace = $FALSE
    ForEach($CharToReplace in $CharsToReplace)
    {
        If($ScriptString.Contains($CharToReplace))
        {
            $ContainsCharsToReplace = $TRUE
            Break
        }
    }
    If(!$ContainsCharsToReplace)
    {
        # Concatenate $ScriptString as a string and then encapsulate with parentheses.
        $ScriptString = Out-ConcatenatedString $ScriptString "'"
        $ScriptString = '(' + $ScriptString + ')'

        If(!$PSBoundParameters['PassThru'])
        {
            # Encapsulate in necessary IEX/Invoke-Expression(s).
            $ScriptString = Out-EncapsulatedInvokeExpression $ScriptString
        }

        Return $ScriptString
    }
    
    # Characters we will use to generate random delimiters to replace the above characters.
    # For simplicity do NOT include single- or double-quotes in this array.
    $CharsToReplaceWith  = @(0..9)
    $CharsToReplaceWith += @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
    $CharsToReplaceWith += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')
    $DelimiterLength = 3
    
    # Multi-dimensional table containing delimiter/replacement key pairs for building final command to reverse substitutions.
    $DelimiterTable = @()
    
    # Iterate through and replace each character in $CharsToReplace in $ScriptString with randomly generated delimiters.
    ForEach($CharToReplace in $CharsToReplace)
    {
        If($ScriptString.Contains($CharToReplace))
        {
            # Create random delimiter of length $DelimiterLength with characters from $CharsToReplaceWith.
            If($CharsToReplaceWith.Count -lt $DelimiterLength) {$DelimiterLength = $CharsToReplaceWith.Count}
            $Delim = (Get-Random -Input $CharsToReplaceWith -Count $DelimiterLength) -Join ''
            
            # Keep generating random delimiters until we find one that is not a substring of $ScriptString.
            While($ScriptString.ToLower().Contains($Delim.ToLower()))
            {
                $Delim = (Get-Random -Input $CharsToReplaceWith -Count $DelimiterLength) -Join ''
                If($DelimiterLength -lt $CharsToReplaceWith.Count)
                {
                    $DelimiterLength++
                }
            }
            
            # Add current delimiter/replacement key pair for building final command to reverse substitutions.
            $DelimiterTable += , @($Delim,$CharToReplace)

            # Replace current character to replace with the generated delimiter
            $ScriptString = $ScriptString.Replace($CharToReplace,$Delim)
        }
    }

    # Add random quotes to delimiters in $DelimiterTable.
    $DelimiterTableWithQuotes = @()
    ForEach($DelimiterArray in $DelimiterTable)
    {
        $Delimiter    = $DelimiterArray[0]
        $OriginalChar = $DelimiterArray[1]
        
        # Randomly choose between a single quote and double quote.
        $RandomQuote = Get-Random -InputObject @("'","`"")
        
        # Make sure $RandomQuote is opposite of $OriginalChar contents if it is a single- or double-quote.
        If($OriginalChar -eq "'") {$RandomQuote = '"'}
        Else {$RandomQuote = "'"}

        # Add quotes.
        $Delimiter = $RandomQuote + $Delimiter + $RandomQuote
        $OriginalChar = $RandomQuote + $OriginalChar + $RandomQuote
        
        # Add random quotes to delimiters in $DelimiterTable.
        $DelimiterTableWithQuotes += , @($Delimiter,$OriginalChar)
    }

    # Reverse the delimiters when building back out the reversing command.
    [Array]::Reverse($DelimiterTable)
    
    # Select random method for building command to reverse the above substitutions to execute the original command.
    # Avoid using the -f format operator (switch option 3) if curly braces are found in $ScriptString.
    If(($ScriptString.Contains('{')) -AND ($ScriptString.Contains('}')))
    {
        $RandomInput = Get-Random -Input (1..2)
    }
    Else
    {
        $RandomInput = Get-Random -Input (1..3)
    }

    # Randomize the case of selected variable syntaxes.
    $StringStr   = Out-RandomCase 'string'
    $CharStr     = Out-RandomCase 'char'
    $ReplaceStr  = Out-RandomCase 'replace'
    $CReplaceStr = Out-RandomCase 'creplace'

    Switch($RandomInput) {
        1 {
            # 1) .Replace

            $ScriptString = "'" + $ScriptString + "'"
            $ReversingCommand = ""

            ForEach($DelimiterArray in $DelimiterTableWithQuotes)
            {
                $Delimiter    = $DelimiterArray[0]
                $OriginalChar = $DelimiterArray[1]
                
                # Randomly decide if $OriginalChar will be displayed in ASCII representation or plaintext in $ReversingCommand.
                # This is to allow for simpler string manipulation on the command line.
                # Place priority on handling if $OriginalChar is a single- and double-quote.
                If($OriginalChar[1] -eq "'")
                {
                    $OriginalChar = "[$StringStr][$CharStr]39"
                    $Delimiter = "'" + $Delimiter.SubString(1,$Delimiter.Length-2) + "'"
                }
                ElseIf($OriginalChar[1] -eq '"')
                {
                    $OriginalChar = "[$StringStr][$CharStr]34"
                }
                Else
                {
                    If(Get-Random -Input (0..1))
                    {
                        $OriginalChar = "[$StringStr][$CharStr]" + [Int][Char]$OriginalChar[1]
                    }
                }
                
                # Randomly select if $Delimiter will be displayed in ASCII representation instead of plaintext in $ReversingCommand. 
                If(Get-Random -Input (0..1))
                {
                    # Convert $Delimiter string into a concatenation of [Char] representations of each characters.
                    # This is to avoid redundant replacement of single quotes if this function is run numerous times back-to-back.
                    $DelimiterCharSyntax = ""
                    For($i=1; $i -lt $Delimiter.Length-1; $i++)
                    {
                        $DelimiterCharSyntax += "[$CharStr]" + [Int][Char]$Delimiter[$i] + '+'
                    }
                    $Delimiter = '(' + $DelimiterCharSyntax.Trim('+') + ')'
                }
                
                # Add reversing commands to $ReversingCommand.
                $ReversingCommand = ".$ReplaceStr($Delimiter,$OriginalChar)" + $ReversingCommand
            }

            # Concatenate $ScriptString as a string and then encapsulate with parentheses.
            $ScriptString = Out-ConcatenatedString $ScriptString "'"
            $ScriptString = '(' + $ScriptString + ')'

            # Add reversing commands to $ScriptString.
            $ScriptString = $ScriptString + $ReversingCommand
        }
        2 {
            # 2) -Replace/-CReplace

            $ScriptString = "'" + $ScriptString + "'"
            $ReversingCommand = ""

            ForEach($DelimiterArray in $DelimiterTableWithQuotes)
            {
                $Delimiter    = $DelimiterArray[0]
                $OriginalChar = $DelimiterArray[1]
                
                # Randomly decide if $OriginalChar will be displayed in ASCII representation or plaintext in $ReversingCommand.
                # This is to allow for simpler string manipulation on the command line.
                # Place priority on handling if $OriginalChar is a single- or double-quote.
                If($OriginalChar[1] -eq '"')
                {
                    $OriginalChar = "[$CharStr]34"
                }
                ElseIf($OriginalChar[1] -eq "'")
                {
                    $OriginalChar = "[$CharStr]39"; $Delimiter = "'" + $Delimiter.SubString(1,$Delimiter.Length-2) + "'"
                }
                Else
                {
                    $OriginalChar = "[$CharStr]" + [Int][Char]$OriginalChar[1]
                }
                
                # Randomly select if $Delimiter will be displayed in ASCII representation instead of plaintext in $ReversingCommand. 
                If(Get-Random -Input (0..1))
                {
                    # Convert $Delimiter string into a concatenation of [Char] representations of each characters.
                    # This is to avoid redundant replacement of single quotes if this function is run numerous times back-to-back.
                    $DelimiterCharSyntax = ""
                    For($i=1; $i -lt $Delimiter.Length-1; $i++)
                    {
                        $DelimiterCharSyntax += "[$CharStr]" + [Int][Char]$Delimiter[$i] + '+'
                    }
                    $Delimiter = '(' + $DelimiterCharSyntax.Trim('+') + ')'
                }
                
                # Randomly choose between -Replace and the lesser-known case-sensitive -CReplace.
                $Replace = (Get-Random -Input @("-$ReplaceStr","-$CReplaceStr"))

                # Add reversing commands to $ReversingCommand. Whitespace before and after $Replace is optional.
                $ReversingCommand = ' '*(Get-Random -Minimum 0 -Maximum 3) + $Replace + ' '*(Get-Random -Minimum 0 -Maximum 3) + "$Delimiter,$OriginalChar" + $ReversingCommand                
            }

            # Concatenate $ScriptString as a string and then encapsulate with parentheses.
            $ScriptString = Out-ConcatenatedString $ScriptString "'"
            $ScriptString = '(' + $ScriptString + ')'

            # Add reversing commands to $ScriptString.
            $ScriptString = '(' + $ScriptString + $ReversingCommand + ')'
        }
        3 {
            # 3) -f format operator

            $ScriptString = "'" + $ScriptString + "'"
            $ReversingCommand = ""
            $Counter = 0

            # Iterate delimiters in reverse for simpler creation of the proper order for $ReversingCommand.
            For($i=$DelimiterTableWithQuotes.Count-1; $i -ge 0; $i--)
            {
                $DelimiterArray = $DelimiterTableWithQuotes[$i]
                
                $Delimiter    = $DelimiterArray[0]
                $OriginalChar = $DelimiterArray[1]
                
                $DelimiterNoQuotes = $Delimiter.SubString(1,$Delimiter.Length-2)
                
                # Randomly decide if $OriginalChar will be displayed in ASCII representation or plaintext in $ReversingCommand.
                # This is to allow for simpler string manipulation on the command line.
                # Place priority on handling if $OriginalChar is a single- or double-quote.
                If($OriginalChar[1] -eq '"')
                {
                    $OriginalChar = "[$CharStr]34"
                }
                ElseIf($OriginalChar[1] -eq "'")
                {
                    $OriginalChar = "[$CharStr]39"; $Delimiter = "'" + $Delimiter.SubString(1,$Delimiter.Length-2) + "'"
                }
                Else
                {
                    $OriginalChar = "[$CharStr]" + [Int][Char]$OriginalChar[1]
                }
                
                # Build out delimiter order to add as arguments to the final -f format operator.
                $ReversingCommand = $ReversingCommand + ",$OriginalChar"

                # Substitute each delimited character with placeholder for -f format operator.
                $ScriptString = $ScriptString.Replace($DelimiterNoQuotes,"{$Counter}")

                $Counter++
            }
            
            # Trim leading comma from $ReversingCommand.
            $ReversingCommand = $ReversingCommand.Trim(',')

            # Concatenate $ScriptString as a string and then encapsulate with parentheses.
            $ScriptString = Out-ConcatenatedString $ScriptString "'"
            $ScriptString = '(' + $ScriptString + ')'
            
            # Add reversing commands to $ScriptString. Whitespace before and after -f format operator is optional.
            $FormatOperator = (Get-Random -Input @('-f','-F'))

            $ScriptString = '(' + $ScriptString + ' '*(Get-Random -Minimum 0 -Maximum 3) + $FormatOperator + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ReversingCommand + ')'
        }
        default {Write-Error "An invalid `$RandomInput value ($RandomInput) was passed to switch block."; Exit;}
    }
    
    # Encapsulate $ScriptString in necessary IEX/Invoke-Expression(s) if -PassThru switch was not specified.
    If(!$PSBoundParameters['PassThru'])
    {
        $ScriptString = Out-EncapsulatedInvokeExpression $ScriptString
    }

    Return $ScriptString
}


Function Out-StringDelimitedConcatenatedAndReordered
{
<#
.SYNOPSIS

Generates delimited, concatenated and reordered version of input PowerShell command.

Invoke-Obfuscation Function: Out-StringDelimitedConcatenatedAndReordered
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-StringDelimitedAndConcatenated (located in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-StringDelimitedConcatenatedAndReordered delimits, concatenates and reorders the concatenated substrings of an input PowerShell command. The purpose is to highlight to the Blue Team that there are more novel ways to encode a PowerShell command other than the most common Base64 approach.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER PassThru

(Optional) Outputs the option to not encapsulate the result in an invocation command.

.EXAMPLE

C:\PS> Out-StringDelimitedConcatenatedAndReordered "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"

(("{16}{5}{6}{14}{3}{19}{15}{10}{18}{17}{0}{2}{7}{8}{12}{9}{11}{4}{13}{1}"-f't','en','ion R','9 -Fore','Gr','e-Host 0i9Hello W','or','ocks!0i9 -Fo','regroun','olo','ite-Hos','r ','dC','e','ld!0i','; Wr','Writ','sca','t 0i9Obfu','groundColor Green')).Replace('0i9',[String][Char]39) |IEX

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedStringCommand function with the corresponding obfuscation level since Out-Out-ObfuscatedStringCommand will handle calling this current function where necessary.
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 2
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,

        [Switch]
        $PassThru
    )

    If(!$PSBoundParameters['PassThru'])
    {
        # Convert $ScriptString to delimited and concatenated string and encapsulate with invocation.
        $ScriptString = Out-StringDelimitedAndConcatenated $ScriptString
    }
    Else
    {
        # Convert $ScriptString to delimited and concatenated string and do no encapsulate with invocation.
        $ScriptString = Out-StringDelimitedAndConcatenated $ScriptString -PassThru
    }

    # Parse out concatenated strings to re-order them.
    $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
    $GroupStartCount = 0
    $ConcatenatedStringsIndexStart = $NULL
    $ConcatenatedStringsIndexEnd   = $NULL
    $ConcatenatedStringsArray = @()
    For($i=0; $i -le $Tokens.Count-1; $i++) {
        $Token = $Tokens[$i]

        If(($Token.Type -eq 'GroupStart') -AND ($Token.Content -eq '('))
        {
            $GroupStartCount = 1
            $ConcatenatedStringsIndexStart = $Token.Start+1
        }
        ElseIf(($Token.Type -eq 'GroupEnd') -AND ($Token.Content -eq ')') -OR ($Token.Type -eq 'Operator') -AND ($Token.Content -ne '+'))
        {
            $GroupStartCount--
            $ConcatenatedStringsIndexEnd = $Token.Start
            # Stop parsing concatenated string.
            If(($GroupStartCount -eq 0) -AND ($ConcatenatedStringsArray.Count -gt 0))
            {
                Break
            }
        }
        ElseIf(($GroupStartCount -gt 0) -AND ($Token.Type -eq 'String'))
        {
            $ConcatenatedStringsArray += $Token.Content
        }
        ElseIf($Token.Type -ne 'Operator')
        {
            # If something other than a string or operator appears then we're not dealing with a pure string concatenation. Thus we reset the group start and the concatenated strings array.
            # This only became an issue once the invocation syntax went from IEX/Invoke-Expression to concatenations like .($ShellId[1]+$ShellId[13]+'x')
            $GroupStartCount = 0
            $ConcatenatedStringsArray = @()
        }
    }

    $ConcatenatedStrings = $ScriptString.SubString($ConcatenatedStringsIndexStart,$ConcatenatedStringsIndexEnd-$ConcatenatedStringsIndexStart)

    # Return $ScriptString as-is if there is only one substring as it would gain nothing to "reorder" a single substring.
    If($ConcatenatedStringsArray.Count -le 1)
    {
        Return $ScriptString
    }

    # Randomize the order of the concatenated strings.
    $RandomIndexes = (Get-Random -Input (0..$($ConcatenatedStringsArray.Count-1)) -Count $ConcatenatedStringsArray.Count)
    
    $Arguments1 = ''
    $Arguments2 = @('')*$ConcatenatedStringsArray.Count
    For($i=0; $i -lt $ConcatenatedStringsArray.Count; $i++)
    {
        $RandomIndex = $RandomIndexes[$i]
        $Arguments1 += '{' + $RandomIndex + '}'
        $Arguments2[$RandomIndex] = "'" + $ConcatenatedStringsArray[$i] + "'"
    }
    
    # Whitespace is not required before or after the -f operator.
    $ScriptStringReordered = '(' + '"' + $Arguments1 + '"' + ' '*(Get-Random @(0..1)) + '-f' + ' '*(Get-Random @(0..1)) + ($Arguments2 -Join ',') + ')'

    # Add re-ordered $ScriptString back into the original $ScriptString context.
    $ScriptString = $ScriptString.SubString(0,$ConcatenatedStringsIndexStart) + $ScriptStringReordered + $ScriptString.SubString($ConcatenatedStringsIndexEnd)

    Return $ScriptString
}


Function Out-StringReversed
{
<#
.SYNOPSIS

Generates concatenated and reversed version of input PowerShell command.

Invoke-Obfuscation Function: Out-StringReversed
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-ConcatenatedString, Out-RandomCase (both are located in Out-ObfuscatedToken.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-StringReversed concatenates and reverses an input PowerShell command. The purpose is to highlight to the Blue Team that there are more novel ways to encode a PowerShell command other than the most common Base64 approach.

.PARAMETER ScriptString

Specifies the string containing your payload.

.EXAMPLE

C:\PS> Out-StringReversed "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"

sv 6nY  ("XEI | )93]rahC[ f-)'n'+'eer'+'G'+' roloC'+'dnuo'+'rgeroF-'+' '+'}0{!sk'+'co'+'R '+'noitacsufb'+'O'+'}0'+'{ ts'+'oH-'+'etirW ;neer'+'G'+' rolo'+'C'+'dnu'+'orgeroF- }0{!d'+'l'+'roW'+' olleH}0{ tsoH-et'+'ir'+'W'(( ");IEX ( (  gcI  vARiaBlE:6ny  ).valUE[ -1..-( (  gcI  vARiaBlE:6ny  ).valUE.Length ) ]-Join '' )

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedStringCommand function with the corresponding obfuscation level since Out-Out-ObfuscatedStringCommand will handle calling this current function where necessary.
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 3
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString
    )

    # Remove any special characters to simplify dealing with the reversed $ScriptString on the command line.
    $ScriptString = Out-ObfuscatedStringCommand ([ScriptBlock]::Create($ScriptString)) 1

    # Reverse $ScriptString.
    $ScriptStringReversed = $ScriptString[-1..-($ScriptString.Length)] -Join ''
    
    # Characters we will use to generate random variable names.
    # For simplicity do NOT include single- or double-quotes in this array.
    $CharsToRandomVarName  = @(0..9)
    $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')

    # Randomly choose variable name starting length.
    $RandomVarLength = (Get-Random -Input @(3..6))
   
    # Create random variable with characters from $CharsToRandomVarName.
    If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
    $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')

    # Keep generating random variables until we find one that is not a substring of $ScriptString.
    While($ScriptString.ToLower().Contains($RandomVarName.ToLower()))
    {
        $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
        $RandomVarLength++
    }

    # Randomly decide if the variable name will be concatenated inline or not.
    # Handle both <varname> and <variable:varname> syntaxes depending on which option is chosen concerning GET variable syntax.
    $RandomVarNameMaybeConcatenated = $RandomVarName
    $RandomVarNameMaybeConcatenatedWithVariablePrepended = 'variable:' + $RandomVarName
    If((Get-Random -Input @(0..1)) -eq 0)
    {
        $RandomVarNameMaybeConcatenated = '(' + (Out-ConcatenatedString $RandomVarName (Get-Random -Input @('"',"'"))) + ')'
        $RandomVarNameMaybeConcatenatedWithVariablePrepended = '(' + (Out-ConcatenatedString "variable:$RandomVarName" (Get-Random -Input @('"',"'"))) + ')'
    }

    # Placeholder for values to be SET in variable differently in each Switch statement below.
    $RandomVarValPlaceholder = '<[)(]>'

    # Generate random variable SET syntax.
    $RandomVarSetSyntax  = @()
    $RandomVarSetSyntax += '$' + $RandomVarName + ' '*(Get-Random @(0..2)) + '=' + ' '*(Get-Random @(0..2)) + $RandomVarValPlaceholder
    $RandomVarSetSyntax += (Get-Random -Input @('Set-Variable','SV','Set')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $RandomVarValPlaceholder + ' '*(Get-Random @(0..2)) + ')'
    
    # Randomly choose from above variable syntaxes.
    $RandomVarSet = (Get-Random -Input $RandomVarSetSyntax)

    # Randomize the case of selected variable syntaxes.
    $RandomVarSet = Out-RandomCase $RandomVarSet
    
    # Generate random variable GET syntax.
    $RandomVarGetSyntax  = @()
    $RandomVarGetSyntax += '$' + $RandomVarName
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('Get-Variable','Variable')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + (Get-Random -Input ((' '*(Get-Random @(0..2)) + ').Value'),(' '*(Get-Random @(1..2)) + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ' '*(Get-Random @(0..2)) + ')')))
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenatedWithVariablePrepended + ' '*(Get-Random @(0..2)) + ').Value'
    
    # Randomly choose from above variable syntaxes.
    $RandomVarGet = (Get-Random -Input $RandomVarGetSyntax)

    # Randomize the case of selected variable syntaxes.
    $RandomVarGet = Out-RandomCase $RandomVarGet

    # Generate random syntax to create/set OFS variable ($OFS is the Output Field Separator automatic variable).
    # Using Set-Item and Set-Variable/SV/SET syntax. Not using New-Item in case OFS variable already exists.
    # If the OFS variable did exists then we could use even more syntax: $varname, Set-Variable/SV, Set-Item/SET, Get-Variable/GV/Variable, Get-ChildItem/GCI/ChildItem/Dir/Ls
    # For more info: https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_automatic_variables
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += '$OFS' + ' '*(Get-Random -Input @(0,1)) + '=' + ' '*(Get-Random -Input @(0,1))  + "''"
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)

    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)

    # Randomize the case of selected variable syntaxes.
    $SetOfsVar            = Out-RandomCase $SetOfsVar
    $SetOfsVarBack        = Out-RandomCase $SetOfsVarBack
    $StringStr            = Out-RandomCase 'string'
    $JoinStr              = Out-RandomCase 'join'
    $LengthStr            = Out-RandomCase 'length'
    $ArrayStr             = Out-RandomCase 'array'
    $ReverseStr           = Out-RandomCase 'reverse'
    $CharStr              = Out-RandomCase 'char'
    $RightToLeftStr       = Out-RandomCase 'righttoleft'
    $RegexStr             = Out-RandomCase 'regex'
    $MatchesStr           = Out-RandomCase 'matches'
    $ValueStr             = Out-RandomCase 'value'
    $ForEachObject        = Out-RandomCase (Get-Random -Input @('ForEach-Object','ForEach','%'))

    # Select random method for building command to reverse the now-reversed $ScriptString to execute the original command.
    Switch(Get-Random -Input (1..3)) {
        1 {
            # 1) $StringVar = $String; $StringVar[-1..-($StringVar.Length)] -Join ''
            
            # Replace placeholder with appropriate value for this Switch statement.
            $RandomVarSet = $RandomVarSet.Replace($RandomVarValPlaceholder,('"' + ' '*(Get-Random -Input @(0,1)) + $ScriptStringReversed + ' '*(Get-Random -Input @(0,1)) + '"'))

            # Set $ScriptStringReversed as environment variable $Random.
            $ScriptString = $RandomVarSet + ' '*(Get-Random -Input @(0,1)) + ';' + ' '*(Get-Random -Input @(0,1))
            
            $RandomVarGet = $RandomVarGet + '[' + ' '*(Get-Random -Input @(0,1)) + '-' + ' '*(Get-Random -Input @(0,1)) + '1' + ' '*(Get-Random -Input @(0,1)) + '..' + ' '*(Get-Random -Input @(0,1)) + '-' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ".$LengthStr" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ']'

            # Build out random syntax depending on whether -Join is prepended or -Join '' is appended.
            # Now also includes [String]::Join .Net syntax and [String] syntax after modifying $OFS variable to ''.
            $JoinOptions  = @()
            $JoinOptions += "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet
            $JoinOptions += $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "''"
            $JoinOptions += "[$StringStr]::$JoinStr" + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $RandomVarGet) + ' '*(Get-Random -Input @(0,1)) + ')'
            $JoinOptions += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + "[$StringStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
            $JoinOption = (Get-Random -Input $JoinOptions)
            
            # Encapsulate in necessary IEX/Invoke-Expression(s).
            $JoinOption = Out-EncapsulatedInvokeExpression $JoinOption
            
            $ScriptString = $ScriptString + $JoinOption
        }
        2 {
            # 2) $StringVar = [Char[]]$String; [Array]::Reverse($StringVar); $StringVar -Join ''
            
            # Replace placeholder with appropriate value for this Switch statement.
            $RandomVarSet = $RandomVarSet.Replace($RandomVarValPlaceholder,("[$CharStr[" + ' '*(Get-Random -Input @(0,1)) + ']' + ' '*(Get-Random -Input @(0,1)) + ']' + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"'))

            # Set $ScriptStringReversed as environment variable $Random.
            $ScriptString = $RandomVarSet + ' '*(Get-Random -Input @(0,1)) + ';' + ' '*(Get-Random -Input @(0,1))
            $ScriptString = $ScriptString + ' '*(Get-Random -Input @(0,1)) + "[$ArrayStr]::$ReverseStr(" + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ';'

            # Build out random syntax depending on whether -Join is prepended or -Join '' is appended.
            # Now also includes [String]::Join .Net syntax and [String] syntax after modifying $OFS variable to ''.
            $JoinOptions  = @()
            $JoinOptions += "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet
            $JoinOptions += $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "''"
            $JoinOptions += "[$StringStr]::$JoinStr" + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')'
            $JoinOptions += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + "[$StringStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
            $JoinOption = (Get-Random -Input $JoinOptions)
            
            # Encapsulate in necessary IEX/Invoke-Expression(s).
            $JoinOption = Out-EncapsulatedInvokeExpression $JoinOption
            
            $ScriptString = $ScriptString + $JoinOption
        }
        3 {
            # 3) -Join[Regex]::Matches($String,'.','RightToLeft')

            # Randomly choose to use 'RightToLeft' or concatenated version of this string in $JoinOptions below.
            If(Get-Random -Input (0..1))
            {
                $RightToLeft = Out-ConcatenatedString $RightToLeftStr "'"
            }
            Else
            {
                $RightToLeft = "'$RightToLeftStr'"
            }
            
            # Build out random syntax depending on whether -Join is prepended or -Join '' is appended.
            # Now also includes [String]::Join .Net syntax and [String] syntax after modifying $OFS variable to ''.
            $JoinOptions  = @()
            $JoinOptions += ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
            $JoinOptions += ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' +  ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
            $JoinOptions += ' '*(Get-Random -Input @(0,1)) + "[$StringStr]::$JoinStr(" + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '$_' + ".$ValueStr" + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
            $JoinOptions += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' +          ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "[$StringStr]" + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '$_' + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'             + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
            $ScriptString = (Get-Random -Input $JoinOptions)
            
            # Encapsulate in necessary IEX/Invoke-Expression(s).
            $ScriptString = Out-EncapsulatedInvokeExpression $ScriptString
        }
        default {Write-Error "An invalid value was passed to switch block."; Exit;}
    }
    
    # Perform final check to remove ticks if they now precede lowercase special characters after the string is reversed.
    # E.g. "testin`G" in reverse would be "G`nitset" where `n would be interpreted as a newline character.
    $SpecialCharacters = @('a','b','f','n','r','t','v','0')
    ForEach($SpecialChar in $SpecialCharacters)
    {
        If($ScriptString.Contains("``"+$SpecialChar))
        {
            $ScriptString = $ScriptString.Replace("``"+$SpecialChar,$SpecialChar)
        }
    }
    
    Return $ScriptString
}


Function Out-EncapsulatedInvokeExpression
{
<#
.SYNOPSIS

HELPER FUNCTION :: Generates random syntax for invoking input PowerShell command.

Invoke-Obfuscation Function: Out-EncapsulatedInvokeExpression
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-EncapsulatedInvokeExpression generates random syntax for invoking input PowerShell command. It uses a combination of IEX and Invoke-Expression as well as ordering (IEX $Command , $Command | IEX).

.PARAMETER ScriptString

Specifies the string containing your payload.

.EXAMPLE

C:\PS> Out-EncapsulatedInvokeExpression {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green}

Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green|Invoke-Expression

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedStringCommand function with the corresponding obfuscation level since Out-Out-ObfuscatedStringCommand will handle calling this current function where necessary.
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 1
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 2
C:\PS> Out-ObfuscatedStringCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 3
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString
    )

    # The below code block is copy/pasted into almost every encoding function so they can maintain zero dependencies and work on their own (I admit using this bad coding practice).
    # Changes to below InvokeExpressionSyntax block should also be copied to those functions.
    # Generate random invoke operation syntax.
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    # Added below slightly-randomized obfuscated ways to form the string 'iex' and then invoke it with . or &.
    # Though far from fully built out, these are included to highlight how IEX/Invoke-Expression is a great indicator but not a silver bullet.
    # These methods draw on common environment variable values and PowerShell Automatic Variable values/methods/members/properties/etc.
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:Public[13]+`$env:Public[5]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    
    # Randomly choose from above invoke operation syntaxes.
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)

    # Randomize the case of selected invoke operation.
    $InvokeExpression = Out-RandomCase $InvokeExpression
    
    # Choose random Invoke-Expression/IEX syntax and ordering: IEX ($ScriptString) or ($ScriptString | IEX)
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $ScriptString + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $ScriptString + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression

    $ScriptString = (Get-Random -Input $InvokeOptions)

    Return $ScriptString
}

#   This file is part of Invoke-Obfuscation.
#
#   Copyright 2017 Daniel Bohannon <@danielhbohannon>
#         while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.



Function Out-ObfuscatedTokenCommand
{
<#
.SYNOPSIS

Master function that orchestrates the tokenization and application of all token-based obfuscation functions to provided PowerShell script.

Invoke-Obfuscation Function: Out-ObfuscatedTokenCommand
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedTokenCommand orchestrates the tokenization and application of all token-based obfuscation functions to provided PowerShell script and places obfuscated tokens back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. If no $TokenTypeToObfuscate is defined then Out-ObfuscatedTokenCommand will automatically perform ALL token obfuscation functions in random order at the highest obfuscation level.

.PARAMETER ScriptBlock

Specifies a scriptblock containing your payload.

.PARAMETER Path

Specifies the path to your payload.

.PARAMETER TokenTypeToObfuscate

(Optional) Specifies the token type to obfuscate ('Command', 'CommandArgument', 'Comment', 'Member', 'String', 'Type', 'Variable', 'RandomWhitespace'). If not defined then Out-ObfuscatedTokenCommand will automatically perform ALL token obfuscation functions in random order at the highest obfuscation level.

.PARAMETER ObfuscationLevel

(Optional) Specifies the obfuscation level for the given TokenTypeToObfuscate. If not defined then Out-ObfuscatedTokenCommand will automatically perform obfuscation function at the highest available obfuscation level. 
Each token has different available obfuscation levels:
'Argument' 1-4
'Command' 1-3
'Comment' 1
'Member' 1-4
'String' 1-2
'Type' 1-2
'Variable' 1
'Whitespace' 1
'All' 1

.EXAMPLE

C:\PS> Out-ObfuscatedTokenCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green}

.(  "{0}{2}{1}" -f'Write','t','-Hos'  ) ( 'Hell' + 'o '  +'Wor'+  'ld!'  ) -ForegroundColor (  "{1}{0}" -f 'een','Gr') ;    .(  "{1}{2}{0}"-f'ost','Writ','e-H' ) (  'O' + 'bfusca'+  't' +  'ion Rocks'  + '!') -ForegroundColor (  "{1}{0}"-f'een','Gr' )

.NOTES

Out-ObfuscatedTokenCommand orchestrates the tokenization and application of all token-based obfuscation functions to provided PowerShell script and places obfuscated tokens back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. If no $TokenTypeToObfuscate is defined then Out-ObfuscatedTokenCommand will automatically perform ALL token obfuscation functions in random order at the highest obfuscation level.
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [ValidateSet('Member', 'Command', 'CommandArgument', 'String', 'Variable', 'Type', 'RandomWhitespace', 'Comment')]
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TokenTypeToObfuscate,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $ObfuscationLevel = 10 # Default to highest obfuscation level if $ObfuscationLevel isn't defined
    )

    # Either convert ScriptBlock to a String or convert script at $Path to a String.
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    
    # If $TokenTypeToObfuscate was not defined then we will automate randomly calling all available obfuscation functions in Out-ObfuscatedTokenCommand.
    If($TokenTypeToObfuscate.Length -eq 0)
    {
        # All available obfuscation token types (minus 'String') currently supported in Out-ObfuscatedTokenCommand.
        # 'Comment' and 'String' will be manually added first and second respectively for reasons defined below.
        # 'RandomWhitespace' will be manually added last for reasons defined below.
        $ObfuscationChoices  = @()
        $ObfuscationChoices += 'Member'
        $ObfuscationChoices += 'Command'
        $ObfuscationChoices += 'CommandArgument'
        $ObfuscationChoices += 'Variable'
        $ObfuscationChoices += 'Type'
        
        # Create new array with 'String' plus all obfuscation types above in random order. 
        $ObfuscationTypeOrder = @()
        # Run 'Comment' first since it will be the least number of tokens to iterate through, and comments may be introduced as obfuscation technique in future revisions.
        $ObfuscationTypeOrder += 'Comment'
        # Run 'String' second since otherwise we will have unnecessary command bloat since other obfuscation functions create additional strings.
        $ObfuscationTypeOrder += 'String'
        $ObfuscationTypeOrder += (Get-Random -Input $ObfuscationChoices -Count $ObfuscationChoices.Count)

        # Apply each randomly-ordered $ObfuscationType from above step.
        ForEach($ObfuscationType in $ObfuscationTypeOrder) 
        {
            $ScriptString = Out-ObfuscatedTokenCommand ([ScriptBlock]::Create($ScriptString)) $ObfuscationType $ObfuscationLevel
        }
        Return $ScriptString
    }

    # Parse out and obfuscate tokens (in reverse to make indexes simpler for adding in obfuscated tokens).
    $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
    
    # Handle fringe case of retrieving count of all tokens used when applying random whitespace.
    $TokenCount = ([System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq $TokenTypeToObfuscate}).Count
    $TokensForInsertingWhitespace = @('Operator','GroupStart','GroupEnd','StatementSeparator')

    # Script-wide variable ($Script:TypeTokenScriptStringGrowth) to speed up Type token obfuscation by avoiding having to re-tokenize ScriptString for every token.
    # This is because we are appending variable instantiation at the beginning of each iteration of ScriptString.
    # Additional script-wide variable ($Script:TypeTokenVariableArray) allows each unique Type token to only be set once per command/script for efficiency and to create less items to create indicators off of.
    $Script:TypeTokenScriptStringGrowth = 0
    $Script:TypeTokenVariableArray = @()
    
    If($TokenTypeToObfuscate -eq 'RandomWhitespace')
    {
        # If $TokenTypeToObfuscate='RandomWhitespace' then calculate $TokenCount for output by adding token count for all tokens in $TokensForInsertingWhitespace.
        $TokenCount = 0
        ForEach($TokenForInsertingWhitespace in $TokensForInsertingWhitespace)
        {
            $TokenCount += ([System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq $TokenForInsertingWhitespace}).Count
        }
    }

    # Handle fringe case of outputting verbiage consistent with options presented in Invoke-Obfuscation.
    If($TokenCount -gt 0)
    {
        # To be consistent with verbiage in Invoke-Obfuscation we will print Argument/Whitespace instead of CommandArgument/RandomWhitespace.
        $TokenTypeToObfuscateToPrint = $TokenTypeToObfuscate
        If($TokenTypeToObfuscateToPrint -eq 'CommandArgument')  {$TokenTypeToObfuscateToPrint = 'Argument'}
        If($TokenTypeToObfuscateToPrint -eq 'RandomWhitespace') {$TokenTypeToObfuscateToPrint = 'Whitespace'}
        If($TokenCount -gt 1) {$Plural = 's'}
        Else {$Plural = ''}

        # Output verbiage concerning which $TokenType is currently being obfuscated and how many tokens of each type are left to obfuscate.
        # This becomes more important when obfuscated large scripts where obfuscation can take several minutes due to all of the randomization steps.
        Write-Host "`n[*] Obfuscating $($TokenCount)" -NoNewLine
        Write-Host " $TokenTypeToObfuscateToPrint" -NoNewLine -ForegroundColor Yellow
        Write-Host " token$Plural."
    }

    # Variables for outputting status of token processing for large token counts when obfuscating large scripts.
    $Counter = $TokenCount
    $OutputCount = 0
    $IterationsToOutputOn = 100
    $DifferenceForEvenOutput = $TokenCount % $IterationsToOutputOn
    
    For($i=$Tokens.Count-1; $i -ge 0; $i--)
    {
        $Token = $Tokens[$i]

        # Extra output for large scripts with several thousands tokens (like Invoke-Mimikatz).
        If(($TokenCount -gt $IterationsToOutputOn*2) -AND ((($TokenCount-$Counter)-($OutputCount*$IterationsToOutputOn)) -eq ($IterationsToOutputOn+$DifferenceForEvenOutput)))
        {
            $OutputCount++
            $ExtraWhitespace = ' '*(([String]($TokenCount)).Length-([String]$Counter).Length)
            If($Counter -gt 0)
            {
                Write-Host "[*]             $ExtraWhitespace$Counter" -NoNewLine
                Write-Host " $TokenTypeToObfuscateToPrint" -NoNewLine -ForegroundColor Yellow
                Write-Host " tokens remaining to obfuscate."
            }
        }

        $ObfuscatedToken = ""

        If(($Token.Type -eq 'String') -AND ($TokenTypeToObfuscate.ToLower() -eq 'string')) 
        {
            $Counter--

            # If String $Token immediately follows a period (and does not begin $ScriptString) then do not obfuscate as a String.
            # In this scenario $Token is originally a Member token that has quotes added to it.
            # E.g. both InvokeCommand and InvokeScript in $ExecutionContext.InvokeCommand.InvokeScript
            If(($Token.Start -gt 0) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '.'))
            {
                Continue
            }
            
            # Set valid obfuscation levels for current token type.
            $ValidObfuscationLevels = @(0,1,2)

            # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}  

            # The below Parameter Binding Validation Attributes cannot have their string values formatted with the -f format operator unless treated as a scriptblock.
            # When we find strings following these Parameter Binding Validation Attributes then if we are using a -f format operator we will treat the result as a scriptblock.
            # Source: https://technet.microsoft.com/en-us/library/hh847743.aspx
            $ParameterValidationAttributesToTreatStringAsScriptblock  = @()
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'alias'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'allownull'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'allowemptystring'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'allowemptycollection'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatecount'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatelength'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatepattern'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validaterange'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatescript'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validateset'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatenotnull'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatenotnullorempty'

            $ParameterValidationAttributesToTreatStringAsScriptblock += 'helpmessage'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'confirmimpact'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'outputtype'

            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-ObfuscatedStringTokenLevel1 $ScriptString $Token 1}
                2 {$ScriptString = Out-ObfuscatedStringTokenLevel1 $ScriptString $Token 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }

        }
        ElseIf(($Token.Type -eq 'Member') -AND ($TokenTypeToObfuscate.ToLower() -eq 'member')) 
        {
            $Counter--

            # Set valid obfuscation levels for current token type.
            $ValidObfuscationLevels = @(0,1,2,3,4)
            
            # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}

            # The below Parameter Attributes cannot be obfuscated like other Member Tokens, so we will only randomize the case of these tokens.
            # Source 1: https://technet.microsoft.com/en-us/library/hh847743.aspx
            $MemberTokensToOnlyRandomCase  = @()
            $MemberTokensToOnlyRandomCase += 'mandatory'
            $MemberTokensToOnlyRandomCase += 'position'
            $MemberTokensToOnlyRandomCase += 'parametersetname'
            $MemberTokensToOnlyRandomCase += 'valuefrompipeline'
            $MemberTokensToOnlyRandomCase += 'valuefrompipelinebypropertyname'
            $MemberTokensToOnlyRandomCase += 'valuefromremainingarguments'
            $MemberTokensToOnlyRandomCase += 'helpmessage'
            $MemberTokensToOnlyRandomCase += 'alias'
            # Source 2: https://technet.microsoft.com/en-us/library/hh847872.aspx
            $MemberTokensToOnlyRandomCase += 'confirmimpact'
            $MemberTokensToOnlyRandomCase += 'defaultparametersetname'
            $MemberTokensToOnlyRandomCase += 'helpuri'
            $MemberTokensToOnlyRandomCase += 'supportspaging'
            $MemberTokensToOnlyRandomCase += 'supportsshouldprocess'
            $MemberTokensToOnlyRandomCase += 'positionalbinding'

            $MemberTokensToOnlyRandomCase += 'ignorecase'

            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-RandomCaseToken             $ScriptString $Token}
                2 {$ScriptString = Out-ObfuscatedWithTicks         $ScriptString $Token}
                3 {$ScriptString = Out-ObfuscatedMemberTokenLevel3 $ScriptString $Tokens $i 1}
                4 {$ScriptString = Out-ObfuscatedMemberTokenLevel3 $ScriptString $Tokens $i 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'CommandArgument') -AND ($TokenTypeToObfuscate.ToLower() -eq 'commandargument')) 
        {
            $Counter--

            # Set valid obfuscation levels for current token type.
            $ValidObfuscationLevels = @(0,1,2,3,4)
            
            # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 
            
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-RandomCaseToken                      $ScriptString $Token}
                2 {$ScriptString = Out-ObfuscatedWithTicks                  $ScriptString $Token}
                3 {$ScriptString = Out-ObfuscatedCommandArgumentTokenLevel3 $ScriptString $Token 1}
                4 {$ScriptString = Out-ObfuscatedCommandArgumentTokenLevel3 $ScriptString $Token 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'Command') -AND ($TokenTypeToObfuscate.ToLower() -eq 'command')) 
        {
            $Counter--

            # Set valid obfuscation levels for current token type.
            $ValidObfuscationLevels = @(0,1,2,3)
            
            # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}

            # If a variable is encapsulated in curly braces (e.g. ${ExecutionContext}) then the string inside is treated as a Command token.
            # So we will force tick obfuscation (option 1) instead of splatting (option 2) as that would cause errors.
            If(($Token.Start -gt 1) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '{') -AND ($ScriptString.SubString($Token.Start+$Token.Length,1) -eq '}'))
            {
                $ObfuscationLevel = 1
            }
            
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-ObfuscatedWithTicks          $ScriptString $Token}
                2 {$ScriptString = Out-ObfuscatedCommandTokenLevel2 $ScriptString $Token 1}
                3 {$ScriptString = Out-ObfuscatedCommandTokenLevel2 $ScriptString $Token 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'Variable') -AND ($TokenTypeToObfuscate.ToLower() -eq 'variable'))
        {
            $Counter--

            # Set valid obfuscation levels for current token type.
            $ValidObfuscationLevels = @(0,1)
            
            # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 

            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-ObfuscatedVariableTokenLevel1 $ScriptString $Token}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'Type') -AND ($TokenTypeToObfuscate.ToLower() -eq 'type')) 
        {
            $Counter--

            # Set valid obfuscation levels for current token type.
            $ValidObfuscationLevels = @(0,1,2)
            
            # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 

            # The below Type value substrings are part of Types that cannot be direct Type casted, so we will not perform direct Type casting on Types containing these values.
            $TypesThatCannotByDirectTypeCasted  = @()
            $TypesThatCannotByDirectTypeCasted += 'directoryservices.accountmanagement.'
            $TypesThatCannotByDirectTypeCasted += 'windows.clipboard'

            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-ObfuscatedTypeToken $ScriptString $Token 1}
                2 {$ScriptString = Out-ObfuscatedTypeToken $ScriptString $Token 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($TokensForInsertingWhitespace -Contains $Token.Type) -AND ($TokenTypeToObfuscate.ToLower() -eq 'randomwhitespace')) 
        {
            $Counter--

            # Set valid obfuscation levels for current token type.
            $ValidObfuscationLevels = @(0,1)
            
            # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 

            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-RandomWhitespace $ScriptString $Tokens $i}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'Comment') -AND ($TokenTypeToObfuscate.ToLower() -eq 'comment'))
        {
            $Counter--

            # Set valid obfuscation levels for current token type.
            $ValidObfuscationLevels = @(0,1)
            
            # If invalid obfuscation level is passed to this function then default to highest obfuscation level available for current token type.
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 
            
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-RemoveComments $ScriptString $Token}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }   
    }

    Return $ScriptString
}


Function Out-ObfuscatedStringTokenLevel1
{
<#
.SYNOPSIS

Obfuscates string token by randomly concatenating the string in-line.

Invoke-Obfuscation Function: Out-ObfuscatedStringTokenLevel1
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-StringDelimitedAndConcatenated, Out-StringDelimitedConcatenatedAndReordered (both located in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedStringTokenLevel1 obfuscates a given string token and places it back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Token

Specifies the token to obfuscate.

.PARAMETER ObfuscationLevel

Specifies whether to 1) Concatenate or 2) Reorder the String token value.

.EXAMPLE

C:\PS> $ScriptString = "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'String'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedStringTokenLevel1 $ScriptString $Token 1}
C:\PS> $ScriptString

Write-Host ('Hello'+' W'+'orl'+'d!') -ForegroundColor Green; Write-Host ('Obfuscation R'+'oc'+'k'+'s'+'!') -ForegroundColor Green

C:\PS> $ScriptString = "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'String'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedStringTokenLevel1 $ScriptString $Token 2}
C:\PS> $ScriptString

Write-Host ("{2}{3}{0}{1}" -f 'Wo','rld!','Hel','lo ') -ForegroundColor Green; Write-Host ("{4}{0}{3}{2}{1}"-f 'bfusca','cks!','Ro','tion ','O') -ForegroundColor Green

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 'String' 1
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )

    $EncapsulateAsScriptBlockInsteadOfParentheses = $FALSE

    # Extract substring to look for parameter binding values to check against $ParameterValidationAttributesToTreatStringAsScriptblock set in the beginning of this script.
    $SubStringLength = 25
    If($Token.Start -lt $SubStringLength)
    {
        $SubStringLength = $Token.Start
    }
    $SubString = $ScriptString.SubString($Token.Start-$SubStringLength,$SubStringLength).Replace(' ','').Replace("`t",'').Replace("`n",'')
    $SubStringLength = 5
    If($SubString.Length -lt $SubStringLength)
    {
        $SubStringLength = $SubString.Length
    }
    $SubString = $SubString.SubString($SubString.Length-$SubStringLength,$SubStringLength)

    # If dealing with ObfuscationLevel -gt 1 (e.g. -f format operator), perform check to see if we're dealing with a string that is part of a Parameter Binding.
    If(($ObfuscationLevel -gt 1) -AND ($Token.Start -gt 5) -AND ($SubString.Contains('(') -OR $SubString.Contains(',')) -AND $ScriptString.SubString(0,$Token.Start).Contains('[') -AND $ScriptString.SubString(0,$Token.Start).Contains('('))
    {
	    # Gather substring preceding the current String token to see if we need to treat the obfuscated string as a scriptblock.
	    $ParameterBindingName = $ScriptString.SubString(0,$Token.Start)
	    $ParameterBindingName = $ParameterBindingName.SubString(0,$ParameterBindingName.LastIndexOf('('))
	    $ParameterBindingName = $ParameterBindingName.SubString($ParameterBindingName.LastIndexOf('[')+1).Trim()
	    # Filter out values that are not Parameter Binding due to contain whitespace, some special characters, etc.
	    If(!$ParameterBindingName.Contains(' ') -AND !$ParameterBindingName.Contains('.') -AND !$ParameterBindingName.Contains(']') -AND !($ParameterBindingName.Length -eq 0))
	    {
		    # If we have a match then set boolean to True so result will be encapsulated with curly braces at the end of this function.
		    If($ParameterValidationAttributesToTreatStringAsScriptblock -Contains $ParameterBindingName.ToLower())
		    {
			    $EncapsulateAsScriptBlockInsteadOfParentheses = $TRUE
		    }
	    }
    }
    ElseIf(($ObfuscationLevel -gt 1) -AND ($Token.Start -gt 5) -AND $ScriptString.SubString($Token.Start-5,5).Contains('='))
    {
        # If dealing with ObfuscationLevel -gt 1 (e.g. -f format operator), perform check to see if we're dealing with a string that is part of a Parameter Binding.
        ForEach($Parameter in $ParameterValidationAttributesToTreatStringAsScriptblock)
        {
            $SubStringLength = $Parameter.Length
                
            # Add 10 more to $SubStringLength in case there is excess whitespace between the = sign.
            $SubStringLength += 10

            # Shorten substring length in case there is not enough room depending on the location of the token in the $ScriptString.
            If($Token.Start -lt $SubStringLength)
            {
                $SubStringLength = $Token.Start
            }

            # Extract substring to compare against $EncapsulateAsScriptBlockInsteadOfParentheses.
            $SubString = $ScriptString.SubString($Token.Start-$SubStringLength,$SubStringLength+1).Trim()

            # If we have a match then set boolean to True so result will be encapsulated with curly braces at the end of this function.
            If($SubString -Match "$Parameter.*=")
            {
                $EncapsulateAsScriptBlockInsteadOfParentheses = $TRUE
            }
        }
    }

    # Do nothing if the token has length <= 1 (e.g. Write-Host "", single-character tokens, etc.).
    If($Token.Content.Length -le 1) {Return $ScriptString}
    
    # Do nothing if the token has length <= 3 and $ObfuscationLevel is 2 (reordering).
    If(($Token.Content.Length -le 3) -AND $ObfuscationLevel -eq 2) {Return $ScriptString}

    # Do nothing if $Token.Content already contains a { or } to avoid parsing errors when { and } are introduced into substrings.
    If($Token.Content.Contains('{') -OR $Token.Content.Contains('}')) {Return $ScriptString}

    # If the Token is 'invoke' then do nothing. This is because .invoke() is treated as a member but ."invoke"() is treated as a string.
    If($Token.Content.ToLower() -eq 'invoke') {Return $ScriptString}

    # Set $Token.Content in a separate variable so it can be modified since Content is a ReadOnly property of $Token.
    $TokenContent = $Token.Content

    # Tokenizer removes ticks from strings, but we want to keep them. So we will replace the contents of $Token.Content with the manually extracted token data from the original $ScriptString.
    $TokenContent = $ScriptString.SubString($Token.Start+1,$Token.Length-2)

    # If a variable is present in a string, more work needs to be done to extract from string. Warning maybe should be thrown either way.
    # Must come back and address this after vacation.
    # Variable can be displaying or setting: "setting var like $($var='secret') and now displaying $var"
    # For now just split on whitespace instead of passing to Out-Concatenated
    If($TokenContent.Contains('$') -OR $TokenContent.Contains('`'))
    {
        $ObfuscatedToken = ''
        $Counter = 0

        # If special use case is met then don't substring the current Token to avoid errors.
        # The special cases involve a double-quoted string containing a variable or a string-embedded-command that contains whitespace in it.
        # E.g. "string ${var name with whitespace} string" or "string $(gci *whitespace_in_command*) string"
        $TokenContentSplit = $TokenContent.Split(' ')
        $ContainsVariableSpecialCases = (($TokenContent.Contains('$(') -OR $TokenContent.Contains('${')) -AND ($ScriptString[$Token.Start] -eq '"'))
        
        If($ContainsVariableSpecialCases)
        {
            $TokenContentSplit = $TokenContent
        }

        ForEach($SubToken in $TokenContentSplit)
        {
            $Counter++
            
            $ObfuscatedSubToken = $SubToken

            # Determine if use case of variable inside of double quotes is present as this will be handled differently below.
            $SpecialCaseContainsVariableInDoubleQuotes = (($ObfuscatedSubToken.Contains('$') -OR $ObfuscatedSubToken.Contains('`')) -AND ($ScriptString[$Token.Start] -eq '"'))

            # Since splitting on whitespace removes legitimate whitespace we need to add back whitespace for all but the final subtoken.
            If($Counter -lt $TokenContent.Split(' ').Count)
            {
                $ObfuscatedSubToken = $ObfuscatedSubToken + ' '
            }

            # Concatenate $SubToken if it's long enough to be concatenated.
            If(($ObfuscatedSubToken.Length -gt 1) -AND !($SpecialCaseContainsVariableInDoubleQuotes))
            {
                # Concatenate each $SubToken via Out-StringDelimitedAndConcatenated so it will handle any replacements for special characters.
                # Define -PassThru flag so an invocation is not added to $ObfuscatedSubToken.
                $ObfuscatedSubToken = Out-StringDelimitedAndConcatenated $ObfuscatedSubToken -PassThru
            
                # Evenly trim leading/trailing parentheses.
                While($ObfuscatedSubToken.StartsWith('(') -AND $ObfuscatedSubToken.EndsWith(')'))
                {
                    $ObfuscatedSubToken = ($ObfuscatedSubToken.SubString(1,$ObfuscatedSubToken.Length-2)).Trim()
                }
            }
            Else
            {
                If($SpecialCaseContainsVariableInDoubleQuotes)
                {
                    $ObfuscatedSubToken = '"' + $ObfuscatedSubToken + '"'
                }
                ElseIf($ObfuscatedSubToken.Contains("'") -OR $ObfuscatedSubToken.Contains('$'))
                {
                    $ObfuscatedSubToken = '"' + $ObfuscatedSubToken + '"'
                }
                Else
                {
                    $ObfuscatedSubToken = "'" + $ObfuscatedSubToken + "'"
                }
            }

            # Add obfuscated/trimmed $SubToken back to $ObfuscatedToken if a Replace operation was used.
            If($ObfuscatedSubToken -eq $PreObfuscatedSubToken)
            {
                # Same, so don't encapsulate. And maybe take off trailing whitespace?
            }
            ElseIf($ObfuscatedSubToken.ToLower().Contains("replace"))
            {
                $ObfuscatedToken += ( '(' + $ObfuscatedSubToken + ')' + '+' )
            }
            Else
            {
                $ObfuscatedToken += ($ObfuscatedSubToken + '+' )
            }
        }

        # Trim extra whitespace and trailing + from $ObfuscatedToken.
        $ObfuscatedToken = $ObfuscatedToken.Trim(' + ')
    }
    Else
    {
        # For Parameter Binding the value has to either be plain concatenation or must be a scriptblock in which case we will encapsulate with {} instead of ().
        # The encapsulation will occur later in the function. At this point we're just setting the boolean variable $EncapsulateAsScriptBlockInsteadOfParentheses.
        # Actual error that led to this is: "Attribute argument must be a constant or a script block."
        # ALLOWED     :: [CmdletBinding(DefaultParameterSetName={"{1}{0}{2}"-f'd','DumpCre','s'})]
        # NOT ALLOWED :: [CmdletBinding(DefaultParameterSetName=("{1}{0}{2}"-f'd','DumpCre','s'))]
        $SubStringStart = 30
        If($Token.Start -lt $SubStringStart)
        {
            $SubStringStart = $Token.Start
        }

        $SubString = $ScriptString.SubString($Token.Start-$SubStringStart,$SubStringStart).ToLower()

        If($SubString.Contains('defaultparametersetname') -AND $SubString.Contains('='))
        {
            $EncapsulateAsScriptBlockInsteadOfParentheses = $TRUE
        }

        If($SubString.Contains('parametersetname') -AND !$SubString.Contains('defaultparametersetname') -AND $SubString.Contains('='))
        {
            # For strings in ParameterSetName parameter binding (but not DefaultParameterSetName) then we will only obfuscate with tick marks.
            # Otherwise we may get errors depending on the version of PowerShell being run.
            $ObfuscatedToken = $Token.Content
            $TokenForTicks = [System.Management.Automation.PSParser]::Tokenize($ObfuscatedToken,[ref]$null)
            $ObfuscatedToken = '"' + (Out-ObfuscatedWithTicks $ObfuscatedToken $TokenForTicks[0]) + '"'
        }
        Else
        {
            # User input $ObfuscationLevel (1-2) will choose between concatenating String token value string or reordering it with the -f format operator.
            # I am leaving out Out-ObfuscatedStringCommand's option 3 since that may introduce a Type token unnecessarily ([Regex]).
            Switch($ObfuscationLevel)
            {
                1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
                2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for String Token Obfuscation."; Exit}
            }
        }

        # Evenly trim leading/trailing parentheses.
        While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
        {
            $ObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
        }
    }

    # Encapsulate concatenated string with parentheses to avoid garbled string in scenarios like Write-* methods.
    If($ObfuscatedToken.Length -ne ($TokenContent.Length + 2))
    {
        # For Parameter Binding the value has to either be plain concatenation or must be a scriptblock in which case we will encapsulate with {} instead of ().
        # Actual error that led to this is: "Attribute argument must be a constant or a script block."
        # ALLOWED     :: [CmdletBinding(DefaultParameterSetName={"{1}{0}{2}"-f'd','DumpCre','s'})]
        # NOT ALLOWED :: [CmdletBinding(DefaultParameterSetName=("{1}{0}{2}"-f'd','DumpCre','s'))]
        If($EncapsulateAsScriptBlockInsteadOfParentheses)
        {
            $ObfuscatedToken = '{' + $ObfuscatedToken + '}'
        }
        ElseIf(($ObfuscatedToken.Length -eq $TokenContent.Length + 5) -AND $ObfuscatedToken.SubString(2,$ObfuscatedToken.Length-4) -eq ($TokenContent + ' '))
        {
            $ObfuscatedToken = $TokenContent
        }
        ElseIf($ObfuscatedToken.StartsWith('"') -AND $ObfuscatedToken.EndsWith('"') -AND !$ObfuscatedToken.Contains('+') -AND !$ObfuscatedToken.Contains('-f'))
        {
            # No encapsulation is needed for string obfuscation that is only double quotes and tick marks for ParameterSetName (and not DefaultParameterSetName).
            $ObfuscatedToken = $ObfuscatedToken
        }
        ElseIf($ObfuscatedToken.Length -ne $TokenContent.Length + 2)
        {
            $ObfuscatedToken = '(' + $ObfuscatedToken + ')'
        }
    }

    # Remove redundant blank string concatenations introduced by special use case of $ inside double quotes.
    If($ObfuscatedToken.EndsWith("+''") -OR $ObfuscatedToken.EndsWith('+""'))
    {
        $ObfuscatedToken = $ObfuscatedToken.SubString(0,$ObfuscatedToken.Length-3)
    }

    # Handle dangling ticks from string concatenation where a substring ends in a tick. Move this tick to the beginning of the following substring.
    If($ObfuscatedToken.Contains('`'))
    {
        If($ObfuscatedToken.Contains('`"+"'))
        {
            $ObfuscatedToken = $ObfuscatedToken.Replace('`"+"','"+"`')
        }
        If($ObfuscatedToken.Contains("``'+'"))
        {
            $ObfuscatedToken = $ObfuscatedToken.Replace("``'+'","'+'``")
        }
    }

    # Add the obfuscated token back to $ScriptString.
    # If string is preceded by a . or :: and followed by ( then it is a Member token encapsulated by quotes and now treated as a string.
    # We must add a .Invoke to the concatenated Member string to avoid syntax errors.
    If((($Token.Start -gt 0) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '.')) -OR (($Token.Start -gt 1) -AND ($ScriptString.SubString($Token.Start-2,2) -eq '::')) -AND ($ScriptString.SubString($Token.Start+$Token.Length,1) -eq '('))
    {
        $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + '.Invoke' + $ScriptString.SubString($Token.Start+$Token.Length)
    }
    Else
    {
        $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    }
    
    Return $ScriptString
}


Function Out-ObfuscatedCommandTokenLevel2
{
<#
.SYNOPSIS

Obfuscates command token by converting it to a concatenated string and using splatting to invoke the command.

Invoke-Obfuscation Function: Out-ObfuscatedCommandTokenLevel2
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-StringDelimitedAndConcatenated, Out-StringDelimitedConcatenatedAndReordered (both located in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedCommandTokenLevel2 obfuscates a given command token and places it back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Token

Specifies the token to obfuscate.

.PARAMETER ObfuscationLevel

Specifies whether to 1) Concatenate or 2) Reorder the splatted Command token value.

.EXAMPLE

C:\PS> $ScriptString = "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'Command'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedCommandTokenLevel2 $ScriptString $Token 1}
C:\PS> $ScriptString

&('Wr'+'itE-'+'HOSt') 'Hello World!' -ForegroundColor Green; .('WrITe-Ho'+'s'+'t') 'Obfuscation Rocks!' -ForegroundColor Green

C:\PS> $ScriptString = "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'Command'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedCommandTokenLevel2 $ScriptString $Token 1}
C:\PS> $ScriptString

&("{1}{0}{2}"-f'h','wRiTE-','ost') 'Hello World!' -ForegroundColor Green; .("{2}{1}{0}" -f'ost','-h','wrIte') 'Obfuscation Rocks!' -ForegroundColor Green

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 'Command' 2
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )

    # Set $Token.Content in a separate variable so it can be modified since Content is a ReadOnly property of $Token.
    $TokenContent = $Token.Content

    # If ticks are already present in current Token then remove so they will not interfere with string concatenation.
    If($TokenContent.Contains('`')) {$TokenContent = $TokenContent.Replace('`','')}

    # Convert $Token to character array for easier manipulation.
    $TokenArray = [Char[]]$TokenContent
    
    # Randomly upper- and lower-case characters in current token.
    $ObfuscatedToken = Out-RandomCase $TokenArray

    # User input $ObfuscationLevel (1-2) will choose between concatenating Command token value string (after trimming square brackets) or reordering it with the -F format operator.
    # I am leaving out Out-ObfuscatedStringCommand's option 3 since that may introduce a Type token unnecessarily ([Regex]).
    Switch($ObfuscationLevel)
    {
        1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
        2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
        default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for Command Token Obfuscation."; Exit}
    }
     
    # Evenly trim leading/trailing parentheses.
    While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
    {
        $ObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
    }

    # Encapsulate $ObfuscatedToken with parentheses.
    $ObfuscatedToken = '(' + $ObfuscatedToken + ')'
    
    # Check if the command is already prepended with an invocation operator. If it is then do not add an invocation operator.
    # E.g. & powershell -Sta -Command $cmd
    # E.g. https://github.com/adaptivethreat/Empire/blob/master/data/module_source/situational_awareness/host/Invoke-WinEnum.ps1#L139
    $SubStringLength = 15
    If($Token.Start -lt $SubStringLength)
    {
        $SubStringLength = $Token.Start
    }

    # Extract substring leading up to the current token.
    $SubString = $ScriptString.SubString($Token.Start-$SubStringLength,$SubStringLength).Trim()

    # Set $InvokeOperatorAlreadyPresent boolean variable to TRUE if the substring ends with invocation operators . or &
    $InvokeOperatorAlreadyPresent = $FALSE
    If($SubString.EndsWith('.') -OR $SubString.EndsWith('&'))
    {
        $InvokeOperatorAlreadyPresent = $TRUE
    }

    If(!$InvokeOperatorAlreadyPresent)
    {
        # Randomly choose between the & and . Invoke Operators.
        # In certain large scripts where more than one parameter are being passed into a custom function 
        # (like Add-SignedIntAsUnsigned in Invoke-Mimikatz.ps1) then using . will cause errors but & will not.
        # For now we will default to only & if $ScriptString.Length -gt 10000
        If($ScriptString.Length -gt 10000) {$RandomInvokeOperator = '&'}
        Else {$RandomInvokeOperator = Get-Random -InputObject @('&','.')}
    
        # Add invoke operator (and potentially whitespace) to complete splatting command.
        $ObfuscatedToken = $RandomInvokeOperator + $ObfuscatedToken
    }

    # Add the obfuscated token back to $ScriptString.
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    
    Return $ScriptString
}


Function Out-ObfuscatedWithTicks
{
<#
.SYNOPSIS

HELPER FUNCTION :: Obfuscates any token by randomizing its case and randomly adding ticks. It takes PowerShell special characters into account so you will get `N instead of `n, `T instead of `t, etc.

Invoke-Obfuscation Function: Out-ObfuscatedWithTicks
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedWithTicks obfuscates given input as a helper function to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Token

Specifies the token to obfuscate.

.EXAMPLE

C:\PS> $ScriptString = "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'Command'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedWithTicks $ScriptString $Token}
C:\PS> $ScriptString

WrI`Te-Ho`sT 'Hello World!' -ForegroundColor Green; WrIte-`hO`S`T 'Obfuscation Rocks!' -ForegroundColor Green

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 'Command' 2
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token
    )

    # If ticks are already present in current Token then Return $ScriptString as is.
    If($Token.Content.Contains('`'))
    {
        Return $ScriptString
    }
    
    # The Parameter Attributes in $MemberTokensToOnlyRandomCase (defined at beginning of script) cannot be obfuscated like other Member Tokens
    # For these tokens we will only randomize the case and then return as is.
    # Source: https://social.technet.microsoft.com/wiki/contents/articles/15994.powershell-advanced-function-parameter-attributes.aspx
    If($MemberTokensToOnlyRandomCase -Contains $Token.Content.ToLower())
    {
        $ObfuscatedToken = Out-RandomCase $Token.Content
        $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
        Return $ScriptString
    }

    # Set boolean variable to encapsulate member with double quotes if it is setting a value like below.
    # E.g. New-Object PSObject -Property @{ "P`AY`LOaDS" = $Payload }
    $EncapsulateWithDoubleQuotes = $FALSE
    If($ScriptString.SubString(0,$Token.Start).Contains('@{') -AND ($ScriptString.SubString($Token.Start+$Token.Length).Trim()[0] -eq '='))
    {
        $EncapsulateWithDoubleQuotes = $TRUE
    }
    
    # Convert $Token to character array for easier manipulation.
    $TokenArray = [Char[]]$Token.Content

    # Randomly upper- and lower-case characters in current token.
    $TokenArray = Out-RandomCase $TokenArray

    # Choose a random percentage of characters to obfuscate with ticks in current token.
    $ObfuscationPercent = Get-Random -Minimum 15 -Maximum 30
    
    # Convert $ObfuscationPercent to the exact number of characters to obfuscate in the current token.
    $NumberOfCharsToObfuscate = [int]($Token.Length*($ObfuscationPercent/100))

    # Guarantee that at least one character will be obfuscated.
    If($NumberOfCharsToObfuscate -eq 0) {$NumberOfCharsToObfuscate = 1}

    # Select random character indexes to obfuscate with ticks (excluding first and last character in current token).
    $CharIndexesToObfuscate = (Get-Random -InputObject (1..($TokenArray.Length-2)) -Count $NumberOfCharsToObfuscate)
    
    # Special characters in PowerShell must be upper-cased before adding a tick before the character.
    $SpecialCharacters = @('a','b','f','n','r','t','v')
 
    # Remove the possibility of a single tick being placed only before the token string.
    # This would leave the string value completely intact, thus defeating the purpose of the tick obfuscation.
    $ObfuscatedToken = '' #$NULL
    $ObfuscatedToken += $TokenArray[0]
    For($i=1; $i -le $TokenArray.Length-1; $i++)
    {
        $CurrentChar = $TokenArray[$i]
        If($CharIndexesToObfuscate -Contains $i)
        {
            # Set current character to upper case in case it is in $SpecialCharacters (i.e., `N instead of `n so it's not treated as a newline special character)
            If($SpecialCharacters -Contains $CurrentChar) {$CurrentChar = ([string]$CurrentChar).ToUpper()}
            
            # Skip adding a tick if character is a special character where case does not apply.
            If($CurrentChar -eq '0') {$ObfuscatedToken += $CurrentChar; Continue}
            
            # Add tick.
            $ObfuscatedToken += '`' + $CurrentChar
        }
        Else
        {
            $ObfuscatedToken += $CurrentChar
        }
    }

    # If $Token immediately follows a . or :: (and does not begin $ScriptString) then encapsulate with double quotes so ticks are valid.
    # E.g. both InvokeCommand and InvokeScript in $ExecutionContext.InvokeCommand.InvokeScript
    If((($Token.Start -gt 0) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '.')) -OR (($Token.Start -gt 1) -AND ($ScriptString.SubString($Token.Start-2,2) -eq '::')))
    {
        # Encapsulate the obfuscated token with double quotes since ticks were introduced.
        $ObfuscatedToken = '"' + $ObfuscatedToken + '"'
    }
    ElseIf($EncapsulateWithDoubleQuotes)
    {
        # Encapsulate the obfuscated token with double quotes since ticks were introduced.
        $ObfuscatedToken = '"' + $ObfuscatedToken + '"'
    }

    # Add the obfuscated token back to $ScriptString.
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    
    Return $ScriptString
}


Function Out-ObfuscatedMemberTokenLevel3
{
<#
.SYNOPSIS

Obfuscates member token by randomizing its case, randomly concatenating the member as a string and adding the .invoke operator. This enables us to treat a member token as a string to gain the obfuscation benefits of a string.

Invoke-Obfuscation Function: Out-ObfuscatedMemberTokenLevel3
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-StringDelimitedAndConcatenated, Out-StringDelimitedConcatenatedAndReordered (both located in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedMemberTokenLevel3 obfuscates a given token and places it back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Tokens

Specifies the token array containing the token we will obfuscate.

.PARAMETER Index

Specifies the index of the token to obfuscate.

.PARAMETER ObfuscationLevel

Specifies whether to 1) Concatenate or 2) Reorder the Member token value.

.EXAMPLE

C:\PS> $ScriptString = "[console]::WriteLine('Hello World!'); [console]::WriteLine('Obfuscation Rocks!')"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {If($Tokens[$i].Type -eq 'Member') {$ScriptString = Out-ObfuscatedMemberTokenLevel3 $ScriptString $Tokens $i 1}}
C:\PS> $ScriptString

[console]::('wR'+'It'+'eline').Invoke('Hello World!'); [console]::('wrItEL'+'IN'+'E').Invoke('Obfuscation Rocks!')

C:\PS> $ScriptString = "[console]::WriteLine('Hello World!'); [console]::WriteLine('Obfuscation Rocks!')"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {If($Tokens[$i].Type -eq 'Member') {$ScriptString = Out-ObfuscatedMemberTokenLevel3 $ScriptString $Tokens $i 2}}
C:\PS> $ScriptString

[console]::("{0}{2}{1}"-f 'W','ITEline','r').Invoke('Hello World!'); [console]::("{2}{1}{0}" -f 'liNE','RITE','W').Invoke('Obfuscation Rocks!')

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {[console]::WriteLine('Hello World!'); [console]::WriteLine('Obfuscation Rocks!')} 'Member' 3
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken[]]
        $Tokens,
        
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Index,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )

    $Token = $Tokens[$Index]
    
    # The Parameter Attributes in $MemberTokensToOnlyRandomCase (defined at beginning of script) cannot be obfuscated like other Member Tokens
    # For these tokens we will only randomize the case and then return as is.
    # Source: https://social.technet.microsoft.com/wiki/contents/articles/15994.powershell-advanced-function-parameter-attributes.aspx
    If($MemberTokensToOnlyRandomCase -Contains $Token.Content.ToLower())
    {
        $ObfuscatedToken = Out-RandomCase $Token.Content
        $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
        Return $ScriptString
    }
    
    # If $Token immediately follows a . or :: (and does not begin $ScriptString) of if followed by [] type cast within 
    #   parentheses then only allow Member token to be obfuscated with ticks and quotes.
    # The exception to this is when the $Token is immediately followed by an opening parenthese, like in .DownloadString(
    # E.g. both InvokeCommand and InvokeScript in $ExecutionContext.InvokeCommand.InvokeScript
    # E.g. If $Token is 'Invoke' then concatenating it and then adding .Invoke() would be redundant.
    $RemainingSubString = 50
    If($RemainingSubString -gt $ScriptString.SubString($Token.Start+$Token.Length).Length)
    {
        $RemainingSubString = $ScriptString.SubString($Token.Start+$Token.Length).Length
    }

    # Parse out $SubSubString to make next If block a little cleaner for handling fringe cases in which we will revert to ticks instead of concatenation or reordering of the Member token value.
    $SubSubString = $ScriptString.SubString($Token.Start+$Token.Length,$RemainingSubString)
    
    If(($Token.Content.ToLower() -eq 'invoke') `
    -OR (((($Token.Start -gt 0) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '.')) `
    -OR (($Token.Start -gt 1) -AND ($ScriptString.SubString($Token.Start-2,2) -eq '::'))) `
    -AND (($ScriptString.Length -ge $Token.Start+$Token.Length+1) -AND (($SubSubString.SubString(0,1) -ne '(') -OR (($SubSubString.Contains('[')) -AND !($SubSubString.SubString(0,$SubSubString.IndexOf('[')).Contains(')')))))))
    {
        # We will use the scriptString length prior to obfuscating 'invoke' to help extract the this token after obfuscation so we can add quotes before re-inserting it. 
        $PrevLength = $ScriptString.Length

        # Obfuscate 'invoke' token with ticks.
        $ScriptString = Out-ObfuscatedWithTicks $ScriptString $Token
        
        #$TokenLength = 'invoke'.Length + ($ScriptString.Length - $PrevLength)
        $TokenLength = $Token.Length + ($ScriptString.Length - $PrevLength)
        
        # Encapsulate obfuscated and extracted token with double quotes if it is not already.
        $ObfuscatedTokenExtracted =  $ScriptString.SubString($Token.Start,$TokenLength)
        If($ObfuscatedTokenExtracted.StartsWith('"') -AND $ObfuscatedTokenExtracted.EndsWith('"'))
        {
            $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedTokenExtracted + $ScriptString.SubString($Token.Start+$TokenLength)
        }
        Else
        {
            $ScriptString = $ScriptString.SubString(0,$Token.Start) + '"' + $ObfuscatedTokenExtracted + '"' + $ScriptString.SubString($Token.Start+$TokenLength)
        }

        Return $ScriptString
    }

    # Set $Token.Content in a separate variable so it can be modified since Content is a ReadOnly property of $Token.
    $TokenContent = $Token.Content
    
    # If ticks are already present in current Token then remove so they will not interfere with string concatenation.
    If($TokenContent.Contains('`')) {$TokenContent = $TokenContent.Replace('`','')}

    # Convert $Token to character array for easier manipulation.
    $TokenArray = [Char[]]$TokenContent

    # Randomly upper- and lower-case characters in current token.
    $TokenArray = Out-RandomCase $TokenArray
    
    # User input $ObfuscationLevel (1-2) will choose between concatenating Member token value string or reordering it with the -F format operator.
    # I am leaving out Out-ObfuscatedStringCommand's option 3 since that may introduce a Type token unnecessarily ([Regex]).
    Switch($ObfuscationLevel)
    {
        1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
        2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
        default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for Member Token Obfuscation."; Exit}
    }
    
    # Evenly trim leading/trailing parentheses -- .Trim does this unevenly.
    While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
    {
        $ObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
    }

    # Encapsulate $ObfuscatedToken with parentheses.
    $ObfuscatedToken = '(' + $ObfuscatedToken + ')'

    # Retain current token before re-tokenizing if 'invoke' member was introduced (see next For loop below)
    $InvokeToken = $Token
    # Retain how much the token has increased during obfuscation process so far.
    $TokenLengthIncrease = $ObfuscatedToken.Length - $Token.Content.Length

    # Add .Invoke if Member token was originally immediately followed by '('
    If(($Index -lt $Tokens.Count) -AND ($Tokens[$Index+1].Content -eq '(') -AND ($Tokens[$Index+1].Type -eq 'GroupStart')) 
    {
        $ObfuscatedToken = $ObfuscatedToken + '.Invoke'
    }
    
    # Add the obfuscated token back to $ScriptString.
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)  

    Return $ScriptString
}


Function Out-ObfuscatedCommandArgumentTokenLevel3
{
<#
.SYNOPSIS

Obfuscates command argument token by randomly concatenating the command argument as a string and encapsulating it with parentheses.

Invoke-Obfuscation Function: Out-ObfuscatedCommandArgumentTokenLevel3
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-StringDelimitedAndConcatenated, Out-StringDelimitedConcatenatedAndReordered (both located in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedCommandArgumentTokenLevel3 obfuscates a given token and places it back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Token

Specifies the token to obfuscate.

.PARAMETER ObfuscationLevel

Specifies whether to 1) Concatenate or 2) Reorder the Argument token value.

.EXAMPLE

C:\PS> $ScriptString = "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'CommandArgument'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedCommandArgumentTokenLevel3 $ScriptString $Token 1}
C:\PS> $ScriptString

Write-Host 'Hello World!' -ForegroundColor ('Gr'+'een'); Write-Host 'Obfuscation Rocks!' -ForegroundColor ("Gree"+"n")

C:\PS> $ScriptString = "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'CommandArgument'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedCommandArgumentTokenLevel3 $ScriptString $Token 2}
C:\PS> $ScriptString

Write-Host 'Hello World!' -ForegroundColor ("{1}{0}"-f 'een','Gr'); Write-Host 'Obfuscation Rocks!' -ForegroundColor ("{0}{1}" -f 'Gre','en')

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 'CommandArgument' 3
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )

    # Function name declarations are CommandArgument tokens that cannot be obfuscated with concatenations.
    # For these we will obfuscated them with ticks because this changes the string from AMSI's perspective but not the final functionality.
    If($ScriptString.SubString(0,$Token.Start-1).Trim().ToLower().EndsWith('function'))
    #If($ScriptString.SubString(0,$Token.Start-1).Trim().ToLower().EndsWith('function') -or $ScriptString.SubString(0,$Token.Start-1).Trim().ToLower().EndsWith('filter'))
    {
        $ScriptString = Out-ObfuscatedWithTicks $ScriptString $Token
        Return $ScriptString
    }

    # Set $Token.Content in a separate variable so it can be modified since Content is a ReadOnly property of $Token.
    $TokenContent = $Token.Content
    
    # If ticks are already present in current Token then remove so they will not interfere with string concatenation.
    If($TokenContent.Contains('`')) {$TokenContent = $TokenContent.Replace('`','')}

    # User input $ObfuscationLevel (1-2) will choose between concatenating CommandArgument token value string or reordering it with the -F format operator.
    # I am leaving out Out-ObfuscatedStringCommand's option 3 since that may introduce a Type token unnecessarily ([Regex]).
    Switch($ObfuscationLevel)
    {
        1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
        2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
        default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for Argument Token Obfuscation."; Exit}
    }
    
    # Evenly trim leading/trailing parentheses -- .Trim does this unevenly.
    While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
    {
        $ObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
    }

    # Encapsulate $ObfuscatedToken with parentheses.
    $ObfuscatedToken = '(' + $ObfuscatedToken + ')'
    
    # Add the obfuscated token back to $ScriptString.
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    
    Return $ScriptString
}


Function Out-ObfuscatedTypeToken
{
<#
.SYNOPSIS

Obfuscates type token by using direct type cast syntax and concatenating or reordering the Type token value.
This function only applies to Type tokens immediately followed by . or :: operators and then a Member token.
E.g. [Char][Int]'123' will not be obfuscated by this function, but [Console]::WriteLine will be obfuscated.

Invoke-Obfuscation Function: Out-ObfuscatedTypeToken
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: Out-StringDelimitedAndConcatenated, Out-StringDelimitedConcatenatedAndReordered (both located in Out-ObfuscatedStringCommand.ps1)
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedTypeToken obfuscates a given token and places it back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Token

Specifies the token to obfuscate.

.PARAMETER ObfuscationLevel

Specifies whether to 1) Concatenate or 2) Reorder the Type token value.

.EXAMPLE

C:\PS> $ScriptString = "[console]::WriteLine('Hello World!'); [console]::WriteLine('Obfuscation Rocks!')"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'Type'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedTypeToken $ScriptString $Token 1}
C:\PS> $ScriptString

sET  EOU ( [TYPe]('CO'+'NS'+'oLe')) ;    (  CHILdiTEM  VariablE:EOU ).VALUE::WriteLine('Hello World!');   $eoU::WriteLine('Obfuscation Rocks!')

C:\PS> $ScriptString = "[console]::WriteLine('Hello World!'); [console]::WriteLine('Obfuscation Rocks!')"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'Type'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedTypeToken $ScriptString $Token 2}
C:\PS> $ScriptString

SET-vAriablE  BVgz6n ([tYpe]("{2}{1}{0}" -f'sOle','On','C')  )  ;    $BVGz6N::WriteLine('Hello World!');  ( cHilDItem  vAriAbLE:bVGZ6n ).VAlue::WriteLine('Obfuscation Rocks!')

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {[console]::WriteLine('Hello World!'); [console]::WriteLine('Obfuscation Rocks!')} 'Type' 1
C:\PS> Out-ObfuscatedTokenCommand {[console]::WriteLine('Hello World!'); [console]::WriteLine('Obfuscation Rocks!')} 'Type' 2
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )

    # If we are dealing with a Type that is found in $TypesThatCannotByDirectTypeCasted then return as is since it will error if we try to direct Type cast.
    ForEach($Type in $TypesThatCannotByDirectTypeCasted)
    {
        If($Token.Content.ToLower().Contains($Type))
        {
            Return $ScriptString
        }
    }

    # If we are dealing with a Type that is NOT immediately followed by a Member token (denoted by . or :: operators) then we won't obfuscated.
    # This is for Type tokens like: [Char][Int]'123' etc.
    If(($ScriptString.SubString($Token.Start+$Script:TypeTokenScriptStringGrowth+$Token.Length,1) -ne '.') -AND ($ScriptString.SubString($Token.Start+$Script:TypeTokenScriptStringGrowth+$Token.Length,2) -ne '::'))
    {
        Return $ScriptString
    }

    # This variable will be used to track the growth in length of $ScriptString since we'll be appending variable creation at the beginning of $ScriptString.
    # This will allow us to avoid tokenizing $ScriptString for every single Type token that is present.
    $PrevLength = $ScriptString.Length

    # See if we've already set another instance of this same Type token previously in this obfsucation iteration.
    $RandomVarName = $NULL
    $UsingPreviouslyDefinedVarName = $FALSE
    ForEach($DefinedTokenVariable in $Script:TypeTokenVariableArray)
    {
        If($Token.Content.ToLower() -eq $DefinedTokenVariable[0])
        {
            $RandomVarName = $DefinedTokenVariable[1]
            $UsingPreviouslyDefinedVarName = $TRUE
        }
    }

    # If we haven't already defined a random variable for this Token type then we will do that. Otherwise we will use the previously-defined variable.
    If(!($UsingPreviouslyDefinedVarName))
    {
        # User input $ObfuscationLevel (1-2) will choose between concatenating Type token value string (after trimming square brackets) or reordering it with the -F format operator.
        # I am leaving out Out-ObfuscatedStringCommand's option 3 since that may introduce another Type token unnecessarily ([Regex]).

        # Trim of encapsulating square brackets before obfuscating the string value of the Type token.
        $TokenContent = $Token.Content.Trim('[]')

        Switch($ObfuscationLevel)
        {
            1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
            2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
            default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for Type Token Obfuscation."; Exit}
        }
        
        # Evenly trim leading/trailing parentheses.
        While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
        {
            $ObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
        }

        # Add syntax for direct type casting.
        $ObfuscatedTokenTypeCast = '[type]' + '(' + $ObfuscatedToken + ')'

        # Characters we will use to generate random variable names.
        # For simplicity do NOT include single- or double-quotes in this array.
        $CharsToRandomVarName  = @(0..9)
        $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')

        # Randomly choose variable name starting length.
        $RandomVarLength = (Get-Random -Input @(3..6))
   
        # Create random variable with characters from $CharsToRandomVarName.
        If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
        $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')

        # Keep generating random variables until we find one that is not a substring of $ScriptString.
        While($ScriptString.ToLower().Contains($RandomVarName.ToLower()))
        {
            $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
            $RandomVarLength++
        }

        # Track this variable name and Type token so we can reuse this variable name for future uses of this same Type token in this obfuscation iteration.
        $Script:TypeTokenVariableArray += , @($Token.Content,$RandomVarName)
    }

    # Randomly decide if the variable name will be concatenated inline or not.
    # Handle both <varname> and <variable:varname> syntaxes depending on which option is chosen concerning GET variable syntax.
    $RandomVarNameMaybeConcatenated = $RandomVarName
    $RandomVarNameMaybeConcatenatedWithVariablePrepended = 'variable:' + $RandomVarName
    If((Get-Random -Input @(0..1)) -eq 0)
    {
        $RandomVarNameMaybeConcatenated = '(' + (Out-ConcatenatedString $RandomVarName (Get-Random -Input @('"',"'"))) + ')'
        $RandomVarNameMaybeConcatenatedWithVariablePrepended = '(' + (Out-ConcatenatedString "variable:$RandomVarName" (Get-Random -Input @('"',"'"))) + ')'
    }
    
    # Generate random variable SET syntax.
    $RandomVarSetSyntax  = @()
    $RandomVarSetSyntax += '$' + $RandomVarName + ' '*(Get-Random @(0..2)) + '=' + ' '*(Get-Random @(0..2)) + $ObfuscatedTokenTypeCast
    $RandomVarSetSyntax += (Get-Random -Input @('Set-Variable','SV','Set')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $ObfuscatedTokenTypeCast + ' '*(Get-Random @(0..2)) + ')'
    $RandomVarSetSyntax += 'Set-Item' + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenatedWithVariablePrepended + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $ObfuscatedTokenTypeCast + ' '*(Get-Random @(0..2)) + ')'

    # Randomly choose from above variable syntaxes.
    $RandomVarSet = (Get-Random -Input $RandomVarSetSyntax)

    # Randomize the case of selected variable syntaxes.
    $RandomVarSet = Out-RandomCase $RandomVarSet
  
    # Generate random variable GET syntax.
    $RandomVarGetSyntax  = @()
    $RandomVarGetSyntax += '$' + $RandomVarName
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('Get-Variable','Variable')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + (Get-Random -Input ((' '*(Get-Random @(0..2)) + ').Value'),(' '*(Get-Random @(1..2)) + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ' '*(Get-Random @(0..2)) + ')')))
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenatedWithVariablePrepended + ' '*(Get-Random @(0..2)) + ').Value'
    
    # Randomly choose from above variable syntaxes.
    $RandomVarGet = (Get-Random -Input $RandomVarGetSyntax)

    # Randomize the case of selected variable syntaxes.
    $RandomVarGet = Out-RandomCase $RandomVarGet

    # If we're using an existing variable already set in ScriptString for the current Type token then we don't need to prepend an additional SET variable syntax.
    $PortionToPrependToScriptString = ''
    If(!($UsingPreviouslyDefinedVarName))
    {
        $PortionToPrependToScriptString = ' '*(Get-Random @(0..2)) + $RandomVarSet  + ' '*(Get-Random @(0..2)) + ';' + ' '*(Get-Random @(0..2))
    }

    # Add the obfuscated token back to $ScriptString.
    $ScriptString = $PortionToPrependToScriptString + $ScriptString.SubString(0,$Token.Start+$Script:TypeTokenScriptStringGrowth) + ' '*(Get-Random @(1..2)) + $RandomVarGet + $ScriptString.SubString($Token.Start+$Token.Length+$Script:TypeTokenScriptStringGrowth)

    # Keep track how much $ScriptString grows for each Type token obfuscation iteration.
    $Script:TypeTokenScriptStringGrowth = $Script:TypeTokenScriptStringGrowth + $PortionToPrependToScriptString.Length

    Return $ScriptString
}


Function Out-ObfuscatedVariableTokenLevel1
{
<#
.SYNOPSIS

Obfuscates variable token by randomizing its case, randomly adding ticks and wrapping it in curly braces.

Invoke-Obfuscation Function: Out-ObfuscatedVariableTokenLevel1
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-ObfuscatedVariableTokenLevel1 obfuscates a given token and places it back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Token

Specifies the token to obfuscate.

.EXAMPLE

C:\PS> $ScriptString = "`$Message1 = 'Hello World!'; Write-Host `$Message1 -ForegroundColor Green; `$Message2 = 'Obfuscation Rocks!'; Write-Host `$Message2 -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'Variable'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-ObfuscatedVariableTokenLevel1 $ScriptString $Token}
C:\PS> $ScriptString

${m`e`ssAge1} = 'Hello World!'; Write-Host ${MEss`Ag`e1} -ForegroundColor Green; ${meSsAg`e`2} = 'Obfuscation Rocks!'; Write-Host ${M`es`SagE2} -ForegroundColor Green

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {$Message1 = 'Hello World!'; Write-Host $Message1 -ForegroundColor Green; $Message2 = 'Obfuscation Rocks!'; Write-Host $Message2 -ForegroundColor Green} 'Variable' 1
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token
    )

    # Return as-is if the variable is already encapsulated with ${}. Otherwise you will get errors if you have something like ${var} turned into ${${var}}
    If($ScriptString.SubString($Token.Start,2) -eq '${')
    {
        Return $ScriptString
    }

    # Length of pre-obfuscated ScriptString will be important in extracting out the obfuscated token before we add curly braces.
    $PrevLength = $ScriptString.Length

    $ScriptString = Out-ObfuscatedWithTicks $ScriptString $Token   

    # Pull out ObfuscatedToken from ScriptString and add curly braces around obfuscated variable token.
    $ObfuscatedToken = $ScriptString.SubString($Token.Start,$Token.Length+($ScriptString.Length-$PrevLength))
    $ObfuscatedToken = '${' + $ObfuscatedToken.Trim('"') + '}'

    # Add the obfuscated token back to $ScriptString.
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length+($ScriptString.Length-$PrevLength))

    Return $ScriptString
}


Function Out-RandomCaseToken
{
<#
.SYNOPSIS

HELPER FUNCTION :: Obfuscates any token by randomizing its case and reinserting it into the ScriptString input variable.

Invoke-Obfuscation Function: Out-RandomCaseToken
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-RandomCaseToken obfuscates given input as a helper function to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Token

Specifies the token to obfuscate.

.EXAMPLE

C:\PS> $ScriptString = "Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'CommandArgument'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-RandomCaseToken $ScriptString $Token}
C:\PS> $ScriptString

Write-Host 'Hello World!' -ForegroundColor GREeN; Write-Host 'Obfuscation Rocks!' -ForegroundColor gReeN

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 'CommandArgument' 1
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token
    )
                
    # Convert $Token to character array for easier manipulation.
    $TokenArray = [Char[]]$Token.Content
    
    # Randomly upper- and lower-case characters in current token.
    $TokenArray = Out-RandomCase $TokenArray
    
    # Convert character array back to string.
    $ObfuscatedToken = $TokenArray -Join ''
    
    # Add the obfuscated token back to $ScriptString.
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    
    Return $ScriptString
}


Function Out-ConcatenatedString
{
<#
.SYNOPSIS

HELPER FUNCTION :: Obfuscates any string by randomly concatenating it and encapsulating the result with input single- or double-quotes.

Invoke-Obfuscation Function: Out-ConcatenatedString
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-ConcatenatedString obfuscates given input as a helper function to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER InputVal

Specifies the string to obfuscate.

.PARAMETER Quote

Specifies the single- or double-quote used to encapsulate the concatenated string.

.EXAMPLE

C:\PS> Out-ConcatenatedString "String to be concatenated" '"'

"String "+"to be "+"co"+"n"+"c"+"aten"+"at"+"ed

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 'CommandArgument' 3
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $InputVal,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $Quote
    )

    # Strip leading and trailing single- or double-quotes if there are no more quotes of the same kind in $InputVal.
    # E.g. 'stringtoconcat' will have the leading and trailing quotes removed and will use $Quote.
    # But a string "'G'+'" passed to this function as 'G'+' will have all quotes remain as part of the $InputVal string.
    If($InputVal.Contains("'")) {$InputVal = $InputVal.Replace("'","`'")}
    If($InputVal.Contains('"')) {$InputVal = $InputVal.Replace('"','`"')}
    
    # Do nothing if string is of length 2 or less
    $ObfuscatedToken = ''
    If($InputVal.Length -le 2)
    {
        $ObfuscatedToken = $Quote + $InputVal + $Quote
        Return $ObfuscatedToken
    }

    # Choose a random percentage of characters to have concatenated in current token.
    # If the current token is greater than 1000 characters (as in SecureString or Base64 strings) then set $ConcatPercent much lower
    If($InputVal.Length -gt 25000)
    {
        $ConcatPercent = Get-Random -Minimum 0.05 -Maximum 0.10
    }
    ElseIf($InputVal.Length -gt 1000)
    {
        $ConcatPercent = Get-Random -Minimum 2 -Maximum 4
    }
    Else
    {
        $ConcatPercent = Get-Random -Minimum 15 -Maximum 30
    }
    
    # Convert $ConcatPercent to the exact number of characters to concatenate in the current token.
    $ConcatCount =  [Int]($InputVal.Length*($ConcatPercent/100))

    # Guarantee that at least one concatenation will occur.
    If($ConcatCount -eq 0) 
    {
        $ConcatCount = 1
    }

    # Select random indexes on which to concatenate.
    $CharIndexesToConcat = (Get-Random -InputObject (1..($InputVal.Length-1)) -Count $ConcatCount) | Sort-Object
  
    # Perform inline concatenation.
    $LastIndex = 0

    ForEach($IndexToObfuscate in $CharIndexesToConcat)
    {
        # Extract substring to concatenate with $ObfuscatedToken.
        $SubString = $InputVal.SubString($LastIndex,$IndexToObfuscate-$LastIndex)
       
        # Concatenate with quotes and addition operator.
        $ObfuscatedToken += $SubString + $Quote + "+" + $Quote

        $LastIndex = $IndexToObfuscate
    }

    # Add final substring.
    $ObfuscatedToken += $InputVal.SubString($LastIndex)
    $ObfuscatedToken += $FinalSubString

    # Add final quotes if necessary.
    If(!($ObfuscatedToken.StartsWith($Quote) -AND $ObfuscatedToken.EndsWith($Quote)))
    {
        $ObfuscatedToken = $Quote + $ObfuscatedToken + $Quote
    }
   
    # Remove any existing leading or trailing empty string concatenation.
    If($ObfuscatedToken.StartsWith("''+"))
    {
        $ObfuscatedToken = $ObfuscatedToken.SubString(3)
    }
    If($ObfuscatedToken.EndsWith("+''"))
    {
        $ObfuscatedToken = $ObfuscatedToken.SubString(0,$ObfuscatedToken.Length-3)
    }
    
    Return $ObfuscatedToken
}


Function Out-RandomCase
{
<#
.SYNOPSIS

HELPER FUNCTION :: Obfuscates any string or char[] by randomizing its case.

Invoke-Obfuscation Function: Out-RandomCase
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-RandomCase obfuscates given input as a helper function to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER InputValStr

Specifies the string to obfuscate.

.PARAMETER InputVal

Specifies the char[] to obfuscate.

.EXAMPLE

C:\PS> Out-RandomCase "String to have case randomized"

STrINg to haVe caSe RAnDoMIzeD

C:\PS> Out-RandomCase ([char[]]"String to have case randomized")

StrING TO HavE CASE randOmIzeD

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {Write-Host 'Hello World!' -ForegroundColor Green; Write-Host 'Obfuscation Rocks!' -ForegroundColor Green} 'Command' 3
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding( DefaultParameterSetName = 'InputVal')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'InputValStr')]
        [ValidateNotNullOrEmpty()]
        [String]
        $InputValStr,

        [Parameter(Position = 0, ParameterSetName = 'InputVal')]
        [ValidateNotNullOrEmpty()]
        [Char[]]
        $InputVal
    )
    
    If($PSBoundParameters['InputValStr'])
    {
        # Convert string to char array for easier manipulation.
        $InputVal = [Char[]]$InputValStr
    }

    # Randomly convert each character to upper- or lower-case.
    $OutputVal = ($InputVal | ForEach-Object {If((Get-Random -Minimum 0 -Maximum 2) -eq 0) {([String]$_).ToUpper()} Else {([String]$_).ToLower()}}) -Join ''

    Return $OutputVal
}


Function Out-RandomWhitespace
{
<#
.SYNOPSIS

Obfuscates operator/groupstart/groupend/statementseparator token by adding random amounts of whitespace before/after the token depending on the token value and its immediate surroundings in the input script.

Invoke-Obfuscation Function: Out-RandomWhitespace
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-RandomWhitespace adds random whitespace before/after a given token and places it back into the provided PowerShell script to evade detection by simple IOCs and process execution monitoring relying solely on command-line arguments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Tokens

Specifies the token array containing the token we will obfuscate.

.PARAMETER Index

Specifies the index of the token to obfuscate.

.EXAMPLE

C:\PS> $ScriptString = "Write-Host ('Hel'+'lo Wo'+'rld!') -ForegroundColor Green; Write-Host ('Obfu'+'scation Ro'+'cks!') -ForegroundColor Green"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {If(($Tokens[$i].Type -eq 'Operator') -OR ($Tokens[$i].Type -eq 'GroupStart') -OR ($Tokens[$i].Type -eq 'GroupEnd')) {$ScriptString = Out-RandomWhitespace $ScriptString $Tokens $i}}
C:\PS> $ScriptString

Write-Host ('Hel'+  'lo Wo'  + 'rld!') -ForegroundColor Green; Write-Host ( 'Obfu'  +'scation Ro' +  'cks!') -ForegroundColor Green

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {Write-Host ('Hel'+'lo Wo'+'rld!') -ForegroundColor Green; Write-Host ('Obfu'+'scation Ro'+'cks!') -ForegroundColor Green} 'RandomWhitespace' 1
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken[]]
        $Tokens,
        
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Index
    )
        
    $Token = $Tokens[$Index]

    $ObfuscatedToken = $Token.Content
    
    # Do not add DEFAULT setting in below Switch block.
    Switch($Token.Content) {
        '(' {$ObfuscatedToken = $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        ')' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken}
        ';' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '|' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '+' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '=' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '&' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '.' {
            # Retrieve character in script immediately preceding the current token
            If($Index -eq 0) {$PrevChar = ' '}
            Else {$PrevChar = $ScriptString.SubString($Token.Start-1,1)}
            
            # Only add randomized whitespace to . if it is acting as a standalone invoke operator (either at the beginning of the script or immediately preceded by ; or whitespace)
            If(($PrevChar -eq ' ') -OR ($PrevChar -eq ';')) {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        }
    }
    
    # Add the obfuscated token back to $ScriptString.
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    
    Return $ScriptString
}


Function Out-RemoveComments
{
<#
.SYNOPSIS

Obfuscates variable token by removing all comment tokens. This is primarily since A/V uses strings in comments as part of many of their signatures for well known PowerShell scripts like Invoke-Mimikatz.

Invoke-Obfuscation Function: Out-RemoveComments
Author: Daniel Bohannon (@danielhbohannon)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-RemoveComments obfuscates a given token by removing all comment tokens from the provided PowerShell script to evade detection by simple IOCs or A/V signatures based on strings in PowerShell script comments. For the most complete obfuscation all tokens in a given PowerShell script or script block (cast as a string object) should be obfuscated via the corresponding obfuscation functions and desired obfuscation levels in Out-ObfuscatedTokenCommand.ps1.

.PARAMETER ScriptString

Specifies the string containing your payload.

.PARAMETER Token

Specifies the token to obfuscate.

.EXAMPLE

C:\PS> $ScriptString = "`$Message1 = 'Hello World!'; Write-Host `$Message1 -ForegroundColor Green; `$Message2 = 'Obfuscation Rocks!'; Write-Host `$Message2 -ForegroundColor Green #COMMENT"
C:\PS> $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq 'Comment'}
C:\PS> For($i=$Tokens.Count-1; $i -ge 0; $i--) {$Token = $Tokens[$i]; $ScriptString = Out-RemoveComments $ScriptString $Token}
C:\PS> $ScriptString

$Message1 = 'Hello World!'; Write-Host $Message1 -ForegroundColor Green; $Message2 = 'Obfuscation Rocks!'; Write-Host $Message2 -ForegroundColor Green

.NOTES

This cmdlet is most easily used by passing a script block or file path to a PowerShell script into the Out-ObfuscatedTokenCommand function with the corresponding token type and obfuscation level since Out-ObfuscatedTokenCommand will handle token parsing, reverse iterating and passing tokens into this current function.
C:\PS> Out-ObfuscatedTokenCommand {$Message1 = 'Hello World!'; Write-Host $Message1 -ForegroundColor Green; $Message2 = 'Obfuscation Rocks!'; Write-Host $Message2 -ForegroundColor Green #COMMENT} 'Comment' 1
This is a personal project developed by Daniel Bohannon while an employee at MANDIANT, A FireEye Company.

.LINK

http://www.danielbohannon.com
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
    
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token
    )
    
    # Remove current Comment token.
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ScriptString.SubString($Token.Start+$Token.Length)
    
    Return $ScriptString
}