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
        [System.Object] $PSAmsiScanner,

        [Switch] $Unique
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
            $AmsiAstSignatures = Find-AmsiAstSignatures -ScriptString $ScriptString -PSAmsiScanner $PSAmsiScanner
            $AmsiPSTokenSignatures = Find-AmsiPSTokenSignatures -ScriptString $ScriptString -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        } ElseIf ($ScriptBlock) {
            $AmsiAstSignatures = Find-AmsiAstSignatures -ScriptBlock $ScriptBlock -PSAmsiScanner $PSAmsiScanner
            $AmsiPSTokenSignatures = Find-AmsiPSTokenSignatures -ScriptBlock $ScriptBlock -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        } ElseIf ($ScriptPath) {
            $AmsiAstSignatures = Find-AmsiAstSignatures -ScriptPath $ScriptPath -PSAmsiScanner $PSAmsiScanner
            $AmsiPSTokenSignatures = Find-AmsiPSTokenSignatures -ScriptPath $ScriptPath -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        } ElseIf ($ScriptUri) {
            $AmsiAstSignatures = Find-AmsiAstSignatures -ScriptUri $ScriptUri -PSAmsiScanner $PSAmsiScanner
            $AmsiPSTokenSignatures = Find-AmsiPSTokenSignatures -ScriptUri $ScriptUri -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        } ElseIf ($AbstractSyntaxTree -and $PSTokens) {
            $AmsiAstSignatures = Find-AmsiAstSignatures -AbstractSyntaxTree $AbstractSyntaxTree -PSAmsiScanner $PSAmsiScanner
            $AmsiPSTokenSignatures = Find-AmsiPSTokenSignatures -PSTokens $PSTokens -PSAmsiScanner $PSAmsiScanner -FilterPSTokenTypes 'Comment'
        }
        # Create AmsiSignature objects
        $AmsiAstSignatures = ($AmsiAstSignatures | % { [PSCustomObject] @{ SignatureType = $_.GetType().Name; SignatureContent = $_.Extent.Text; Position = $_.Extent.StartOffset } }) -as [array] 
        $AmsiPSTokenSignatures = ($AmsiPSTokenSignatures | % { [PSCustomObject] @{ SignatureType = $_.GetType().Name; SignatureContent = $_.Content; Position = $_.Start; } }) -as [array]
        $AmsiSignatures = $AmsiAstSignatures + $AmsiPSTokenSignatures
        
        If ($Unique) { $AmsiSignatures | Sort-Object -Unique { $_.SignatureContent } }
        Else { $AmsiSignatures }
    }
    End {
        If ($CreatedPSAmsiScanner) { $PSAmsiScanner.Dispose() }
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

        [Parameter(Position = 1)]
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
        
        $AmsiAstSignatures = $AbstractSyntaxTree.FindAll(
        {
            param($ast) (
                # This Ast has text
                ($ast.Extent.Text) -and
                # And it is flagged by AMSI
                ($PSAmsiScanner.GetPSAmsiScanResult($ast.Extent.Text))
            )
        }, $True) | Sort-Object { $_.Extent.Text.Length }

        # Need to find 'leaves' of detected tree to get the real signatures
        $NonDuplicates = @()
        ForEach ($AmsiAstSignature in $AmsiAstSignatures) {
            $Duplicate = $False
            ForEach ($NonDuplicate in $NonDuplicates) {
                If ($AmsiAstSignature.Extent.Text.Contains($NonDuplicate.Extent.Text) -AND
                   ($AmsiAstSignatures.Extent.Text.Length -ne $NonDuplicate.Extent.Text.Length)) {
                    $Duplicate = $True
                    break
                }
            }
            If (-not $Duplicate) {
                $NonDuplicates += $AmsiAstSignature
            }
        }
        $NonDuplicates -as [array]
    }
    End {
        If ($CreatedPSAmsiScanner) { $PSAmsiScanner.Dispose() }
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
        If ($CreatedPSAmsiScanner) { $PSAmsiScanner.Dispose() }
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
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            $PSAmsiScanner = New-PSAmsiScanner
            $CreatedPSAmsiScanner = $True
        }
    }
    Process {
        # Get the PSTokens that represent the script, if not provided
        If ($ScriptString) { $PSTokens = Get-PSTokens -ScriptString $ScriptString }
        ElseIf ($ScriptBlock) { $PSTokens = Get-PSTokens -ScriptBlock $ScriptBlock }
        ElseIf ($ScriptPath) { $PSTokens = Get-PSTokens -ScriptPath $ScriptPath }
        ElseIf ($ScriptUri) { $PSTokens = Get-PSTokens -ScriptUri $ScriptUri }

        # Filter given tokens by type, and check if PSToken content is flagged by AMSI
        $AmsiPSTokenSignatures = $PSTokens | ? { $_.Type -in $FilterPSTokenTypes } | ? { $PSAmsiScanner.GetPSAmsiScanResult($_.Content) }
        $AmsiPSTokenSignatures -as [array]
    }
    End {
        If ($CreatedPSAmsiScanner) { $PSAmsiScanner.Dispose() }
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
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            $PSAmsiScanner = New-PSAmsiScanner
            $CreatedPSAmsiScanner = $True
        }
    }
    Process {
        # Get the PSTokens that represent the script, if not provided
        If ($ScriptString) { $PSTokens = Get-PSTokens -ScriptString $ScriptString }
        ElseIf ($ScriptBlock) { $PSTokens = Get-PSTokens -ScriptBlock $ScriptBlock }
        ElseIf ($ScriptPath) { $PSTokens = Get-PSTokens -ScriptPath $ScriptPath }
        ElseIf ($ScriptUri) { $PSTokens = Get-PSTokens -ScriptUri $ScriptUri }

        # Filter given tokens by type, and check if Token content is flagged by AMSI
        $PSTokens | ? { $_.Type -in $FilterPSTokenTypes } | % { 
            $Result = $PSAmsiScanner.GetPSAmsiScanResult($_.Content)
            If ($Result) { $True; break }
        }
    }
    End {
        If ($CreatedPSAmsiScanner) { $PSAmsiScanner.Dispose() }
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