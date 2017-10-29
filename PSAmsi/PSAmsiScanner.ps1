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

    [Bool] TestEicarDetection() {
        $Test = ("Y6P`"Q&ABQ\5]Q[Y65)Q_*8DD*8~%FJDBS.TUBOEBSE.BOUJWJSVT.UFTU.GJMF`"%I,I+".ToCharArray() | % { (($_ -as [Int]) - 1) -as [Char]}) -join ""
        return $this.GetPSAmsiScanResult($Test)
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

function Test-EicarDetection {
<#
    .SYNOPSIS

    Tests if the current AMSI AntiMalware Provider detects a standard test EICAR payload.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: PSAmsiScanner
    Optional Dependencies: none

    .DESCRIPTION

    Test-EicarDetection tests if the current AMSI AntiMalware Provider detects a standard test EICAR payload. If your AMSI AntiMalware
    Provider does not detect an EICAR payload it is likely that your AMSI AntiMalware Provider is being somewhat deceptive when they say
    they have implemented AMSI support.
    
    .EXAMPLE

    Test-EicarDetection

    .EXAMPLE

    Test-EicarDetection -PSAmsiScanner $Scanner

    .NOTES

    Test-EicarDetection is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.
    
    #>

    Param (
        [Parameter(Position = 0)] [ValidateNotNull()]
        [ValidateScript({$_.GetType().Name -eq 'PSAmsiScanner'})]
        [System.Object] $PSAmsiScanner
    )
    $CreatedPSAmsiScanner = $False
    If (-not $PSAmsiScanner) {
        $PSAmsiScanner = New-PSAmsiScanner
        $CreatedPSAmsiScanner = $True
    }

    $PSAmsiScanner.TestEicarDetection()

    If ($CreatedPSAmsiScanner) {
        $PSAmsiScanner.Dispose()
    }
}