function Start-PSAmsiServer {
    <#

    .SYNOPSIS

    Starts a PSAmsiServer that sends PSAmsiScanRequests to connecting PSAmsiClients.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: none

    .DESCRIPTION

    Start-PSAmsiServer starts a PSAmsiServer HTTP Listener and sends PSAmsiScanRequests
    to connecting PSAmsiClients and receives the results of the scans.

    .PARAMETER Port

    Specifies the port to start the PSAmsiServer HTTP Listener on.

    .PARAMETER ScriptString

    Specifies the string containing the script to be sent as PSAmsiScanRequests
    to PSAmsiClients.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing the script to be sent as PSAmsiScanRequests
    to PSAmsiClients.

    .PARAMETER ScriptPath

    Specifies the Path to the script to be sent as PSAmsiScanRequests to PSAMsiClients.

    .PARAMETER ScriptUri

    Specifies the URI of the script to be sent as PSAmsiScanRequests to PSAMsiClients.

    .OUTPUTS

    PSCustomObject
    
    .EXAMPLE

    Start-PSAmsiServer -Port 443 -ScriptPath Invoke-Example.ps1

    .EXAMPLE

    Get-ChildItem /path/to/scripts -Recurse -Include *.ps1 | Start-PSAmsiServer -Port 80

    .NOTES

    Start-PSAmsiServer is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
   [CmdletBinding(DefaultParameterSetName = "ByPath")] Param(
        [Parameter(Position = 0, Mandatory)]
        [ValidateRange(1, 65535)]
        [Int] $Port,

        [Parameter(ParameterSetName = "ByString", Position = 1, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNull()]
        [String] $ScriptString,

        [Parameter(ParameterSetName = "ByScriptBlock", Position = 1, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,

        [Parameter(ParameterSetName = "ByPath", Position = 1, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,

        [Parameter(ParameterSetName = "ByUri", Position = 1, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri
    )
    Begin{
        $ErrorActionPreference = "Stop"
        $HTTPServer = New-Object System.Net.HTTPListener
        Write-Verbose "[Start-PSAmsiServer] HTTP Listener starting on port $($Port)"
        $HTTPServer.Prefixes.Add("http://+:" + $Port + "/")
        $HTTPServer.Start()

        $PSAmsiScanRequests = @()
        $ScriptForName = @{}
    }

    Process{
        If ($ScriptBlock) {
            $ScriptString = $ScriptBlock -as [String]
            $ScriptName = $ScriptBlock.Id
        }
        ElseIf ($ScriptPath) {
            $ScriptString = Get-Content -Path $ScriptPath -Raw;
            $ScriptName = Split-Path -Path $ScriptPath -Leaf -Resolve
        }
        ElseIf ($ScriptUri) {
            $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri)
            $ScriptName = Split-Path -Path $ScriptUri.OriginalString -Leaf
        }
        Else {
            $ScriptName = ""
            $null = [System.Security.Cryptography.HashAlgorithm]::Create('SHA256').ComputeHash([Text.Encoding]::UTF8.GetBytes($ScriptString)) | % {
                $ScriptName += $_.ToString("x2")
            }
        }
        
        $ScriptForName[$ScriptName] = $ScriptString
        $PSAmsiScanRequests += [PSCustomObject] @{ ScriptName = $ScriptName; ScriptString = $ScriptString; }
    }

    End {
        Write-Verbose "[Start-PSAmsiServer] Prepared $($PSAmsiScanRequests.Count) PSAmsiScanRequest(s)."
        $CachedAmsiScanResults = @{}
        $PSAmsiScanResults = @()
        $PendingGetRequestResponsesQueue = New-Object System.Collections.Queue
        
        $AwaitingGetRequest = $True

        $Finished = $False

        While (-not $Finished) {
            If ($AwaitingGetRequest -and $PendingGetRequestResponsesQueue.Count -gt 0) {
                Write-Verbose "[Start-PSAmsiServer] Servicing GET request from queue."
                $HTTPServerResponse = $PendingGetRequestResponsesQueue.Dequeue()

                $PSAmsiScanRequestObj = [PSCustomObject] @{ PSAmsiScanRequests = $PSAmsiScanRequests; CachedAmsiScanResults = $CachedAmsiScanResults }
                $JsonString = $PSAmsiScanRequestObj | ConvertTo-Json -Depth 4 -Compress
                
                $ResponseWriter = New-Object System.IO.StreamWriter($HTTPServerResponse.OutputStream)
                $ResponseWriter.Write($JsonString)
                $ResponseWriter.Close()
                $AwaitingGetRequest = $False
            }
            Write-Verbose "[Start-PSAmsiServer] Waiting for request from a client..."
            $HTTPServerContext = $HTTPServer.GetContext()
            $HTTPClientRequest = $HTTPServerContext.Request
            $HTTPServerResponse = $HTTPServerContext.Response
            If ($HTTPClientRequest.HttpMethod -eq 'GET') {
                If ((Split-Path -Path ($HTTPClientRequest.Url) -Leaf).ToLower().EndsWith('psamsiclient.ps1')) {
                    Write-Verbose "[Start-PSAmsiServer] Received GET request from client for PSAmsiClient.ps1"
                    $ResponseWriter = New-Object System.IO.StreamWriter($HTTPServerResponse.OutputStream)
                    $PSAmsiClientPath = (Split-Path -Parent $PSCommandPath) + "/../PSAmsiClient.ps1"
                    If (Test-Path $PSAmsiClientPath) {
                        Write-Verbose "[Start-PSAmsiServer] Serving PSAmsiClient.ps1 to client"
                        $ClientCode = Get-Content $PSAmsiClientPath -Raw
                        $ResponseWriter.Write($ClientCode)
                        $ResponseWriter.Close()
                    }
                    Else {
                        Write-Error "[Start-PSAmsiServer] PSAmsiClient.ps1 file could not be found. Sending empty response."
                        $ResponseWriter.Write('')
                        $ResponseWriter.Close()
                    }
                }
                Else {
                    Write-Verbose "[Start-PSAmsiServer] Received GET request from client. Adding it to the queue."
                    $PendingGetRequestResponsesQueue.Enqueue($HTTPServerResponse)
                }
            }
            ElseIf ($HTTPClientRequest.HttpMethod -eq 'POST') {
                Write-Verbose "[Start-PSAmsiServer] Received POST request from client. Processing data returned."
                $RequestReader = New-Object System.IO.StreamReader($HTTPClientRequest.InputStream, $HTTPClientRequest.ContentEncoding)
                $PSAmsiScanResultObj = $RequestReader.ReadToEnd() | ConvertFrom-Json
                $HTTPServerResponse.ContentLength64 = 0
                $HTTPServerResponse.OutputStream.Close()
                $PSAmsiScanResults += $PSAmsiScanResultObj.PSAmsiScanResults | ? { $_.RequestCompleted }
                $UnfinishedPSAmsiScanResults = $PSAmsiScanResultObj.PSAmsiScanResults | ? { -not $_.RequestCompleted }
                If ($UnfinishedPSAmsiScanResults) {
                    Write-Verbose "[Start-PSAmsiServer] $($UnfinishedPSAmsiScanResults.Count) PSAmsiScanRequest(s) were not completed."
                    # Not finished with at least one scan request
                    $CachedAmsiScanResults = @{}
                    $Result = $PSAmsiScanResultObj.CachedAmsiScanResults | Get-Member -MemberType Properties | % {
                        $CachedAmsiScanResults.Add($_.Name, $PSAmsiScanResultObj.CachedAmsiScanResults.($_.Name))
                    }
                    $PSAmsiScanRequests = @()
                    ForEach ($UnfinishedPSAmsiScanResult in $UnfinishedPSAmsiScanResults) {
                        If ($UnfinishedPSAmsiScanResult.MinimallyObfuscated) {
                            $ScriptString = $UnfinishedPSAmsiScanResult.MinimallyObfuscated
                        }
                        Else {
                            $ScriptString = $ScriptForName[$UnfinishedPSAmsiScanResult.ScriptName]
                        }
                        $PSAmsiScanRequests += [PSCustomObject] @{ ScriptName = $UnfinishedPSAmsiScanResult.ScriptName; ScriptString = $ScriptString; }
                    }
                    $AwaitingGetRequest = $True
                }
                Else {
                    $Finished = $True
                }
            }
            Else {
                Write-Error "[Start-PSAmsiServer] Client $($Client.RemoteEndpoint) attempted unknown HttpMethod $($HTTPClientRequest.HttpMethod)"
            }
        }
        Write-Verbose "[Start-PSAmsiServer] All scans completed. Stopping Server."
        $HTTPServer.Stop()
        $Properties = @('ScriptName', 'ScriptIsFlagged', 'RequestCompleted')
        If ($PSAmsiScanResults | ? { $_.AmsiSignatures }) { $Properties += 'AmsiSignatures' }
        If ($PSAmsiScanResults | ? { $_.MinimallyObfuscated }) { $Properties += 'MinimallyObfuscated' }
        $PSAmsiScanResults | Select-Object -Property $Properties -ExcludeProperty RequestCompleted | Sort-Object ScriptIsFlagged -Descending
    }
}