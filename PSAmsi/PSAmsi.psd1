# Module manifest for module 'PSAmsi'

@{

# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = 'e53f158d-8aa2-8c53-da89-ab75d32c8c01'

# Author of this module
Author = 'Ryan Cobb (@cobbr_io)'

# Description of the functionality provided by this module
Description = 'PSAmsi is a tool for auditing and defeating AMSI signatures.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Script files (.ps1) that are run in the caller's environment prior to importing this module
ScriptsToProcess = @('PSReflect.ps1','AmsiFunctions.ps1','PSAmsiScanner.ps1',
                     'Find-AmsiSignatures.ps1'
                     'Invoke-PSAmsiScan.ps1','Start-PSAmsiServer.ps1','Start-PSAmsiClient.ps1',
                     'Obfuscators\PowerShell\PowerShellObfuscator.ps1', 'Obfuscators\PowerShell\Out-ObfuscatedAst.ps1',
                     'Obfuscators\PowerShell\Invoke-Obfuscation\Out-ObfuscatedTokenCommand.ps1', 'Obfuscators\PowerShell\Invoke-Obfuscation\Out-ObfuscatedStringCommand.ps1')

# Functions to export from this module
FunctionsToExport = @('Start-PSAmsiServer', 'Start-PSAmsiClient', 'Invoke-PSAmsiScan',
                      'New-PSAmsiScanner', 'Get-PSAmsiScanResult', 'Reset-PSAmsiScanCache', 'Invoke-PSAmsiScan',
                      'Find-AmsiSignatures', 'Find-AmsiAstSignatures', 'Get-AmsiPSTokenSignatures',
                      'Test-ContainsAmsiSignatures', 'Test-ContainsAmsiAstSignatures', 'Test-ContainsAmsiPSTokenSignatures',
                      'Get-Ast', 'Get-PSTokens'
                      'Out-MinimallyObfuscated', 'Get-ContainingTokens',
                      'AmsiInitialize', 'AmsiOpenSession', 'AmsiScanString', 'AmsiScanBuffer', 'AmsiCloseSession', 'AmsiUninitialize')

}