class Obfuscator {
    <#

    .SYNOPSIS

    Exists purely as a template class for implementing Obfuscators.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: none

    .DESCRIPTION

    Obfuscator is a template class for obfuscators. Would function as an
    interface, but PowerShell v5 does not implement true interfaces.

    .EXAMPLE

    class SomeLanguageObfuscator {
        SomeLanguageObfuscator() { }
        [String] OutMinimallyObfuscated($ScriptString) { return $ScriptString }
    }

    .NOTES

    Obfuscator is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>

    Obfuscator() {}

    [String] OutMinimallyObfuscated([String] $ScriptString) { return $ScriptString }
}