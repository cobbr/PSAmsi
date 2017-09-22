# PSAmsi

PSAmsi is a tool for auditing and defeating AMSI signatures.

It's best utilized in a test environment to quickly create payloads you know will not be detected by a particular AntiMalware Provider, although it can be useful in certain situations outside of a test environment.

When using outside of a test environment, be sure to understand how PSAmsi works, as it can generate AMSI alerts.

# Getting Started

[Installation instructions](https://github.com/cobbr/PSAmsi/wiki/Installation-and-Setup) and an [introduction to using PSAmsi](https://github.com/cobbr/PSAmsi/wiki/Introduction-To-PSAmsi) are available in the Wiki.

# Disclaimer

You are only authorized to use PSAmsi (and payloads created with PSAmsi) on systems that you have permission to use it on. It was created for research purposes only.

# Acknowledgements

A huge thanks to the following people whose code is used by PSAmsi:
* Daniel Bohannon ([@danielhbohannon](https://twitter.com/danielhbohannon)) - PSAmsi currently uses Invoke-Obfuscation for *all* of it's obfuscation. Thanks Daniel!
* Matt Graeber ([@mattifestation](https://twitter.com/mattifestation)) - PSAmsi uses PSReflect to call the AMSI functions exported from the AMSI dll, while staying in memory. Thanks Matt!
