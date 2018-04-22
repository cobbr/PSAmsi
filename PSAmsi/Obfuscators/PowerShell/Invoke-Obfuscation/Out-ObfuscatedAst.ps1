function Out-ObfuscatedAst
{
    <#

    .SYNOPSIS

    Obfuscates PowerShell scripts using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Get-Ast
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedAst obfuscates PowerShell scripts using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER ScriptString

    Specifies the string containing the script to be obfuscated.

    .PARAMETER ScriptBlock

    Specifies the ScriptBlock containing the script to be obfuscated.

    .PARAMETER ScriptPath

    Specifies the Path containing the script to be obfuscated.

    .PARAMETER ScriptUri

    Specifies the Uri of the script to be obfuscated.

    .PARAMETER AbstractSyntaxTree

    Specifies the root Ast that represents the script to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root Ast should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedAst -Ast $AbstractSyntaxTree

    .EXAMPLE

    Out-ObfuscatedAst "Write-Host example"

    .EXAMPLE

    Out-ObfuscatedAst { Write-Host example }

    .EXAMPLE

    Out-ObfuscatedAst -ScriptPath $ScriptPath

    .EXAMPLE

    @($Ast1, $Ast2, $Ast3) | Out-ObfuscatedAst

    .NOTES

    Out-ObfuscatedAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

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

        [Parameter(ParameterSetName = "ByTree", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        If ($ScriptString) { $AbstractSyntaxTree = Get-Ast -ScriptString $ScriptString } 
        ElseIf ($ScriptBlock) {
            $AbstractSyntaxTree = Get-Ast -ScriptBlock $ScriptBlock
        }
        ElseIf ($ScriptPath) {
            $AbstractSyntaxTree = Get-Ast -ScriptPath $ScriptPath
        }
        ElseIf ($ScriptUri) {
            $AbstractSyntaxTree = Get-Ast -ScriptUri $ScriptUri
        }
        
        Switch ($AbstractSyntaxTree.GetType().Name) {
            "ArrayExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedArrayExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedArrayExpressionAst -Ast $AbstractSyntaxTree }
            }
            "ArrayLiteralAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedArrayLiteralAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedArrayLiteralAst -Ast $AbstractSyntaxTree }
            }
            "AssignmentStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedAssignmentStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedAssignmentStatementAst -Ast $AbstractSyntaxTree }
            }
            "AttributeAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedAttributeAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedAttributeAst -Ast $AbstractSyntaxTree }
            }
            "AttributeBaseAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedAttributeBaseAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedAttributeBaseAst -Ast $AbstractSyntaxTree }
            }
            "AttributedExpessionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedAttributedExpessionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedAssignmentStatementAst -Ast $AbstractSyntaxTree }
            }
            "BaseCtorInvokeMemberExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedBaseCtorInvokeMemberExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedBaseCtorInvokeMemberExpressionAst -Ast $AbstractSyntaxTree }
            }
            "BinaryExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedBinaryExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedBinaryExpressionAst -Ast $AbstractSyntaxTree }
            }
            "BlockStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedBlockStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedBlockStatementAst -Ast $AbstractSyntaxTree }
            }
            "BreakStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedBreakStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedBreakStatementAst -Ast $AbstractSyntaxTree }
            }
            "CatchClauseAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCatchClauseAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedCatchClauseAst -Ast $AbstractSyntaxTree }
            }
            "CommandAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandAst -Ast $AbstractSyntaxTree }
            }
            "CommandBaseAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandBaseAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandBaseAst -Ast $AbstractSyntaxTree }
            } 
            "CommandElementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandElementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandElementAst -Ast $AbstractSyntaxTree }
            }
            "CommandExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandExpressionAst -Ast $AbstractSyntaxTree }
            }
            "CommandParameterAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandParameterAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandParameterAst -Ast $AbstractSyntaxTree }
            }
            "ConfigurationDefinitionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedConfigurationDefinitionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedConfigurationDefinitionAst -Ast $AbstractSyntaxTree }
            }
            "ConstantExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedConstantExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedConstantExpressionAst -Ast $AbstractSyntaxTree }
            }
            "ContinueStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedContinueStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { $ObfuscatedExtent = Out-ObfuscatedContinueStatementAst -Ast $AbstractSyntaxTree }
            }
            "ConvertExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedConvertExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedConvertExpressionAst -Ast $AbstractSyntaxTree }
            }
            "DataStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedDataStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedDataStatementAst -Ast $AbstractSyntaxTree }
            }
            "DoUntilStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedDoUntilStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedDoUntilStatementAst -Ast $AbstractSyntaxTree }
            }
            "DoWhileStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedDoWhileStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedDoWhileStatementAst -Ast $AbstractSyntaxTree }
            }
            "DynamicKeywordStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedDynamicKeywordStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedDynamicKeywordStatementAst -Ast $AbstractSyntaxTree }
            }
            "ErrorStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedErrorStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedErrorStatementAst -Ast $AbstractSyntaxTree }
            }
            "ExitStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedExitStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedExitStatementAst -Ast $AbstractSyntaxTree }
            }
            "ExpandableStringExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedExpandableStringExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedExpandableStringExpressionAst -Ast $AbstractSyntaxTree }
            }
            "ExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedExpressionAst -Ast $AbstractSyntaxTree }
            }
            "FileRedirectionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedFileRedirectionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedFileRedirectionAst -Ast $AbstractSyntaxTree }
            }
            "ForEachStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedForEachStatementAstt -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedForEachStatementAst -Ast $AbstractSyntaxTree }
            }
            "ForStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedForStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedForStatementAst -Ast $AbstractSyntaxTree }
            }
            "FunctionDefinitionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedFunctionDefinitionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedFunctionDefinitionAst -Ast $AbstractSyntaxTree }
            }
            "FunctionMemberAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedFunctionMemberAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedFunctionMemberAst -Ast $AbstractSyntaxTree }
            }
            "HashtableAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedHashtableAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedHashtableAst -Ast $AbstractSyntaxTree }
            }
            "IfStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedIfStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedIfStatementAst -Ast $AbstractSyntaxTree }
            }
            "IndexExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedIndexExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedIndexExpressionAst -Ast $AbstractSyntaxTree }
            }
            "InvokeMemberExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedInvokeMemberExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedInvokeMemberExpressionAst -Ast $AbstractSyntaxTree }
            }
            "LabeledStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedLabeledStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedLabeledStatementAst -Ast $AbstractSyntaxTree }
            }
            "LoopStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedLoopStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedLoopStatementAst -Ast $AbstractSyntaxTree }
            }
            "MemberAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedMemberAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedMemberAst -Ast $AbstractSyntaxTree }
            }
            "MemberExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedMemberExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedMemberExpressionAst -Ast $AbstractSyntaxTree }
            }
            "MergingRedirectionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedMergingRedirectionAstt -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedMergingRedirectionAstt -Ast $AbstractSyntaxTree }
            }
            "NamedAttributeArgumentAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedNamedAttributeArgumentAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedNamedAttributeArgumentAst -Ast $AbstractSyntaxTree }
            }
            "NamedBlockAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedNamedBlockAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedNamedBlockAst -Ast $AbstractSyntaxTree }
            }
            "ParamBlockAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedParamBlockAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedParamBlockAst -Ast $AbstractSyntaxTree }
            }
            "ParameterAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedParameterAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedParameterAst -Ast $AbstractSyntaxTree }
            }
            "ParenExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedParenExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedParenExpressionAst -Ast $AbstractSyntaxTree }
            }
            "PipelineAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedPipelineAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedPipelineAst -Ast $AbstractSyntaxTree }
            }
            "PipelineBaseAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedPipelineBaseAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedPipelineBaseAst -Ast $AbstractSyntaxTree }
            }
            "PropertyMemberAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedPropertyMemberAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedPropertyMemberAst -Ast $AbstractSyntaxTree }
            }
            "RedirectionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedRedirectionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedRedirectionAst -Ast $AbstractSyntaxTree }
            }
            "ReturnStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedReturnStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedReturnStatementAst -Ast $AbstractSyntaxTree }
            }
            "ScriptBlockAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedScriptBlockAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedScriptBlockAst -Ast $AbstractSyntaxTree }
            }
            "ScriptBlockExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedScriptBlockExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedScriptBlockExpressionAst -Ast $AbstractSyntaxTree }
            }
            "StatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedStatementAst -Ast $AbstractSyntaxTree }
            }
            "StatementBlockAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedStatementBlockAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedStatementBlockAst -Ast $AbstractSyntaxTree }
            }
            "StringConstantExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedStringConstantExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedStringConstantExpressionAst -Ast $AbstractSyntaxTree }
            }
            "SubExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedSubExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedSubExpressionAst -Ast $AbstractSyntaxTree }
            }
            "SwitchStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedSwitchStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedSwitchStatementAst -Ast $AbstractSyntaxTree }
            }
            "ThrowStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedThrowStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedThrowStatementAst -Ast $AbstractSyntaxTree }
            }
            "TrapStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTrapStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedTrapStatementAst -Ast $AbstractSyntaxTree }
            }
            "TryStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTryStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedTryStatementAst -Ast $AbstractSyntaxTree }
            }
            "TypeConstraintAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTypeConstraintAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedTypeConstraintAst -Ast $AbstractSyntaxTree }
            }
            "TypeDefinitionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTypeDefinitionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedTypeDefinitionAst -Ast $AbstractSyntaxTree }
            }
            "TypeExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTypeExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedTypeExpressionAst -Ast $AbstractSyntaxTree }
            }
            "UnaryExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedUnaryExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedUnaryExpressionAst -Ast $AbstractSyntaxTree }
            }
            "UsingExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedUsingExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedUsingExpressionAst -Ast $AbstractSyntaxTree }
            }
            "UsingStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedUsingStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedUsingStatementAst -Ast $AbstractSyntaxTree }

            }
            "VariableExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedVariableExpressionAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedVariableExpressionAst -Ast $AbstractSyntaxTree }
            }
            "WhileStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedWhileStatementAst -Ast $AbstractSyntaxTree -DisableNestedObfuscation }
                Else { Out-ObfuscatedWhileStatementAst -Ast $AbstractSyntaxTree }
            }
        }
    }
}

# Ast Children

function Out-ObfuscatedAttributeBaseAst {
    <#

    .SYNOPSIS

    Obfuscates a AttributeBaseAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedAttributeAst, Out-ObfuscatedTypeConstraintAst, Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedAttributeBaseAst obfuscates a AttributeBaseAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the AttributeBaseAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root AttributeBaseAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedAttributeBaseAst -Ast $AttributeBaseAst

    .NOTES

    Out-ObfuscatedAttributeBaseAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.AttributeBaseAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedAttributeBaseAst]"
        # Abstract Ast Type, call inherited ast obfuscation type
        If ($AbstractSyntaxTree.GetType().Name -eq 'AttributeAst') {
            Out-ObfuscatedAttributeAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'TypeConstraintAst') {
            Out-ObfuscatedTypeConstraintAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else {
            $AbstractSyntaxTree.Extent.Text
        }
    }
}

function Out-ObfuscatedCatchClauseAst {
    <#

    .SYNOPSIS

    Obfuscates a CatchClauseAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedCatchClauseAst obfuscates a CatchClauseAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the CatchClauseAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root CatchClauseAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedCatchClauseAst -Ast $CatchClauseAst

    .NOTES

    Out-ObfuscatedAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CatchClauseAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCatchClauseAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedCommandElementAst {
    <#

    .SYNOPSIS

    Obfuscates a CommandElementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedCommandParameterAst, Out-ObfuscatedExpressionAst, Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedCommandElementAst obfuscates a CommandElementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the CommandElementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root CommandElementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedCommandElementAst -Ast $CommandElementAst

    .NOTES

    Out-ObfuscatedCommandElementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandElementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandElementAst]"
        # Abstract Ast Type, call child inherited ast obfuscation type
        If ($AbstractSyntaxTree.GetType().Name -eq 'CommandParameterAst') {
            Out-ObfuscatedCommandParameterAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ExpressionAst') {
            Out-ObfuscatedExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else {
            $AbstractSyntaxTree.Extent.Text
        }
    }
}

function Out-ObfuscatedMemberAst {
    <#

    .SYNOPSIS

    Obfuscates a MemberAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedMemberAst obfuscates a MemberAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the MemberAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root MemberAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedMemberAst -Ast $MemberAst

    .NOTES

    Out-ObfuscatedMemberAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.MemberAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedMemberAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedNamedAttributeArgumentAst {
    <#

    .SYNOPSIS

    Obfuscates a NamedAttributeArgumentAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedNamedAttributeArgumentAst obfuscates a NamedAttributeArgumentAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the NamedAttributeArgumentAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root NamedAttributeArgumentAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedNamedAttributeArgumentAst -Ast $NamedAttributeArgumentAst

    .NOTES

    Out-ObfuscatedNamedAttributeArgumentAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.NamedAttributeArgumentAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedNamedAttributeArgumentAst]"
        If ($AbstractSyntaxTree.ExpressionOmitted) {
            $AbstractSyntaxTree.Extent.Text + " = `$True"
        }
        ElseIf ($AbstractSyntaxTree.Argument.Extent.Text -eq "`$True") {
            $AbstractSyntaxTree.ArgumentName
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedNamedBlockAst {
    <#

    .SYNOPSIS

    Obfuscates a NamedAttributeArgumentAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedNamedBlockAst obfuscates a NamedBlockAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the NamedBlockAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root NamedBlockAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedNamedBlockAst -Ast $NamedBlockAst

    .NOTES

    Out-ObfuscatedNamedBlockAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.NamedBlockAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedNamedBlockAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedParamBlockAst {
    <#

    .SYNOPSIS

    Obfuscates a ParamBlockAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedAstsReordered, Get-AstChildren
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedParamBlockAst obfuscates a ParamBlockAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ParamBlockAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ParamBlockAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedParamBlockAst -Ast $ParamBlockAst

    .NOTES

    Out-ObfuscatedParamBlockAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ParamBlockAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedParamBlockAst]"
        If (-not $DisableNestedObfuscation) {
            $Children = (Get-AstChildren -AbstractSyntaxTree $AbstractSyntaxTree | ? { $_.Extent.StartScriptPosition.GetType().Name -ne 'EmptyScriptPosition' } | Sort-Object { $_.Extent.StartOffset }) -as [array]
            # For some reason 'Attribute' children do not exist within the ParamBlockAst Extent. Very frustrating.
            $ChildrenNotAttributes = $Children | ? { -not ($_ -in $AbstractSyntaxTree.Attributes) }
            $ChildrenAttributes = $Children | ? { $_ -in $AbstractSyntaxTree.Attributes }
            
            Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $ChildrenNotAttributes
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedParameterAst {
    <#

    .SYNOPSIS

    Obfuscates a ParameterAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedAstsReordered, Get-AstChildren
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedParameterAst obfuscates a ParameterAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ParameterAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ParameterAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedParameterAst -Ast $ParameterAst

    .NOTES

    Out-ObfuscatedParameterAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ParameterAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedParameterAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedRedirectionAst {
    <#

    .SYNOPSIS

    Obfuscates a RedirectionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedRedirectionAst obfuscates a RedirectionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the RedirectionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root RedirectionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedRedirectionAst -Ast $RedirectionAst

    .NOTES

    Out-ObfuscatedRedirectionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.RedirectionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedRedirectionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedScriptBlockAst {
    <#

    .SYNOPSIS

    Obfuscates a ScriptBlockAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst, Out-ObfuscatedAstsReordered, Out-ObfuscatedAst, Get-AstChildren
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedScriptBlockAst obfuscates a ScriptBlockAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ScriptBlockAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ScriptBlockAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedScriptBlockAst -Ast $ScriptBlockAst

    .NOTES

    Out-ObfuscatedScriptBlockAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ScriptBlockAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedScriptBlockAst]"
        If (-not $DisableNestedObfuscation) {
            $Children = (Get-AstChildren -Ast $AbstractSyntaxTree | ? { $_.Extent.StartScriptPosition.GetType().Name -ne 'EmptyScriptPosition' }) -as [array]
            $RealChildren = $Children
            $FunctionDefinitionBlocks = @()
            If ($AbstractSyntaxTree.BeginBlock) { $FunctionDefinitionBlocks += $AbstractSyntaxTree.BeginBlock }
            If ($AbstractSyntaxTree.ProcessBlock) { $FunctionDefinitionBlocks += $AbstractSyntaxTree.ProcessBlock }
            If ($AbstractSyntaxTree.EndBlock) { $FunctionDefinitionBlocks += $AbstractSyntaxTree.EndBlock }

            If ($Children.Count -eq 2 -AND $Children[0].GetType().Name -eq 'ParamBlockAst' -AND $Children[1].GetType().Name -eq 'NamedBlockAst' -AND $Children[1] -eq $AbstractSyntaxTree.EndBlock) {
                [System.Management.Automation.Language.Ast[]] $RealChildren = ($Children[0]) -as [array]
                $RealChildren += (Get-AstChildren -Ast $Children[1] | ? { $_.Extent.StartScriptPosition.GetType().Name -ne 'EmptyScriptPosition' } | Sort-Object { $_.Extent.StartOffset }) -as [array]
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -ChildrenAsts $RealChildren
            }
            ElseIf ($FunctionDefinitionBlocks.Count -gt 1) {
                $Children = $Children | Sort-Object { $_.Extent.StartOffset }
                $Reordered  = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts ($FunctionDefinitionBlocks | Sort-Object { $_.Extent.StartOffset })

                If ($AbstractSyntaxTree.ParamBlock) {
                    $ObfuscatedParamBlock = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.ParamBlock
                    $FinalObfuscated = [String] $AbstractSyntaxTree.Extent.Text.Substring(0, $AbstractSyntaxTree.ParamBlock.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset)
                    $FinalObfuscated += [String] $ObfuscatedParamBlock
                    $FinalObfuscated += [String] $Reordered.Substring($AbstractSyntaxTree.ParamBlock.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset + $AbstractSyntaxTree.ParamBlock.Extent.Text.Length)
                } Else { $FinalObfuscated = $Reordered }

                $FinalObfuscated
            }
            Else {
                $Children = $Children | Sort-Object { $_.Extent.StartOffset }
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -ChildrenAsts $Children
            }
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a StatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedStatementAst obfuscates a StatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the StatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root StatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedStatementAst -Ast $StatementAst

    .NOTES

    Out-ObfuscatedStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.StatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedStatementBlockAst {
    <#

    .SYNOPSIS

    Obfuscates a StatementBlockAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedStatementBlockAst obfuscates a StatementBlockAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the StatementBlockAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root StatementBlockAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedStatementBlockAst -Ast $StatementBlockAst

    .NOTES

    Out-ObfuscatedStatementBlockAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.StatementBlockAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedStatementBlockAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# AttributeBaseAst Inherited classes

function Out-ObfuscatedAttributeAst {
    <#

    .SYNOPSIS

    Obfuscates a AttributeAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedAstsReordered
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedAttributeAst obfuscates a AttributeAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the AttributeAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root AttributeAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedAttributeAst -Ast $AttributeAst

    .NOTES

    Out-ObfuscatedAttributeAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.AttributeAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedAttributeAst]"
        $ObfuscationDecision = 0
        Switch ($ObfuscationDecision) {
            # Reorders the NamedArguments or applicable PositionalArguments
            0 {
                $ObfuscatedString = $AbstractSyntaxTree.Extent.Text
                If ($AbstractSyntaxTree.NamedArguments.Count -gt 0) {
                    $NamedArguments = $AbstractSyntaxTree.NamedArguments
                    If ($DisableNestedObfuscation) {
                        $ObfuscatedString = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $NamedArguments -DisableNestedObfuscation
                    } Else {
                        $ObfuscatedString = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $NamedArguments
                    }
                }
                ElseIf ($AbstractSyntaxTree.PositionalArguments.Count -gt 0) {
                    If ($AbstractSyntaxTree.TypeName.FullName -in @('Alias', 'ValidateSet')) {
                        $PositionalArguments = $AbstractSyntaxTree.PositionalArguments
                        If ($DisableNestedObfuscation) {
                            $ObfuscatedString = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $PositionalArguments -DisableNestedObfuscation
                        } Else {
                            $ObfuscatedString = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $PositionalArguments
                        }
                    }
                }

                $ObfuscatedString
            }
        }
    }
}

function Out-ObfuscatedTypeConstraintAst {
    <#

    .SYNOPSIS

    Obfuscates a TypeConstraintAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedTypeConstraintAst obfuscates a TypeConstraintAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the TypeConstraintAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root TypeConstraintAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedTypeConstraintAst -Ast $TypeConstraintAst

    .NOTES

    Out-ObfuscatedTypeConstraintAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TypeConstraintAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTypeConstraintAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}


# CommandElementAst Inherited Classes

function Out-ObfuscatedCommandParameterAst {
    <#

    .SYNOPSIS

    Obfuscates a CommandParameterAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedCommandParameterAst obfuscates a CommandParameterAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the CommandParameterAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root CommandParameterAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedCommandParameterAst -Ast $CommandParameterAst

    .NOTES

    Out-ObfuscatedCommandParameterAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandParameterAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandParameterAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a ExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedArrayExpressionAst, Out-ObfuscatedArrayLiteralAst, Out-ObfuscatedAttributedExpressionAst, Out-ObfuscatedBinaryExpressionAst, Out-ObfuscatedConstantExpressionAst, Out-ObfuscatedErrorExpressionAst, Out-ObfuscatedExpandedStringExpressionAst, Out-ObfuscatedHashtableAst, Out-ObfuscatedIndexExpressionAst, Out-ObfuscatedMemberExpressionAst, Out-ObfuscatedParenExpressionAst, Out-ObfuscatedScriptBlockExpressionAst, Out-ObfuscatedSubExpressionAst, Out-ObfuscatedTypeExpressionAst, Out-ObfuscatedUnaryExpressionAst, Out-ObfuscatedUsingExpressionAst, Out-ObfuscatedVariableExpressionAst, Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedExpressionAst obfuscates a ExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedExpressionAst -Ast $ExpressionAst

    .NOTES

    Out-ObfuscatedExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedExpressionAst]"
        # Abstract Ast Type, call inherited ast obfuscation type
        If ($AbstractSyntaxTree.GetType().Name -eq 'ArrayExpressionAst') {
            Out-ObfuscatedArrayExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ArrayLiteralAst') {
            Out-ObfuscatedArrayLiteralAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'AttributedExpressionAst') {
            Out-ObfuscatedAttributedExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'BinaryExpressionAst') {
            Out-ObfuscatedBinaryExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ConstantExpressionAst') {
            Out-ObfuscatedConstantExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ErrorExpressionAst') {
            Out-ObfuscatedErrorExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ExpandedStringExpressionAst') {
            Out-ObfuscatedExpandedStringExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'HashtableAst') {
            Out-ObfuscatedHashtableAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'IndexExpressionAst') {
            Out-ObfuscatedIndexExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'MemberExpressionAst') {
            Out-ObfuscatedMemberExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ParenExpressionAst') {
            Out-ObfuscatedParenExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ScriptBlockExpressionAst') {
            Out-ObfuscatedScriptBlockExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'SubExpressionAst') {
            Out-ObfuscatedSubExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'TypeExpressionAst') {
            Out-ObfuscatedTypeExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'UnaryExpressionAst') {
            Out-ObfuscatedUnaryExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'UsingExpressionAst') {
            Out-ObfuscatedUsingExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'VariableExpressionAst') {
            Out-ObfuscatedVariableExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else {
            $AbstractSyntaxTree.Extent.Text
        }
    }
}

# ExpressionAst Inherited Classes

function Out-ObfuscatedArrayExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates an ArrayExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedArrayExpressionAst obfuscates an ArrayExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ArrayExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ArrayExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedArrayExpressionAst -Ast $ArrayExpressionAst

    .NOTES

    Out-ObfuscatedArrayExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ArrayExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedArrayExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedArrayLiteralAst {
    <#

    .SYNOPSIS

    Obfuscates an ArrayLiteralAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedArrayLiteralAst obfuscates an ArrayLiteralAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ArrayLiteralAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ArrayLiteralAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedArrayLiteralAst -Ast $ArrayLiteralAst

    .NOTES

    Out-ObfuscatedArrayLiteralAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ArrayLiteralAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedArrayLiteralAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedAttributedExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates an AttributedExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedArrayExpressionAst, Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedAttributedExpressionAst obfuscates an AttributedExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the AttributedExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root AttributedExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedAttributedExpressionAst -Ast $ArrayLiteralAst

    .NOTES

    Out-ObfuscatedAttributedExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.AttributedExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedAttributedExpressionAst]"
        If ($AbstractSyntaxTree.GetType().Name -eq 'ConvertExpressionAst') {
            Out-ObfuscatedArrayExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else {
            $AbstractSyntaxTree.Extent.Text
        }
    }
}

function Out-ObfuscatedBinaryExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a BinaryExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Test-ExpressionAstIsNumeric, Out-ObfuscatedAst, Out-ParenthesizedString, Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedBinaryExpressionAst obfuscates a BinaryExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the BinaryExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root BinaryExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedBinaryExpressionAst -Ast $BinaryExpressionAst

    .NOTES

    Out-ObfuscatedBinaryExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.BinaryExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedBinaryExpressionAst]"
        $ObfuscationDecision = 0
        Switch($ObfuscationDecision) {
            0 {
                $OperatorText = [System.Management.Automation.Language.TokenTraits]::Text($AbstractSyntaxTree.Operator)

                $ObfuscatedString = $AbstractSyntaxTree.Extent.Text

                # Numeric operation obfuscation
                If((Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Left) -AND (Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Right)) {
                    $Whitespace = ""
                    If ((Get-Random @(0,1)) -eq 0) { $Whitespace = " " }
                    # Operators that can be reordered
                    $LeftString = $AbstractSyntaxTree.Left.Extent.Text
                    $RightString = $AbstractSyntaxTree.Right.Extent.Text
                    If (-not $DisableNestedObfuscation) {
                        $LeftString = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left
                        $RightString = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right
                    }
                    If ($OperatorText -in @("+", "*")) {
                        $ObfuscatedString = $RightString + $Whitespace + $OperatorText + $Whitespace + $LeftString
                    }
                    ElseIf ($OperatorText -eq "-") {
                        $ObfuscatedString = Out-ParenthesizedString -String ("-" + $Whitespace + (Out-ParenthesizedString -String ((Out-ParenthesizedString $RightString) + $Whitespace + $OperatorText + $Whitespace + (Out-ParenthesizedString $LeftString))))
                    }
                }
                ElseIf (-not $DisableNestedObfuscation) { $ObfuscatedString = Out-ObfuscatedChildrenAst -Ast $AbstractSyntaxTree }

                $ObfuscatedString
            }
        }
    }
}

function Out-ObfuscatedConstantExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a ConstantExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedConstantExpressionAst obfuscates a ConstantExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ConstantExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ConstantExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedConstantExpressionAst -Ast $ConstantExpressionAst

    .NOTES

    Out-ObfuscatedConstantExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ConstantExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedConstantExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedErrorExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a ErrorExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedErrorExpressionAst obfuscates a ErrorExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ErrorExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ErrorExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedErrorExpressionAst -Ast $ErrorExpressionAst

    .NOTES

    Out-ObfuscatedErrorExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ErrorExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedErrorExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedExpandableStringExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates an ExpandableStringExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedExpandableStringExpressionAst obfuscates an ExpandableStringExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ExpandableStringExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ExpandableStringExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedExpandableStringExpressionAst -Ast $ExpandableStringExpressionAst

    .NOTES

    Out-ObfuscatedExpandableStringExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ExpandableStringExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedExpandableStringExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedHashtableAst {
    <#

    .SYNOPSIS

    Obfuscates a HashtableAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedHashtableAst obfuscates a HashtableAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the HashtableAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root HashtableAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedHashtableAst -Ast $HashtableAst

    .NOTES

    Out-ObfuscatedHashtableAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.HashtableAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedHashtableAst]"
        $ObfuscationDecision = 0
        Switch($ObfuscationDecision) {
            0 {
                $ObfuscatedKeyValuePairs = @()
                $ChildrenAsts = $AbstractSyntaxTree.KeyValuePairs | %  { $_.Item1; $_.Item2 }
                If ($DisableNestedObfuscation) {
                    $ObfuscatedKeyValuePairs = $AbstractSyntaxTree.KeyValuePairs
                }
                Else {
                    ForEach ($KeyValuePair in $AbstractSyntaxTree.KeyValuePairs) {
                        $ObfuscatedItem1 = Out-ObfuscatedAst $KeyValuePair.Item1
                        $ObfuscatedItem2 = Out-ObfuscatedAst $KeyValuePair.Item2
                        $ObfuscatedKeyValuePairs += [System.Tuple]::Create($ObfuscatedItem1, $ObfuscatedItem2)
                    }
                }

                $ObfuscatedString = $AbstractSyntaxTree.Extent.Text
                $ObfuscatedString = "@{"
                If ($ObfuscatedKeyValuePairs.Count -ge 1) {
                    $ObfuscatedKeyValuePairs = $ObfuscatedKeyValuePairs | Get-Random -Count $ObfuscatedKeyValuePairs.Count
                    ForEach ($ObfuscatedKeyValuePair in $ObfuscatedKeyValuePairs) {
                        $ObfuscatedString += $ObfuscatedKeyValuePair.Item1 + "=" + $ObfuscatedKeyValuePair.Item2 + ";"
                    }
                }
                $ObfuscatedString += "}"

                $ObfuscatedString
            }
        }
    }
}

function Out-ObfuscatedIndexExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a IndexExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedHashtableAst obfuscates a IndexExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the IndexExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root IndexExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedIndexExpressionAst -Ast $IndexExpressionAst

    .NOTES

    Out-ObfuscatedIndexExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.IndexExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedIndexExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedMemberExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a MemberExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedMemberExpressionAst obfuscates a MemberExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the MemberExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root MemberExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedMemberExpressionAst -Ast $MemberExpressionAst

    .NOTES

    Out-ObfuscatedMemberExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.MemberExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedMemberExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedParenExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a ParenExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedParenExpressionAst obfuscates a ParenExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ParenExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ParenExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedParenExpressionAst -Ast $ParenExpressionAst

    .NOTES

    Out-ObfuscatedParenExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ParenExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedParenExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedScriptBlockExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a ScriptBlockExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedScriptBlockExpressionAst obfuscates a ScriptBlockExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ScriptBlockExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ScriptBlockExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedScriptBlockExpressionAst -Ast $ScriptBlockExpressionAst

    .NOTES

    Out-ObfuscatedScriptBlockExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ScriptBlockExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedScriptBlockExpressionAst]"
        $ExtentToObfuscate = ""
        If (-not $DisableNestedObfuscation) {
            $ExtentToObfuscate = Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $ExtentToObfuscate = $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedSubExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a SubExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedSubExpressionAst obfuscates a SubExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the SubExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root SubExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedSubExpressionAst -Ast $SubExpressionAst

    .NOTES

    Out-ObfuscatedSubExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.SubExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedSubExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedTypeExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a TypeExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedTypeExpressionAst obfuscates a TypeExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the TypeExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root TypeExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedTypeExpressionAst -Ast $TypeExpressionAst

    .NOTES

    Out-ObfuscatedTypeExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TypeExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTypeExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedUnaryExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a UnaryExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedUnaryExpressionAst obfuscates a UnaryExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the UnaryExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root UnaryExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedUnaryExpressionAst -Ast $UnaryExpressionAst

    .NOTES

    Out-ObfuscatedUnaryExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.UnaryExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedUnaryExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedUsingExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a UnaryExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedUsingExpressionAst obfuscates a UsingExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the UsingExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root UsingExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedUsingExpressionAst -Ast $UsingExpressionAst

    .NOTES

    Out-ObfuscatedUsingExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.UsingExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedUsingExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedVariableExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a VariableExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedVariableExpressionAst obfuscates a VariableExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the VariableExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root VariableExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedVariableExpressionAst -Ast $VariableExpressionAst

    .NOTES

    Out-ObfuscatedVariableExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.VariableExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedVariableExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# AttributedExpressionAst Inherited Class

function Out-ObfuscatedConvertExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a ConvertExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedConvertExpressionAst obfuscates a ConvertExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ConvertExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ConvertExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedConvertExpressionAst -Ast $ConvertExpressionAst

    .NOTES

    Out-ObfuscatedConvertExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ConvertExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedConvertExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# ConstantExpressionAst Inherited Class

function Out-ObfuscatedStringConstantExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a StringConstantExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedStringConstantExpressionAst obfuscates a StringConstantExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the StringConstantExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root StringConstantExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedStringConstantExpressionAst -Ast $StringConstantExpressionAst

    .NOTES

    Out-ObfuscatedStringConstantExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.StringConstantExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedStringConstantExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# MemberExpressionAst Inherited Class

function Out-ObfuscatedInvokeMemberExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a InvokeMemberExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedInvokeMemberExpressionAst obfuscates a InvokeMemberExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the InvokeMemberExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root InvokeMemberExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedInvokeMemberExpressionAst -Ast $InvokeMemberExpressionAst

    .NOTES

    Out-ObfuscatedInvokeMemberExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.InvokeMemberExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedInvokeMemberExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# InvokeMemberExpressionAst Inherited Class

function Out-ObfuscatedBaseCtorInvokeMemberExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a BaseCtorInvokeMemberExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedBaseCtorInvokeMemberExpressionAst obfuscates a BaseCtorInvokeMemberExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the BaseCtorInvokeMemberExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root BaseCtorInvokeMemberExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedBaseCtorInvokeMemberExpressionAst -Ast $InvokeMemberExpressionAst

    .NOTES

    Out-ObfuscatedBaseCtorInvokeMemberExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.BaseCtorInvokeMemberExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedBaseCtorInvokeMemberExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# MemberAst Inherited Classes

function Out-ObfuscatedFunctionMemberAst {
    <#

    .SYNOPSIS

    Obfuscates a FunctionMemberAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedFunctionMemberAst obfuscates a FunctionMemberAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the FunctionMemberAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root FunctionMemberAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedFunctionMemberAst -Ast $FunctionMemberAst

    .NOTES

    Out-ObfuscatedFunctionMemberAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.FunctionMemberAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedFunctionMemberAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedPropertyMemberAst {
    <#

    .SYNOPSIS

    Obfuscates a PropertyMemberAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedPropertyMemberAst obfuscates a PropertyMemberAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the PropertyMemberAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root PropertyMemberAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedPropertyMemberAst -Ast $PropertyMemberAst

    .NOTES

    Out-ObfuscatedPropertyMemberAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.PropertyMemberAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedPropertyMemberAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# RedirectionAst Inherited Classes

function Out-ObfuscatedFileRedirectionAst {
    <#

    .SYNOPSIS

    Obfuscates a FileRedirectionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedFileRedirectionAst obfuscates a FileRedirectionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the FileRedirectionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root FileRedirectionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedFileRedirectionAst -Ast $FileRedirectionAst

    .NOTES

    Out-ObfuscatedFileRedirectionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.FileRedirectionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedFileRedirectionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedMergingRedirectionAst {
    <#

    .SYNOPSIS

    Obfuscates a MergingRedirectionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedMergingRedirectionAst obfuscates a MergingRedirectionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the MergingRedirectionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root MergingRedirectionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedMergingRedirectionAst -Ast $MergingRedirectionAst

    .NOTES

    Out-ObfuscatedMergingRedirectionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.MergingRedirectionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedMergingRedirectionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# StatementAst Inherited Classes

function Out-ObfuscatedBlockStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a BlockStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedBlockStatementAst obfuscates a BlockStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the BlockStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root BlockStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedBlockStatementAst -Ast $BlockStatementAst

    .NOTES

    Out-ObfuscatedBlockStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.BlockStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedBlockStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedBreakStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a BreakStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedBreakStatementAst obfuscates a BreakStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the BreakStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root BreakStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedBreakStatementAst -Ast $BreakStatementAst

    .NOTES

    Out-ObfuscatedBreakStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.BreakStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedBreakStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedCommandBaseAst {
    <#

    .SYNOPSIS

    Obfuscates a CommandBaseAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedCommandBaseAst obfuscates a CommandBaseAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the CommandBaseAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root CommandBaseAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedCommandBaseAst -Ast $CommandBaseAst

    .NOTES

    Out-ObfuscatedCommandBaseAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandBaseAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandBaseAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedConfigurationDefinitionAst {
    <#

    .SYNOPSIS

    Obfuscates a ConfigurationDefinitionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedConfigurationDefinitionAst obfuscates a ConfigurationDefinitionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ConfigurationDefinitionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ConfigurationDefinitionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedConfigurationDefinitionAst -Ast $ConfigurationDefinitionAst

    .NOTES

    Out-ObfuscatedConfigurationDefinitionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ConfigurationDefinitionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedConfigurationDefinitionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedContinueStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a ContinueStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedContinueStatementAst obfuscates a ContinueStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ContinueStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ContinueStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedContinueStatementAst -Ast $ContinueStatementAst

    .NOTES

    Out-ObfuscatedContinueStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ContinueStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedContinueStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedDataStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a DataStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedDataStatementAst obfuscates a DataStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the DataStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root DataStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedDataStatementAst -Ast $DataStatementAst

    .NOTES

    Out-ObfuscatedDataStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.DataStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedDataStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedDynamicKeywordStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a DynamicKeywordStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedDynamicKeywordStatementAst obfuscates a DynamicKeywordStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the DynamicKeywordStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root DynamicKeywordStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedDynamicKeywordStatementAst -Ast $DataStatementAst

    .NOTES

    Out-ObfuscatedDynamicKeywordStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.DynamicKeywordStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedDynamicKeywordStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedExitStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a ExitStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedExitStatementAst obfuscates a ExitStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ExitStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ExitStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedExitStatementAst -Ast $ExitStatementAst

    .NOTES

    Out-ObfuscatedExitStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ExitStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedExitStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedFunctionDefinitionAst {
    <#

    .SYNOPSIS

    Obfuscates a FunctionDefinitionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedFunctionDefinitionAst obfuscates a FunctionDefinitionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the FunctionDefinitionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root FunctionDefinitionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedFunctionDefinitionAst -Ast $FunctionDefinitionAst

    .NOTES

    Out-ObfuscatedFunctionDefinitionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.FunctionDefinitionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedFunctionDefinitionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedIfStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a IfStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedIfStatementAst obfuscates a IfStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the IfStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root IfStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedIfStatementAst -Ast $IfStatementAst

    .NOTES

    Out-ObfuscatedIfStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.IfStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedIfStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedLabeledStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a LabeledStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedLabeledStatementAst obfuscates a LabeledStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the LabeledStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root LabeledStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedLabeledStatementAst -Ast $IfStatementAst

    .NOTES

    Out-ObfuscatedLabeledStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.LabeledStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedLabeledStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedPipelineBaseAst {
    <#

    .SYNOPSIS

    Obfuscates a PipelineBaseAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedPipelineBaseAst obfuscates a PipelineBaseAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the PipelineBaseAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root PipelineBaseAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedPipelineBaseAst -Ast $PipelineBaseAst

    .NOTES

    Out-ObfuscatedPipelineBaseAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.PipelineBaseAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedPipelineBaseAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedReturnStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a ReturnStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedReturnStatementAst obfuscates a ReturnStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ReturnStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ReturnStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedReturnStatementAst -Ast $ReturnStatementAst

    .NOTES

    Out-ObfuscatedReturnStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ReturnStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedReturnStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedThrowStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a ThrowStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedThrowStatementAst obfuscates a ThrowStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ThrowStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ThrowStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedThrowStatementAst -Ast $ThrowStatementAst

    .NOTES

    Out-ObfuscatedThrowStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ThrowStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedThrowStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedTrapStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a TrapStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedTrapStatementAst obfuscates a TrapStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the TrapStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root TrapStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedTrapStatementAst -Ast $TrapStatementAst

    .NOTES

    Out-ObfuscatedTrapStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TrapStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTrapStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedTryStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a TryStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedTryStatementAst obfuscates a TryStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the TryStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root TryStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedTryStatementAst -Ast $TryStatementAst

    .NOTES

    Out-ObfuscatedTryStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TryStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTryStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedTypeDefinitionAst {
    <#

    .SYNOPSIS

    Obfuscates a TypeDefinitionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedTypeDefinitionAst obfuscates a TypeDefinitionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the TypeDefinitionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root TypeDefinitionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedTypeDefinitionAst -Ast $TypeDefinitionAst

    .NOTES

    Out-ObfuscatedTypeDefinitionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TypeDefinitionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTypeDefinitionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedUsingStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a UsingStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedUsingStatementAst obfuscates a UsingStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the UsingStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root UsingStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedUsingStatementAst -Ast $UsingStatementAst

    .NOTES

    Out-ObfuscatedUsingStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.UsingStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedUsingStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# CommandBaseAst Inherited Classes

function Out-ObfuscatedCommandAst {
    <#

    .SYNOPSIS

    Obfuscates a CommandAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Get-AstChildren, Out-ObfuscatedAst, Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedCommandAst obfuscates a CommandAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the CommandAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root CommandAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedCommandAst -Ast $CommandAst

    .NOTES

    Out-ObfuscatedCommandAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandAst]"
        If (-not $DisableNestedObfuscation) {
            $Children = Get-AstChildren -AbstractSyntaxTree $AbstractSyntaxTree
            If($Children.Count -ge 5) {
                $ReorderableIndices = @()
                $ObfuscatedReorderableExtents = @()
                $LastChild = $Children[1]
                For ([Int] $i = 2; $i -lt $Children.Count; $i++) {
                    $CurrentChild = $Children[$i]
                    If ($LastChild.GetType().Name -eq 'CommandParameterAst' -AND $CurrentChild.GetType().Name -ne 'CommandParameterAst') {
                        $FirstIndex = $LastChild.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset
                        $PairLength = $CurrentChild.Extent.StartOffset + $CurrentChild.Extent.Text.Length - $LastChild.Extent.StartOffset
                        $SecondIndex = $CurrentChild.Extent.StartOffset + $CurrentChild.Extent.Text.Length - $AbstractSyntaxTree.Extent.StartOffset
                        $PairExtent = $AbstractSyntaxTree.Extent.Text.Substring($FirstIndex, $PairLength)
                        $ObfuscatedLastChild = Out-ObfuscatedAst -AbstractSyntaxTree $LastChild
                        $ObfuscatedCurrentChild = Out-ObfuscatedAst -AbstractSyntaxTree $CurrentChild
                        $ObfuscatedPairExtent = $ObfuscatedLastChild + " " + $ObfuscatedCurrentChild
                        $ReorderableIndices += [Tuple]::Create($FirstIndex, $SecondIndex)
                        $ObfuscatedReorderableExtents += [String] $ObfuscatedPairExtent
                    }
                    ElseIf ($LastChild.GetType().Name -eq 'CommandParameterAst' -AND $CurrentChild.GetType().Name -eq 'CommandParameterAst') {
                        $ObfuscatedLastChild = Out-ObfuscatedAst -AbstractSyntaxTree $LastChild
                        $FirstIndex = $LastChild.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset
                        $SecondIndex = $LastChild.Extent.StartOffset + $LastChild.Extent.Text.Length - $AbstractSyntaxTree.Extent.StartOffset
                        $ReorderableIndices += [Tuple]::Create($FirstIndex, $SecondIndex)
                        $ObfuscatedReorderableExtents += [String] $ObfuscatedLastChild
                    }
                    ElseIf ($CurrentChild.GetType().Name -eq 'CommandParameterAst' -AND $i -eq ($Children.Count -1)) {
                        $ObfuscatedCurrentChild = Out-ObfuscatedAst -AbstractSyntaxTree $CurrentChild
                        $FirstIndex = $CurrentChild.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset
                        $SecondIndex = $CurrentChild.Extent.StartOffset + $CurrentChild.Extent.Text.Length - $AbstractSyntaxTree.Extent.StartOffset
                        $ReorderableIndices += [Tuple]::Create($FirstIndex, $SecondIndex)
                        $ObfuscatedReorderableExtents += [String] $ObfuscatedCurrentChild
                    }
                    $LastChild = $CurrentChild
                }
                If ($ObfuscatedReorderableExtents.Count -gt 1) {
                    $ObfuscatedReorderableExtents = $ObfuscatedReorderableExtents | Get-Random -Count $ObfuscatedReorderableExtents.Count
                    $ObfuscatedExtent = $AbstractSyntaxTree.Extent.Text
                    For ([Int] $i = 0; $i -lt $ObfuscatedReorderableExtents.Count; $i++) {
                        $LengthDifference = $ObfuscatedExtent.Length - $AbstractSyntaxTree.Extent.Text.Length
                        $ObfuscatedExtent = $ObfuscatedExtent.Substring(0, $ReorderableIndices[$i].Item1 + $LengthDifference)
                        $ObfuscatedExtent += [String] $ObfuscatedReorderableExtents[$i]
                        $ObfuscatedExtent += [String] $AbstractSyntaxTree.Extent.Text.Substring($ReorderableIndices[$i].Item2)
                    }
                    $ObfuscatedExtent
                } Else { Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree }
            }
            Else { Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree }
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedCommandExpressionAst {
    <#

    .SYNOPSIS

    Obfuscates a CommandExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedCommandExpressionAst obfuscates a CommandExpressionAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the CommandExpressionAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root CommandExpressionAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedCommandExpressionAst -Ast $CommandExpressionAst

    .NOTES

    Out-ObfuscatedCommandExpressionAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandExpressionAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# LabeledStatementAst Inherited Classes

function Out-ObfuscatedLoopStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a LoopStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedLoopStatementAst obfuscates a LoopStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the LoopStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root LoopStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedLoopStatementAst -Ast $LoopStatementAst

    .NOTES

    Out-ObfuscatedLoopStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.LoopStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )

    Process {
        Write-Verbose "[Out-ObfuscatedLoopStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedSwitchStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a SwitchStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedSwitchStatementAst obfuscates a SwitchStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the SwitchStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root SwitchStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedSwitchStatementAst -Ast $SwitchStatementAst

    .NOTES

    Out-ObfuscatedSwitchStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.SwitchStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedSwitchStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# LoopStatementAst Inherited Classes

function Out-ObfuscatedDoUntilStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a DoUntilStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedDoUntilStatementAst obfuscates a DoUntilStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the DoUntilStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root DoUntilStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedDoUntilStatementAst -Ast $DoUntilStatementAst

    .NOTES

    Out-ObfuscatedDoUntilStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.DoUntilStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedDoUntilStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedDoWhileStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a DoWhileStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedDoWhileStatementAst obfuscates a DoWhileStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the DoWhileStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root DoWhileStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedDoWhileStatementAst -Ast $DoWhileStatementAst

    .NOTES

    Out-ObfuscatedDoWhileStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.DoWhileStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedDoWhileStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedForEachStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a ForEachStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedForEachStatementAst obfuscates a ForEachStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ForEachStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ForEachStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedForEachStatementAst -Ast $ForEachStatementAst

    .NOTES

    Out-ObfuscatedForEachStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ForEachStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedForEachStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedForStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a ForStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedForStatementAst obfuscates a ForStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ForStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ForStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedForStatementAst -Ast $ForStatementAst

    .NOTES

    Out-ObfuscatedForStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ForStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedForStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedWhileStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a WhileStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedWhileStatementAst obfuscates a WhileStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the WhileStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root WhileStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedWhileStatementAst -Ast $WhileStatementAst

    .NOTES

    Out-ObfuscatedWhileStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.WhileStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedWhileStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

# PipelineBaseAst Inherited Classes

function Out-ObfuscatedAssignmentStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a AssignmentStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedAst, Out-ParenthesizedString, Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedAssignmentStatementAst obfuscates a AssignmentStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the AssignmentStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root AssignmentStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedAssignmentStatementAst -Ast $AssignmentStatementAst

    .NOTES

    Out-ObfuscatedAssignmentStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.AssignmentStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedAssignmentStatementAst]"
        $OperatorText = [System.Management.Automation.Language.TokenTraits]::Text($AbstractSyntaxTree.Operator)
        If ($AbstractSyntaxTree.Left.GetType().Name -eq "VariableExpressionAst" -AND $AbstractSyntaxTree.Left.VariablePath.IsVariable) {
            If ($OperatorText -eq "=") {
                $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right }
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString $RightExtent)
            }
            ElseIf ($OperatorText -eq "+=") {
                $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right }
                $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left }
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " + " + (Out-ParenthesizedString $RightExtent)))
            }
            ElseIf ($OperatorText -eq "-=") {
                $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right }
                $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left }
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " - " + (Out-ParenthesizedString $RightExtent)))
            }
            ElseIf ($OperatorText -eq "*=") {
                $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right }
                $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left }
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " * " + (Out-ParenthesizedString $RightExtent)))
            }
            ElseIf ($OperatorText -eq "/=") {
                $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right }
                $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left }
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " / " + (Out-ParenthesizedString $RightExtent)))
            }
            ElseIf ($OperatorText -eq "%=") {
                $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right }
                $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left }
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " % " + (Out-ParenthesizedString $RightExtent)))
            }
            ElseIf ($OperatorText -eq "++") {
                $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right }
                $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left }
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " + 1"))
            }
            ElseIf ($OperatorText -eq "--") {
                $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right }
                $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left }
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " - 1"))
            }
            ElseIf (-not $DisableNestedObfuscation) { Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        ElseIf ($AbstractSyntaxTree.Left.GetType().Name -eq "ConvertExpressionAst" -AND $AbstractSyntaxTree.Left.Child.GetType().Name -eq "VariableExpressionAst" -AND
                $AbstractSyntaxTree.Left.VariablePath.IsVariable -AND $AbstractSyntaxTree.Left.Attribute.GetType().Name -eq 'TypeConstraintName') {
            If ($OperatorText -eq "=") {
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Right.Extent.Text))
            }
            ElseIf ($OperatorText -eq "+=") {
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " + " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
            }
            ElseIf ($OperatorText -eq "-=") {
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " - " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
            }
            ElseIf ($OperatorText -eq "*=") {
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " * " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
            }
            ElseIf ($OperatorText -eq "/=") {
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " / " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
            }
            ElseIf ($OperatorText -eq "%=") {
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " % " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
            }
            ElseIf ($OperatorText -eq "++") {
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " + 1"))
            }
            ElseIf ($OperatorText -eq "--") {
                "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " - 1"))
            }
            ElseIf (-not $DisableNestedObfuscation) { Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedErrorStatementAst {
    <#

    .SYNOPSIS

    Obfuscates a ErrorStatementAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedErrorStatementAst obfuscates a ErrorStatementAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the ErrorStatementAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root ErrorStatementAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedErrorStatementAst -Ast $ErrorStatementAst

    .NOTES

    Out-ObfuscatedErrorStatementAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ErrorStatementAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedErrorStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}

function Out-ObfuscatedPipelineAst {
    <#

    .SYNOPSIS

    Obfuscates a PipelineAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedChildrenAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedPipelineAst obfuscates a PipelineAst using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the PipelineAst to be obfuscated.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root PipelineAst should be obfuscated, obfuscation should not be applied recursively.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedPipelineAst -Ast $PipelineAst

    .NOTES

    Out-ObfuscatedPipelineAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.PipelineAst] $AbstractSyntaxTree,

        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedPipelineAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}


# Utility functions

function Out-ObfuscatedAstsReordered {
    <#

    .SYNOPSIS

    Obfuscates and re-orders ChildrenAsts inside of a ParentAst PipelineAst using AbstractSyntaxTree-based obfuscation rules.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedAstsReordered obfuscates an Ast using AbstractSyntaxTree-based obfuscation rules, and re-orders the obfuscated
    ChildrenAsts of the ParentAst inside of the ParentAst.

    .PARAMETER ParentAst

    Specifies the ParentAst, of which it's children should be re-ordered.

    .PARAMETER ChildrenAsts

    Specifies the ChildrenAsts within the ParentAst that can be re-ordered.

    .PARAMETER DisableNestedObfuscation

    Specifies that only the root Ast should be obfuscated, obfuscation should not be applied recursively to the ChildrenAsts.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedAstsReordered -ParentAst $ParentAst -ChildrenAsts (Get-ChildrenAst -Ast $ParentAst)

    .NOTES

    Out-ObfuscatedAstsReordered is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast', 'AbstractSyntaxTree')]
        [System.Management.Automation.Language.Ast] $ParentAst,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.Ast[]] $ChildrenAsts,

        [Switch] $DisableNestedObfuscation
    )
    Write-Verbose "[Out-ObfuscatedAstsReordered]"
    If ($DisableNestedObfuscation) {
        $ChildrenObfuscatedExtents = ($ChildrenAsts | % { $_.Extent.Text }) -as [array]
    }
    Else {
        $ChildrenObfuscatedExtents = ($ChildrenAsts | Out-ObfuscatedAst) -as [array]
    }

    $ObfuscatedString = $ParentAst.Extent.Text
    $PrevChildrenLength = 0
    $PrevObfuscatedChildrenLength = 0
    If ($ChildrenObfuscatedExtents.Count -gt 1) {
        $ChildrenObfuscatedExtents = $ChildrenObfuscatedExtents | Get-Random -Count $ChildrenObfuscatedExtents.Count
        For ([Int] $i = 0; $i -lt $ChildrenAsts.Count; $i++) {
            $LengthDifference = $ObfuscatedString.Length - $ParentAst.Extent.Text.Length
            $BeginLength = ($ChildrenAsts[$i].Extent.StartOffset - $ParentAst.Extent.StartOffset) + $LengthDifference
            $EndStartIndex = ($ChildrenAsts[$i].Extent.StartOffset - $ParentAst.Extent.StartOffset) + $ChildrenAsts[$i].Extent.Text.Length
            
            $ObfuscatedString = [String] $ObfuscatedString.SubString(0, $BeginLength)
            $ObfuscatedString += [String] $ChildrenObfuscatedExtents[$i]
            $ObfuscatedString += [String] $ParentAst.Extent.Text.Substring($EndStartIndex)
        }
    }

    $ObfuscatedString
}

function Out-ParenthesizedString {
    <#

    .SYNOPSIS

    Outputs a string that is guaranteed to be surrounded in a single set of parentheses.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: none

    .DESCRIPTION

    Out-ParenthesizedString outputs a string that is guaranteed to be surrounded in a single set of parentheses, which is
    often needed when re-ordering Asts within a script.

    .PARAMETER ScriptString

    Specifies the string that should be parenthesized.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ParenthesizedString -ScriptString $ScriptString

    .NOTES

    Out-ParenthesizedString is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param(
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [String] $ScriptString
    )
    Process {
        Write-Verbose "[Out-ParenthesizedString]"
        $TrimmedString = $ScriptString.Trim()
        If ($TrimmedString.StartsWith("(") -and $TrimmedString.EndsWith(")")) {
            $StackDepth = 1
            $SurroundingMatch = $True
            For([Int]$i = 1; $i -lt $TrimmedString.Length - 1; $i++) {
                $Char = $TrimmedString[$i]
                If ($Char -eq ")") {
                    If ($StackDepth -eq 1) { $SurroundingMatch = $False; break; }
                    Else { $StackDepth -= 1 }
                }
                ElseIf ($Char -eq "(") { $StackDepth += 1 }
            }
            If ($SurroundingMatch) { $ScriptString }
            Else { "(" + $ScriptString + ")" }
        } Else {
            "(" + $ScriptString + ")"
        }
    }
}

function Test-ExpressionAstIsNumeric {
    <#

    .SYNOPSIS

    Recursively tests if an ExpressionAst is a numeric expression, and can be re-ordered.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: none

    .DESCRIPTION

    Test-ExpressionAstIsNumeric recursively tests if an ExpressionAst is a numeric expression, and can be re-ordered.

    .PARAMETER AbstractSyntaxTree

    Specifies the ExpressionAst that should be tested to see if it is a numeric expression.

    .OUTPUTS

    String

    .EXAMPLE

    Test-ExpressionAstIsNumeric -Ast (Get-Ast "1 + 2 + (3 - 4 * (5 / 6))")

    .NOTES

    Test-ExpressionAstIsNumeric is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ExpressionAst] $AbstractSyntaxTree
    )
    Process {
        If ($AbstractSyntaxTree.StaticType.Name -in @('Int32', 'Int64', 'UInt32', 'UInt64', 'Decimal', 'Single', 'Double')) {
            $True
        }
        ElseIf ($AbstractSyntaxTree.Extent.Text -match "^[\d\.]+$") {
            $True
        }
        ElseIf ($AbstractSyntaxTree.Extent.Text -match "^[\d\.]+$") {
            $True
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'BinaryExpressionAst') {
            ((Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Left) -AND (Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Right))
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'UnaryExpressionAst' -AND [System.Management.Automation.Language.TokenTraits]::Text($AbstractSyntaxTree.TokenKind) -in @("+", "-", "*", "/", "++", "--")) {
            (Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Child)
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ParenExpressionAst' -AND $AbstractSyntaxTree.Pipeline.GetType().Name -eq 'PipelineAst') {
            $PipelineElements = ($AbstractSyntaxTree.Pipeline.PipelineElements) -as [array]
            If ($PipelineElements.Count -eq 1) {
                (Test-ExpressionAstIsNumeric -Ast $PipelineElements[0].Expression)
            } Else { $False }
        }
        Else {
            $False
        }
    }
}

function Get-AstChildren {
    <#

    .SYNOPSIS

    Gets the children Asts of a given AbstractSyntaxTree.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: none
    Optional Dependencies: none

    .DESCRIPTION

    Get-AstChildren gets the children Asts of a given AbstractSyntaxTree by searching the parent Ast's property
    values for Ast types.

    .PARAMETER AbstractSyntaxTree

    Specifies the parent Ast to get the children Asts from.

    .OUTPUTS

    [System.Management.Automation.Ast[]]

    .EXAMPLE

    Get-AstChildren -Ast $Ast

    .NOTES

    Get-AstChildren is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree
    )
    Process {
        Write-Verbose "[Get-AstChildren]"
        ForEach ($Property in $AbstractSyntaxTree.PSObject.Properties) {
            If ($Property.Name -eq 'Parent') { continue }

            $PropertyValue = $Property.Value
            If ($PropertyValue -ne $null -AND $PropertyValue -is [System.Management.Automation.Language.Ast]) {
                $PropertyValue
            }
            Else {
                $Collection = $PropertyValue -as [System.Management.Automation.Language.Ast[]]
                If ($Collection -ne $null) {
                    $Collection
                }
            }
        }
    }
}

function Out-ObfuscatedChildrenAst {
    <#

    .SYNOPSIS

    Recursively obfuscates the ChildrenAsts of an Ast.

    Author: Ryan Cobb (@cobbr_io)
    License: GNU GPLv3
    Required Dependecies: Out-ObfuscatedAst
    Optional Dependencies: none

    .DESCRIPTION

    Out-ObfuscatedChildrenAst recursively obfuscates the ChildrenAsts of an Ast using AbstractSyntaxTree-based obfuscation rules.

    .PARAMETER AbstractSyntaxTree

    Specifies the parent Ast, whose children will be recursively obfuscated.

    .PARAMETER ChildrenAsts

    Optionally specifies the ChildrenAsts within the ParentAst that should be recursively obfuscated.

    .OUTPUTS

    String

    .EXAMPLE

    Out-ObfuscatedChildrenAst -Ast $Ast -ChildrenAsts (Get-ChildrenAst -Ast $ParentAst)

    .NOTES

    Out-ObfuscatedChildrenAst is a part of PSAmsi, a tool for auditing and defeating AMSI signatures.

    PSAmsi is located at https://github.com/cobbr/PSAmsi. Additional information can be found at https://cobbr.io.

    #>
    Param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree,

        [Parameter(Position = 1)]
        [System.Management.Automation.Language.Ast[]] $ChildrenAsts = @()
    )
    Process {
        Write-Verbose "[Out-ObfuscatedChildrenAst]"
        If ($ChildrenAsts.Count -eq 0) {
            $ChildrenAsts = (Get-AstChildren -AbstractSyntaxTree $AbstractSyntaxTree | ? { $_.Extent.StartScriptPosition.GetType().Name -ne 'EmptyScriptPosition' } | Sort-Object { $_.Extent.StartOffset }) -as [array]
        }
        If ($ChildrenAsts.Count -gt 0) {
            $ChildrenObfuscatedExtents = ($ChildrenAsts | Out-ObfuscatedAst ) -as [array]
        }

        $ObfuscatedExtent = $AbstractSyntaxTree.Extent.Text
        If ($ChildrenObfuscatedExtents.Count -gt 0 -AND $ChildrenAsts.Count -gt 0 -AND $ChildrenObfuscatedExtents.Count -eq $ChildrenAsts.Count) {
            For ([Int] $i = 0; $i -lt $ChildrenAsts.Length; $i++) {
                $LengthDifference = $ObfuscatedExtent.Length - $AbstractSyntaxTree.Extent.Text.Length
                $EndStartIndex = ($ChildrenAsts[$i].Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset) + $ChildrenAsts[$i].Extent.Text.Length
                $StartLength = ($ChildrenAsts[$i].Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset) + $LengthDifference
                $ObfuscatedExtent = [String] $ObfuscatedExtent.Substring(0, $StartLength)
                If (-not $ChildrenObfuscatedExtents[$i]) {
                    $ObfuscatedExtent += [String] $ChildrenAsts[$i].Extent.Text
                }
                Else {
                    $ObfuscatedExtent += [String] $ChildrenObfuscatedExtents[$i]
                }
                $ObfuscatedExtent += [String] $AbstractSyntaxTree.Extent.Text.Substring($EndStartIndex)
            }
        }
        $ObfuscatedExtent
    }
}