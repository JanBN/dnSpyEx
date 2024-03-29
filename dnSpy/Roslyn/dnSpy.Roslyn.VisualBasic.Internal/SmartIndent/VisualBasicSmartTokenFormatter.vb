﻿' Licensed to the .NET Foundation under one or more agreements.
' The .NET Foundation licenses this file to you under the MIT license.
' See the LICENSE file in the project root for more information.

Imports System.Threading
Imports dnSpy.Roslyn.Internal.SmartIndent
Imports Microsoft.CodeAnalysis
Imports Microsoft.CodeAnalysis.Formatting
Imports Microsoft.CodeAnalysis.Formatting.Rules
Imports Microsoft.CodeAnalysis.Options
Imports Microsoft.CodeAnalysis.Text
Imports Microsoft.CodeAnalysis.VisualBasic
Imports Microsoft.CodeAnalysis.VisualBasic.Syntax
Imports Roslyn.Utilities

Namespace Global.dnSpy.Roslyn.VisualBasic.Internal.SmartIndent
	Friend Class VisualBasicSmartTokenFormatter
		Implements ISmartTokenFormatter

		Private ReadOnly _optionSet As OptionSet
		Private ReadOnly _formattingRules As IEnumerable(Of AbstractFormattingRule)

		Private ReadOnly _root As CompilationUnitSyntax

		Public Sub New(optionSet As OptionSet,
		               formattingRules As IEnumerable(Of AbstractFormattingRule),
		               root As CompilationUnitSyntax)
			Contract.ThrowIfNull(optionSet)
			Contract.ThrowIfNull(formattingRules)
			Contract.ThrowIfNull(root)

			_optionSet = optionSet
			_formattingRules = formattingRules

			_root = root
		End Sub

		Public Function FormatTokenAsync(workspace As Workspace, token As SyntaxToken, cancellationToken As CancellationToken) As Task(Of IList(Of TextChange)) Implements ISmartTokenFormatter.FormatTokenAsync
			Contract.ThrowIfTrue(token.IsKind(SyntaxKind.None) OrElse token.IsKind(SyntaxKind.EndOfFileToken))

			' get previous token
			Dim previousToken = token.GetPreviousToken()

			Dim spans = New TextSpan() {TextSpan.FromBounds(previousToken.SpanStart, token.Span.End)}
			Return _
				Task.FromResult(Formatter.GetFormattedTextChanges(_root, spans, workspace, _optionSet, _formattingRules, cancellationToken))
		End Function
	End Class
End Namespace
