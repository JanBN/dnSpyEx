﻿' Licensed to the .NET Foundation under one or more agreements.
' The .NET Foundation licenses this file to you under the MIT license.
' See the LICENSE file in the project root for more information.

Imports System.Collections.ObjectModel
Imports Microsoft.CodeAnalysis.ExpressionEvaluator
Imports Microsoft.CodeAnalysis.VisualBasic.Symbols
Imports Microsoft.VisualStudio.Debugger.Evaluation.ClrCompilation

Namespace Microsoft.CodeAnalysis.VisualBasic.ExpressionEvaluator

    Friend NotInheritable Class VisualBasicLocalAndMethod : Inherits LocalAndMethod

        Private ReadOnly _method As MethodSymbol

        Public Sub New(localName As String, localDisplayName As String, method As MethodSymbol, flags As DkmClrCompilationResultFlags, kind As LocalAndMethodKind, index As Integer)
            MyBase.New(localName, localDisplayName, method.Name, flags, kind, index)
            _method = method
        End Sub

        Public Overrides Function GetCustomTypeInfo(ByRef payload As ReadOnlyCollection(Of Byte)) As Guid
            payload = _method.GetCustomTypeInfoPayload()
            Return If(payload Is Nothing, Nothing, CustomTypeInfo.PayloadTypeId)
        End Function
    End Class

End Namespace
