﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.VisualStudio.Debugger.Evaluation.ClrCompilation;
using System;
using System.Collections.ObjectModel;

namespace Microsoft.CodeAnalysis.ExpressionEvaluator
{
    /// <summary>
    /// The name of a local or argument and the name of
    /// the corresponding method to access that object.
    /// </summary>
    internal abstract class LocalAndMethod
    {
        public readonly string LocalName;
        public readonly string LocalDisplayName;
        public readonly string MethodName;
        public readonly DkmClrCompilationResultFlags Flags;
        public readonly LocalAndMethodKind Kind;
        public readonly int Index;

        public LocalAndMethod(string localName, string localDisplayName, string methodName, DkmClrCompilationResultFlags flags, LocalAndMethodKind kind, int index)
        {
            this.LocalName = localName;
            this.LocalDisplayName = localDisplayName;
            this.MethodName = methodName;
            this.Flags = flags;
            this.Kind = kind;
            this.Index = index;
        }

        public abstract Guid GetCustomTypeInfo(out ReadOnlyCollection<byte>? payload);
    }

    internal enum LocalAndMethodKind
    {
        Local,
        Parameter,
        This,
        TypeVariables,
        LocalConstant,
        StaticLocal,
        Exception,
        StowedException,
        ReturnValue,
        ObjectId,
        ObjectAddress,
        // Variable defined by the user using the EE. Enter 'expression' "int i = 123;" in the immediate window
        EEVariable,
    }
}
