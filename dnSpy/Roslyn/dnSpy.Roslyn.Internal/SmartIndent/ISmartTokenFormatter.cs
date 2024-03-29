﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace dnSpy.Roslyn.Internal.SmartIndent {
	interface ISmartTokenFormatter {
		Task<IList<TextChange>> FormatTokenAsync(Workspace workspace, SyntaxToken token, CancellationToken cancellationToken);
	}
}
