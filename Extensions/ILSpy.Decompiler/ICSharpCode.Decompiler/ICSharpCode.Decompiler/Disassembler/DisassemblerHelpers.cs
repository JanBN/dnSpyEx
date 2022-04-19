// Copyright (c) 2011 AlphaSierraPapa for the SharpDevelop Team
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this
// software and associated documentation files (the "Software"), to deal in the Software
// without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
// to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
// FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Pdb;
using dnSpy.Contracts.Decompiler;
using dnSpy.Contracts.Text;
using ICSharpCode.NRefactory;

namespace ICSharpCode.Decompiler.Disassembler {
	public enum ILNameSyntax
	{
		/// <summary>
		/// class/valuetype + TypeName (built-in types use keyword syntax)
		/// </summary>
		Signature,
		/// <summary>
		/// Like signature, but always refers to type parameters using their position
		/// </summary>
		SignatureNoNamedTypeParameters,
		/// <summary>
		/// [assembly]Full.Type.Name (even for built-in types)
		/// </summary>
		TypeName,
		/// <summary>
		/// Name (but built-in types use keyword syntax)
		/// </summary>
		ShortTypeName
	}

	public static class DisassemblerHelpers
	{
		static readonly char[] _validNonLetterIdentifierCharacter = new char[] { '_', '$', '@', '?', '`', '.' };

		const int OPERAND_ALIGNMENT = 10;

		static DisassemblerHelpers()
		{
			spaces = new string[OPERAND_ALIGNMENT];
			for (int i = 0; i < spaces.Length; i++)
				spaces[i] = new string(' ', i);
		}
		static readonly string[] spaces;

		public static void WriteOffsetReference(IDecompilerOutput writer, Instruction instruction, MethodDef method, object data = null)
		{
			if (data == null)
				data = BoxedTextColor.Label;
			var r = instruction == null ? null : method == null ? (object)instruction : new InstructionReference(method, instruction);
			writer.Write(DnlibExtensions.OffsetToString(instruction.GetOffset()), r, DecompilerReferenceFlags.None, data);
		}

		public static void WriteTo(this ExceptionHandler exceptionHandler, IDecompilerOutput writer, MethodDef method)
		{
			writer.Write(".try", BoxedTextColor.Keyword);
			writer.Write(" ", BoxedTextColor.Text);
			WriteOffsetReference(writer, exceptionHandler.TryStart, method);
			writer.Write("-", BoxedTextColor.Operator);
			WriteOffsetReference(writer, exceptionHandler.TryEnd, method);
			writer.Write(" ", BoxedTextColor.Text);
			writer.Write(exceptionHandler.HandlerType.ToString(), BoxedTextColor.Keyword);
			if (exceptionHandler.FilterStart != null) {
				writer.Write(" ", BoxedTextColor.Text);
				WriteOffsetReference(writer, exceptionHandler.FilterStart, method);
				writer.Write(" ", BoxedTextColor.Text);
				writer.Write("handler", BoxedTextColor.Keyword);
				writer.Write(" ", BoxedTextColor.Text);
			}
			if (exceptionHandler.CatchType != null) {
				writer.Write(" ", BoxedTextColor.Text);
				exceptionHandler.CatchType.WriteTo(writer);
			}
			writer.Write(" ", BoxedTextColor.Text);
			WriteOffsetReference(writer, exceptionHandler.HandlerStart, method);
			writer.Write("-", BoxedTextColor.Operator);
			WriteOffsetReference(writer, exceptionHandler.HandlerEnd, method);
		}

		internal static void WriteTo(this Instruction instruction, IDecompilerOutput writer, DisassemblerOptions options, uint baseRva, long baseOffs, IInstructionBytesReader byteReader, MethodDef method, InstructionOperandConverter instructionOperandConverter, PdbAsyncMethodCustomDebugInfo pdbAsyncInfo, out int startLocation)
		{
			var numberFormatter = NumberFormatter.GetCSharpInstance(hex: options.HexadecimalNumbers, upper: true);
			if (options.ShowPdbInfo) {
				var seqPoint = instruction.SequencePoint;
				if (seqPoint != null) {
					writer.Write("/* (", BoxedTextColor.Comment);
					const int HIDDEN = 0xFEEFEE;
					if (seqPoint.StartLine == HIDDEN)
						writer.Write("hidden", BoxedTextColor.Comment);
					else {
						writer.Write(seqPoint.StartLine.ToString(), BoxedTextColor.Comment);
						writer.Write(",", BoxedTextColor.Comment);
						writer.Write(seqPoint.StartColumn.ToString(), BoxedTextColor.Comment);
					}
					writer.Write(")-(", BoxedTextColor.Comment);
					if (seqPoint.EndLine == HIDDEN)
						writer.Write("hidden", BoxedTextColor.Comment);
					else {
						writer.Write(seqPoint.EndLine.ToString(), BoxedTextColor.Comment);
						writer.Write(",", BoxedTextColor.Comment);
						writer.Write(seqPoint.EndColumn.ToString(), BoxedTextColor.Comment);
					}
					writer.Write(") ", BoxedTextColor.Comment);
					writer.Write(seqPoint.Document.Url, BoxedTextColor.Comment);
					writer.Write(" */", BoxedTextColor.Comment);
					writer.WriteLine();
				}
				if (pdbAsyncInfo != null) {
					if (pdbAsyncInfo.CatchHandlerInstruction == instruction)
						writer.WriteLine("/* Catch Handler */", BoxedTextColor.Comment);
					var asyncStepInfos = pdbAsyncInfo.StepInfos;
					for (int i = 0; i < asyncStepInfos.Count; i++) {
						var info = asyncStepInfos[i];
						if (info.YieldInstruction == instruction)
							writer.WriteLine("/* Yield Instruction */", BoxedTextColor.Comment);
						if (info.BreakpointInstruction == instruction)
							writer.WriteLine("/* Resume Instruction */", BoxedTextColor.Comment);
					}
				}
			}
			if (options != null && (options.ShowTokenAndRvaComments || options.ShowILBytes)) {
				writer.Write("/* ", BoxedTextColor.Comment);

				bool needSpace = false;

				if (options.ShowTokenAndRvaComments) {
					ulong fileOffset = (ulong)baseOffs + instruction.Offset;
					var hexOffsetString = string.Format("0x{0:X8}", fileOffset);
					bool orig = byteReader?.IsOriginalBytes == true;
					if (orig)
						writer.Write(hexOffsetString, new AddressReference(options.OwnerModule == null ? null : options.OwnerModule.Location, false, fileOffset, (ulong)instruction.GetSize()), DecompilerReferenceFlags.None, BoxedTextColor.Comment);
					else
						writer.Write(hexOffsetString, BoxedTextColor.Comment);
					needSpace = true;
				}

				if (options.ShowILBytes) {
					if (needSpace)
						writer.Write(" ", BoxedTextColor.Comment);
					if (byteReader == null)
						writer.Write("??", BoxedTextColor.Comment);
					else {
						int size = instruction.GetSize();
						for (int i = 0; i < size; i++) {
							var b = byteReader.ReadByte();
							if (b < 0)
								writer.Write("??", BoxedTextColor.Comment);
							else
								writer.Write(string.Format("{0:X2}", b), BoxedTextColor.Comment);
						}
						// Most instructions should be at most 5 bytes in length, but use 6 since
						// ldftn/ldvirtftn are 6 bytes long. The longest instructions are those with
						// 8 byte operands, ldc.i8 and ldc.r8: 9 bytes.
						const int MIN_BYTES = 6;
						for (int i = size; i < MIN_BYTES; i++)
							writer.Write("  ", BoxedTextColor.Comment);
					}
				}

				writer.Write(" */", BoxedTextColor.Comment);
				writer.Write(" ", BoxedTextColor.Text);
			}
			startLocation = writer.NextPosition;
			writer.Write(DnlibExtensions.OffsetToString(instruction.GetOffset()), new InstructionReference(method, instruction), DecompilerReferenceFlags.Definition, BoxedTextColor.Label);
			writer.Write(":", BoxedTextColor.Punctuation);
			writer.Write(" ", BoxedTextColor.Text);
			writer.Write(instruction.OpCode.Name, instruction.OpCode, DecompilerReferenceFlags.None, BoxedTextColor.OpCode);
			if (ShouldHaveOperand(instruction)) {
				int count = OPERAND_ALIGNMENT - instruction.OpCode.Name.Length;
				if (count <= 0)
					count = 1;
				writer.Write(spaces[count], BoxedTextColor.Text);
				if (instruction.OpCode == OpCodes.Ldtoken) {
					var member = instruction.Operand as IMemberRef;
					if (member != null && member.IsMethod) {
						writer.Write("method", BoxedTextColor.Keyword);
						writer.Write(" ", BoxedTextColor.Text);
					}
					else if (member != null && member.IsField) {
						writer.Write("field", BoxedTextColor.Keyword);
						writer.Write(" ", BoxedTextColor.Text);
					}
				}
				WriteOperand(writer, instructionOperandConverter?.Convert(instruction.Operand) ?? instruction.Operand, options.MaxStringLength, numberFormatter, method);
			}
			if (options != null && options.GetOpCodeDocumentation != null) {
				var doc = options.GetOpCodeDocumentation(instruction.OpCode);
				if (doc != null) {
					writer.Write("\t", BoxedTextColor.Text);
					writer.Write("// " + doc, BoxedTextColor.Comment);
				}
			}
		}

		static bool ShouldHaveOperand(Instruction instr)
		{
			switch (instr.OpCode.OperandType) {
			case OperandType.InlineBrTarget:
			case OperandType.InlineField:
			case OperandType.InlineI:
			case OperandType.InlineI8:
			case OperandType.InlineMethod:
			case OperandType.InlineR:
			case OperandType.InlineSig:
			case OperandType.InlineString:
			case OperandType.InlineSwitch:
			case OperandType.InlineTok:
			case OperandType.InlineType:
			case OperandType.InlineVar:
			case OperandType.ShortInlineBrTarget:
			case OperandType.ShortInlineI:
			case OperandType.ShortInlineR:
			case OperandType.ShortInlineVar:
				return true;
			case OperandType.InlineNone:
			case OperandType.InlinePhi:
			default:
				return false;
			}
		}

		static void WriteLabelList(IDecompilerOutput writer, IList<Instruction> instructions, MethodDef method)
		{
			var bh1 = BracePairHelper.Create(writer, "(", CodeBracesRangeFlags.Parentheses);
			for(int i = 0; i < instructions.Count; i++) {
				if (i != 0) {
					writer.Write(",", BoxedTextColor.Punctuation);
					writer.Write(" ", BoxedTextColor.Text);
				}
				WriteOffsetReference(writer, instructions[i], method);
			}
			bh1.Write(")");
		}

		static string ToInvariantCultureString(object value)
		{
			if (value == null)
				return "<<<NULL>>>";
			IConvertible convertible = value as IConvertible;
			return(null != convertible)
				? convertible.ToString(System.Globalization.CultureInfo.InvariantCulture)
				: value.ToString();
		}

		public static void WriteMethodTo(this IMethod method, IDecompilerOutput writer)
		{
			writer.Write((MethodSig)null, method);
		}

		public static void Write(this IDecompilerOutput writer, MethodSig sig, IMethod method = null)
		{
			if (sig == null && method != null)
				sig = method.MethodSig;
			if (sig == null)
				return;
			if (sig.ExplicitThis) {
				writer.Write("instance", BoxedTextColor.Keyword);
				writer.Write(" ", BoxedTextColor.Text);
				writer.Write("explicit", BoxedTextColor.Keyword);
				writer.Write(" ", BoxedTextColor.Text);
			}
			else if (sig.HasThis) {
				writer.Write("instance", BoxedTextColor.Keyword);
				writer.Write(" ", BoxedTextColor.Text);
			}
			if (sig.CallingConvention == CallingConvention.VarArg) {
				writer.Write("vararg", BoxedTextColor.Keyword);
				writer.Write(" ", BoxedTextColor.Text);
			}
			sig.RetType.WriteTo(writer, ILNameSyntax.SignatureNoNamedTypeParameters);
			writer.Write(" ", BoxedTextColor.Text);
			if (method != null) {
				if (method.DeclaringType != null) {
					method.DeclaringType.WriteTo(writer, ILNameSyntax.TypeName);
					writer.Write("::", BoxedTextColor.Operator);
				}
				MethodDef md = method as MethodDef;
				if (md != null && md.IsCompilerControlled) {
					writer.Write(Escape(method.Name + "$PST" + method.MDToken.ToInt32().ToString("X8")), method, DecompilerReferenceFlags.None, CSharpMetadataTextColorProvider.Instance.GetColor(method));
				}
				else {
					writer.Write(Escape(method.Name), method, DecompilerReferenceFlags.None, CSharpMetadataTextColorProvider.Instance.GetColor(method));
				}
			}
			MethodSpec gim = method as MethodSpec;
			if (gim != null && gim.GenericInstMethodSig != null) {
				var bh1 = BracePairHelper.Create(writer, "<", CodeBracesRangeFlags.AngleBrackets);
				for (int i = 0; i < gim.GenericInstMethodSig.GenericArguments.Count; i++) {
					if (i > 0) {
						writer.Write(",", BoxedTextColor.Punctuation);
						writer.Write(" ", BoxedTextColor.Text);
					}
					gim.GenericInstMethodSig.GenericArguments[i].WriteTo(writer);
				}
				bh1.Write(">");
			}
			var bh2 = BracePairHelper.Create(writer, "(", CodeBracesRangeFlags.Parentheses);
			var parameters = sig.GetParameters();
			for(int i = 0; i < parameters.Count; ++i) {
				if (i > 0) {
					writer.Write(",", BoxedTextColor.Punctuation);
					writer.Write(" ", BoxedTextColor.Text);
				}
				parameters[i].WriteTo(writer, ILNameSyntax.SignatureNoNamedTypeParameters);
			}
			bh2.Write(")");
		}

		public static void WriteTo(this MethodSig sig, IDecompilerOutput writer)
		{
			if (sig.ExplicitThis) {
				writer.Write("instance", BoxedTextColor.Keyword);
				writer.Write(" ", BoxedTextColor.Text);
				writer.Write("explicit", BoxedTextColor.Keyword);
				writer.Write(" ", BoxedTextColor.Text);
			}
			else if (sig.HasThis) {
				writer.Write("instance", BoxedTextColor.Keyword);
				writer.Write(" ", BoxedTextColor.Text);
			}
			sig.RetType.WriteTo(writer, ILNameSyntax.SignatureNoNamedTypeParameters);
			writer.Write(" ", BoxedTextColor.Text);
			var bh1 = BracePairHelper.Create(writer, "(", CodeBracesRangeFlags.Parentheses);
			var parameters = sig.GetParameters();
			for(int i = 0; i < parameters.Count; ++i) {
				if (i > 0) {
					writer.Write(",", BoxedTextColor.Punctuation);
					writer.Write(" ", BoxedTextColor.Text);
				}
				parameters[i].WriteTo(writer, ILNameSyntax.SignatureNoNamedTypeParameters);
			}
			bh1.Write(")");
		}

		public static void WriteFieldTo(this IField field, IDecompilerOutput writer)
		{
			if (field == null || field.FieldSig == null)
				return;
			field.FieldSig.Type.WriteTo(writer, ILNameSyntax.SignatureNoNamedTypeParameters);
			writer.Write(" ", BoxedTextColor.Text);
			field.DeclaringType.WriteTo(writer, ILNameSyntax.TypeName);
			writer.Write("::", BoxedTextColor.Operator);
			writer.Write(Escape(field.Name), field, DecompilerReferenceFlags.None, CSharpMetadataTextColorProvider.Instance.GetColor(field));
		}

		static bool IsValidIdentifierCharacter(char c)
			=> char.IsLetterOrDigit(c) || _validNonLetterIdentifierCharacter.IndexOf(c) >= 0;

		static bool IsValidIdentifier(string identifier)
		{
			if (string.IsNullOrEmpty(identifier))
				return false;

			if (char.IsDigit(identifier[0]))
				return false;

			// As a special case, .ctor and .cctor are valid despite starting with a dot
			if (identifier[0] == '.')
				return identifier == ".ctor" || identifier == ".cctor";

			if (identifier.Contains(".."))
				return false;

			if (ilKeywords.Contains(identifier))
				return false;

			return identifier.All(IsValidIdentifierCharacter);
		}

		static readonly HashSet<string> ilKeywords = BuildKeywordList(
			"abstract", "algorithm", "alignment", "ansi", "any", "arglist",
			"array", "as", "assembly", "assert", "at", "auto", "autochar", "beforefieldinit",
			"blob", "blob_object", "bool", "brnull", "brnull.s", "brzero", "brzero.s", "bstr",
			"bytearray", "byvalstr", "callmostderived", "carray", "catch", "cdecl", "cf",
			"char", "cil", "class", "clsid", "const", "currency", "custom", "date", "decimal",
			"default", "demand", "deny", "endmac", "enum", "error", "explicit", "extends", "extern",
			"false", "famandassem", "family", "famorassem", "fastcall", "fault", "field", "filetime",
			"filter", "final", "finally", "fixed", "float", "float32", "float64", "forwardref",
			"fromunmanaged", "handler", "hidebysig", "hresult", "idispatch", "il", "illegal",
			"implements", "implicitcom", "implicitres", "import", "in", "inheritcheck", "init",
			"initonly", "instance", "int", "int16", "int32", "int64", "int8", "interface", "internalcall",
			"iunknown", "lasterr", "lcid", "linkcheck", "literal", "localloc", "lpstr", "lpstruct", "lptstr",
			"lpvoid", "lpwstr", "managed", "marshal", "method", "modopt", "modreq", "native", "nested",
			"newslot", "noappdomain", "noinlining", "nomachine", "nomangle", "nometadata", "noncasdemand",
			"noncasinheritance", "noncaslinkdemand", "noprocess", "not", "not_in_gc_heap", "notremotable",
			"notserialized", "null", "nullref", "object", "objectref", "opt", "optil", "out",
			"permitonly", "pinned", "pinvokeimpl", "prefix1", "prefix2", "prefix3", "prefix4", "prefix5", "prefix6",
			"prefix7", "prefixref", "prejitdeny", "prejitgrant", "preservesig", "private", "privatescope", "protected",
			"public", "record", "refany", "reqmin", "reqopt", "reqrefuse", "reqsecobj", "request", "retval",
			"rtspecialname", "runtime", "safearray", "sealed", "sequential", "serializable", "special", "specialname",
			"static", "stdcall", "storage", "stored_object", "stream", "streamed_object", "string", "struct",
			"synchronized", "syschar", "sysstring", "tbstr", "thiscall", "tls", "to", "true", "typedref",
			"unicode", "unmanaged", "unmanagedexp", "unsigned", "unused", "userdefined", "value", "valuetype",
			"vararg", "variant", "vector", "virtual", "void", "wchar", "winapi", "with", "wrapper",

			// These are not listed as keywords in spec, but ILAsm treats them as such
			"property", "type", "flags", "codelabel", "callconv", "strict",
			// ILDasm uses these keywords for unsigned integers
			"uint8", "uint16", "uint32", "uint64"
		);

		static HashSet<string> BuildKeywordList(params string[] keywords)
		{
			HashSet<string> s = new HashSet<string>(keywords);
			foreach (var field in typeof(OpCodes).GetFields()) {
				if (field.FieldType != typeof(OpCode))
					continue;
				OpCode opCode = (OpCode)field.GetValue(null);
				if (opCode.OpCodeType != OpCodeType.Nternal)
					s.Add(opCode.Name);
			}
			return s;
		}

		internal static bool MustEscape(string identifier) {
			return !IsValidIdentifier(identifier);
		}

		public static string Escape(string identifier) {
			if (MustEscape(identifier)) {
				// The ECMA specification says that ' inside SQString should be ecaped using an octal escape sequence,
				// but we follow Microsoft's ILDasm and use \'.
				return "'" + IdentifierEscaper.Truncate(NRefactory.CSharp.TextWriterTokenWriter.ConvertString(identifier)
																  .Replace("'", "\\'")) + "'";
			}
			else {
				return IdentifierEscaper.Truncate(identifier);
			}
		}

		public static void WriteTo(this TypeSig type, IDecompilerOutput writer, ILNameSyntax syntax = ILNameSyntax.Signature)
		{
			type.WriteTo(writer, syntax, 0);
		}

		const int MAX_CONVERTTYPE_DEPTH = 50;
		public static void WriteTo(this TypeSig type, IDecompilerOutput writer, ILNameSyntax syntax, int depth)
		{
			if (depth++ > MAX_CONVERTTYPE_DEPTH)
				return;
			ILNameSyntax syntaxForElementTypes = syntax == ILNameSyntax.SignatureNoNamedTypeParameters ? syntax : ILNameSyntax.Signature;
			if (type is PinnedSig) {
				((PinnedSig)type).Next.WriteTo(writer, syntaxForElementTypes, depth);
				writer.Write(" ", BoxedTextColor.Text);
				writer.Write("pinned", BoxedTextColor.Keyword);
			} else if (type is ArraySig) {
				ArraySig at = (ArraySig)type;
				at.Next.WriteTo(writer, syntaxForElementTypes, depth);
				var bh1 = BracePairHelper.Create(writer, "[", CodeBracesRangeFlags.SquareBrackets);
				for (int i = 0; i < at.Rank; i++)
				{
					if (i != 0) {
						writer.Write(",", BoxedTextColor.Punctuation);
						writer.Write(" ", BoxedTextColor.Text);
					}
					int? lower = i < at.LowerBounds.Count ? at.LowerBounds[i] : (int?)null;
					uint? size = i < at.Sizes.Count ? at.Sizes[i] : (uint?)null;
					if (lower != null)
					{
						writer.Write(lower.ToString(), BoxedTextColor.Number);
						if (size != null) {
							writer.Write("..", BoxedTextColor.Operator);
							writer.Write((lower.Value + (int)size.Value - 1).ToString(), BoxedTextColor.Number);
						}
						else
							writer.Write("...", BoxedTextColor.Operator);
					}
				}
				bh1.Write("]");
			} else if (type is SZArraySig) {
				SZArraySig at = (SZArraySig)type;
				at.Next.WriteTo(writer, syntaxForElementTypes, depth);
				var bh1 = BracePairHelper.Create(writer, "[", CodeBracesRangeFlags.SquareBrackets);
				bh1.Write("]");
			} else if (type is GenericSig) {
				if (((GenericSig)type).IsMethodVar)
					writer.Write("!!", BoxedTextColor.Operator);
				else
					writer.Write("!", BoxedTextColor.Operator);
				string typeName = type.TypeName;
				if (string.IsNullOrEmpty(typeName) || typeName[0] == '!' || syntax == ILNameSyntax.SignatureNoNamedTypeParameters)
					writer.Write(((GenericSig)type).Number.ToString(), BoxedTextColor.Number);
				else
					writer.Write(Escape(typeName), CSharpMetadataTextColorProvider.Instance.GetColor(type));
			} else if (type is ByRefSig) {
				((ByRefSig)type).Next.WriteTo(writer, syntaxForElementTypes, depth);
				writer.Write("&", BoxedTextColor.Operator);
			} else if (type is PtrSig) {
				((PtrSig)type).Next.WriteTo(writer, syntaxForElementTypes, depth);
				writer.Write("*", BoxedTextColor.Operator);
			} else if (type is GenericInstSig) {
				((GenericInstSig)type).GenericType.WriteTo(writer, syntaxForElementTypes, depth);
				var bh1 = BracePairHelper.Create(writer, "<", CodeBracesRangeFlags.AngleBrackets);
				var arguments = ((GenericInstSig)type).GenericArguments;
				for (int i = 0; i < arguments.Count; i++) {
					if (i > 0) {
						writer.Write(",", BoxedTextColor.Punctuation);
						writer.Write(" ", BoxedTextColor.Text);
					}
					arguments[i].WriteTo(writer, syntaxForElementTypes, depth);
				}
				bh1.Write(">");
			} else if (type is CModOptSig) {
				((ModifierSig)type).Next.WriteTo(writer, syntax, depth);
				writer.Write(" ", BoxedTextColor.Text);
				writer.Write("modopt", BoxedTextColor.Keyword);
				var bh1 = BracePairHelper.Create(writer, "(", CodeBracesRangeFlags.Parentheses);
				((ModifierSig)type).Modifier.WriteTo(writer, ILNameSyntax.TypeName, ThreeState.Unknown, depth);
				bh1.Write(")");
				writer.Write(" ", BoxedTextColor.Text);
			}
			else if (type is CModReqdSig) {
				((ModifierSig)type).Next.WriteTo(writer, syntax, depth);
				writer.Write(" ", BoxedTextColor.Text);
				writer.Write("modreq", BoxedTextColor.Keyword);
				var bh1 = BracePairHelper.Create(writer, "(", CodeBracesRangeFlags.Parentheses);
				((ModifierSig)type).Modifier.WriteTo(writer, ILNameSyntax.TypeName, ThreeState.Unknown, depth);
				bh1.Write(")");
				writer.Write(" ", BoxedTextColor.Text);
			}
			else if (type is SentinelSig) {
				writer.Write("...", BoxedTextColor.Text);
				((SentinelSig)type).Next.WriteTo(writer, syntax, depth);
			}
			else if (type is FnPtrSig fnPtrSig) {
				writer.Write("method", BoxedTextColor.Keyword);
				writer.Write(" ", BoxedTextColor.Text);
				fnPtrSig.MethodSig.RetType.WriteTo(writer, syntax, depth);
				writer.Write(" ", BoxedTextColor.Text);
				writer.Write("*", BoxedTextColor.Punctuation);
				var bh1 = BracePairHelper.Create(writer, "(", CodeBracesRangeFlags.Parentheses);
				var parameters = fnPtrSig.MethodSig.GetParameters();
				for (int i = 0; i < parameters.Count; ++i) {
					if (i > 0) {
						writer.Write(",", BoxedTextColor.Punctuation);
						writer.Write(" ", BoxedTextColor.Text);
					}
					parameters[i].WriteTo(writer, ILNameSyntax.SignatureNoNamedTypeParameters);
				}
				bh1.Write(")");
			}
			else if (type is TypeDefOrRefSig tdrs) {
				ThreeState isVT;
				if (tdrs is ClassSig)
					isVT = ThreeState.No;
				else if (tdrs is ValueTypeSig)
					isVT = ThreeState.Yes;
				else
					isVT = ThreeState.Unknown;
				WriteTo(tdrs.TypeDefOrRef, writer, syntax, isVT, depth);
			}
		}

		public static void WriteTo(this ITypeDefOrRef type, IDecompilerOutput writer, ILNameSyntax syntax = ILNameSyntax.Signature)
		{
			type.WriteTo(writer, syntax, ThreeState.Unknown, 0);
		}

		internal static void WriteTo(this ITypeDefOrRef type, IDecompilerOutput writer, ILNameSyntax syntax, ThreeState isValueType, int depth)
		{
			if (depth++ > MAX_CONVERTTYPE_DEPTH || type == null)
				return;
			var ts = type as TypeSpec;
			if (ts != null) {
				WriteTo(((TypeSpec)type).TypeSig, writer, syntax, depth);
				return;
			}
			string typeFullName = type.FullName;
			string typeName = type.Name.String;
			TypeSig typeSig = null;
			string name = type.DefinitionAssembly.IsCorLib() ? PrimitiveTypeName(typeFullName, type.Module, out typeSig) : null;
			if (syntax == ILNameSyntax.ShortTypeName) {
				if (name != null)
					WriteKeyword(writer, name, typeSig.ToTypeDefOrRef());
				else
					writer.Write(Escape(typeName), type, DecompilerReferenceFlags.None, CSharpMetadataTextColorProvider.Instance.GetColor(type));
			} else if ((syntax == ILNameSyntax.Signature || syntax == ILNameSyntax.SignatureNoNamedTypeParameters) && name != null) {
				WriteKeyword(writer, name, typeSig.ToTypeDefOrRef());
			} else {
				if (syntax == ILNameSyntax.Signature || syntax == ILNameSyntax.SignatureNoNamedTypeParameters) {
					bool isVT;
					if (isValueType != ThreeState.Unknown)
						isVT = isValueType == ThreeState.Yes;
					else
						isVT = DnlibExtensions.IsValueType(type);
					writer.Write(isVT ? "valuetype" : "class", BoxedTextColor.Keyword);
					writer.Write(" ", BoxedTextColor.Text);
				}

				if (type.DeclaringType != null) {
					type.DeclaringType.WriteTo(writer, ILNameSyntax.TypeName, ThreeState.Unknown, depth);
					writer.Write("/", BoxedTextColor.Operator);
					writer.Write(Escape(typeName), type, DecompilerReferenceFlags.None, CSharpMetadataTextColorProvider.Instance.GetColor(type));
				} else {
					if (!(type is TypeDef) && type.Scope != null && !(type is TypeSpec)) {
						var bh1 = BracePairHelper.Create(writer, "[", CodeBracesRangeFlags.SquareBrackets);
						writer.Write(Escape(type.Scope.GetScopeName()), type.Scope, DecompilerReferenceFlags.None, BoxedTextColor.ILModule);
						bh1.Write("]");
					}
					if (ts != null || MustEscape(typeFullName))
						writer.Write(Escape(typeFullName), type, DecompilerReferenceFlags.None, CSharpMetadataTextColorProvider.Instance.GetColor(type));
					else {
						WriteNamespace(writer, type.Namespace, type.DefinitionAssembly);
						if (!string.IsNullOrEmpty(type.Namespace))
							writer.Write(".", BoxedTextColor.Operator);
						writer.Write(IdentifierEscaper.Escape(type.Name), type, DecompilerReferenceFlags.None, CSharpMetadataTextColorProvider.Instance.GetColor(type));
					}
				}
			}
		}

		internal static void WriteNamespace(IDecompilerOutput writer, string ns, IAssembly nsAsm)
		{
			var sb = Interlocked.CompareExchange(ref cachedStringBuilder, null, cachedStringBuilder) ?? new StringBuilder();
			sb.Clear();
			var parts = ns.Split('.');
			for (int i = 0; i < parts.Length; i++) {
				if (i > 0) {
					sb.Append('.');
					writer.Write(".", BoxedTextColor.Operator);
				}
				var nsPart = parts[i];
				sb.Append(nsPart);
				if (!string.IsNullOrEmpty(nsPart)) {
					var nsRef = new NamespaceReference(nsAsm, sb.ToString());
					writer.Write(IdentifierEscaper.Escape(nsPart), nsRef, DecompilerReferenceFlags.None, BoxedTextColor.Namespace);
				}
			}
			if (sb.Capacity <= 1000)
				cachedStringBuilder = sb;
		}
		static StringBuilder cachedStringBuilder = new StringBuilder();

		internal static void WriteKeyword(IDecompilerOutput writer, string name, ITypeDefOrRef tdr)
		{
			var parts = name.Split(' ');
			for (int i = 0; i < parts.Length; i++) {
				if (i > 0)
					writer.Write(" ", BoxedTextColor.Text);
				if (tdr != null)
					writer.Write(parts[i], tdr, DecompilerReferenceFlags.None, BoxedTextColor.Keyword);
				else
					writer.Write(parts[i], BoxedTextColor.Keyword);
			}
		}

		public static void WriteOperand(IDecompilerOutput writer, object operand, int maxStringLength, NumberFormatter numberFormatter, MethodDef method = null)
		{
			Instruction targetInstruction = operand as Instruction;
			if (targetInstruction != null) {
				WriteOffsetReference(writer, targetInstruction, method);
				return;
			}

			IList<Instruction> targetInstructions = operand as IList<Instruction>;
			if (targetInstructions != null) {
				WriteLabelList(writer, targetInstructions, method);
				return;
			}

			SourceLocal variable = operand as SourceLocal;
			if (variable != null) {
				writer.Write(Escape(variable.Name), variable, DecompilerReferenceFlags.None, BoxedTextColor.Local);
				return;
			}

			Parameter paramRef = operand as Parameter;
			if (paramRef != null) {
				if (string.IsNullOrEmpty(paramRef.Name)) {
					if (paramRef.IsHiddenThisParameter)
						writer.Write("<hidden-this>", paramRef, DecompilerReferenceFlags.None, BoxedTextColor.Parameter);
					else
						writer.Write(paramRef.MethodSigIndex.ToString(), paramRef, DecompilerReferenceFlags.None, BoxedTextColor.Parameter);
				}
				else
					writer.Write(Escape(paramRef.Name), paramRef, DecompilerReferenceFlags.None, BoxedTextColor.Parameter);
				return;
			}

			MemberRef memberRef = operand as MemberRef;
			if (memberRef != null) {
				if (memberRef.IsMethodRef)
					memberRef.WriteMethodTo(writer);
				else
					memberRef.WriteFieldTo(writer);
				return;
			}

			MethodDef methodDef = operand as MethodDef;
			if (methodDef != null) {
				methodDef.WriteMethodTo(writer);
				return;
			}

			FieldDef fieldDef = operand as FieldDef;
			if (fieldDef != null) {
				fieldDef.WriteFieldTo(writer);
				return;
			}

			ITypeDefOrRef typeRef = operand as ITypeDefOrRef;
			if (typeRef != null) {
				typeRef.WriteTo(writer, ILNameSyntax.TypeName);
				return;
			}

			IMethod m = operand as IMethod;
			if (m != null) {
				m.WriteMethodTo(writer);
				return;
			}

			MethodSig sig = operand as MethodSig;
			if (sig != null) {
				sig.WriteTo(writer);
				return;
			}

			const DecompilerReferenceFlags numberFlags = DecompilerReferenceFlags.Local | DecompilerReferenceFlags.Hidden | DecompilerReferenceFlags.NoFollow;
			string s = operand as string;
			if (s != null) {
				int start = writer.NextPosition;
				writer.Write("\"" + NRefactory.CSharp.TextWriterTokenWriter.ConvertStringMaxLength(s, maxStringLength) + "\"", BoxedTextColor.String);
				int end = writer.NextPosition;
				writer.AddBracePair(new TextSpan(start, 1), new TextSpan(end - 1, 1), CodeBracesRangeFlags.DoubleQuotes);
			} else if (operand is char) {
				writer.Write(numberFormatter.Format((int)(char)operand), BoxedTextColor.Number);
			} else if (operand is float) {
				float val = (float)operand;
				if (val == 0) {
					if (1 / val == float.NegativeInfinity) {
						// negative zero is a special case
						writer.Write("-0.0", operand, numberFlags, BoxedTextColor.Number);
					}
					else
						writer.Write("0.0", operand, numberFlags, BoxedTextColor.Number);
				} else if (float.IsInfinity(val) || float.IsNaN(val)) {
					byte[] data = BitConverter.GetBytes(val);
					var bh1 = BracePairHelper.Create(writer, "(", CodeBracesRangeFlags.Parentheses);
					for (int i = 0; i < data.Length; i++) {
						if (i > 0)
							writer.Write(" ", BoxedTextColor.Text);
						writer.Write(data[i].ToString("X2"), BoxedTextColor.Number);
					}
					bh1.Write(")");
				} else {
					writer.Write(val.ToString("R", System.Globalization.CultureInfo.InvariantCulture), operand, numberFlags, BoxedTextColor.Number);
				}
			} else if (operand is double) {
				double val = (double)operand;
				if (val == 0) {
					if (1 / val == double.NegativeInfinity) {
						// negative zero is a special case
						writer.Write("-0.0", operand, numberFlags, BoxedTextColor.Number);
					}
					else
						writer.Write("0.0", operand, numberFlags, BoxedTextColor.Number);
				} else if (double.IsInfinity(val) || double.IsNaN(val)) {
					byte[] data = BitConverter.GetBytes(val);
					var bh1 = BracePairHelper.Create(writer, "(", CodeBracesRangeFlags.Parentheses);
					for (int i = 0; i < data.Length; i++) {
						if (i > 0)
							writer.Write(" ", BoxedTextColor.Text);
						writer.Write(data[i].ToString("X2"), BoxedTextColor.Number);
					}
					bh1.Write(")");
				} else {
					writer.Write(val.ToString("R", System.Globalization.CultureInfo.InvariantCulture), operand, numberFlags, BoxedTextColor.Number);
				}
			} else if (operand is bool) {
				writer.Write((bool)operand ? "true" : "false", BoxedTextColor.Keyword);
			} else {
				if (operand == null)
					writer.Write("<null>", BoxedTextColor.Error);
				else {
					switch (operand) {
					case int v:
						s = numberFormatter.Format(v);
						break;
					case uint v:
						s = numberFormatter.Format(v);
						break;
					case long v:
						s = numberFormatter.Format(v);
						break;
					case ulong v:
						s = numberFormatter.Format(v);
						break;
					case byte v:
						s = numberFormatter.Format(v);
						break;
					case ushort v:
						s = numberFormatter.Format(v);
						break;
					case short v:
						s = numberFormatter.Format(v);
						break;
					case sbyte v:
						s = numberFormatter.Format(v);
						break;
					default:
						s = ToInvariantCultureString(operand);
						break;
					}
					writer.Write(s, operand, numberFlags, CSharpMetadataTextColorProvider.Instance.GetColor(operand));
				}
			}
		}

		public static string PrimitiveTypeName(string fullName, ModuleDef module, out TypeSig typeSig)
		{
			var corLibTypes = module == null ? null : module.CorLibTypes;
			typeSig = null;
			switch (fullName) {
				case "System.SByte":
					if (corLibTypes != null)
						typeSig = corLibTypes.SByte;
					return "int8";
				case "System.Int16":
					if (corLibTypes != null)
						typeSig = corLibTypes.Int16;
					return "int16";
				case "System.Int32":
					if (corLibTypes != null)
						typeSig = corLibTypes.Int32;
					return "int32";
				case "System.Int64":
					if (corLibTypes != null)
						typeSig = corLibTypes.Int64;
					return "int64";
				case "System.Byte":
					if (corLibTypes != null)
						typeSig = corLibTypes.Byte;
					return "uint8";
				case "System.UInt16":
					if (corLibTypes != null)
						typeSig = corLibTypes.UInt16;
					return "uint16";
				case "System.UInt32":
					if (corLibTypes != null)
						typeSig = corLibTypes.UInt32;
					return "uint32";
				case "System.UInt64":
					if (corLibTypes != null)
						typeSig = corLibTypes.UInt64;
					return "uint64";
				case "System.Single":
					if (corLibTypes != null)
						typeSig = corLibTypes.Single;
					return "float32";
				case "System.Double":
					if (corLibTypes != null)
						typeSig = corLibTypes.Double;
					return "float64";
				case "System.Void":
					if (corLibTypes != null)
						typeSig = corLibTypes.Void;
					return "void";
				case "System.Boolean":
					if (corLibTypes != null)
						typeSig = corLibTypes.Boolean;
					return "bool";
				case "System.String":
					if (corLibTypes != null)
						typeSig = corLibTypes.String;
					return "string";
				case "System.Char":
					if (corLibTypes != null)
						typeSig = corLibTypes.Char;
					return "char";
				case "System.Object":
					if (corLibTypes != null)
						typeSig = corLibTypes.Object;
					return "object";
				case "System.IntPtr":
					if (corLibTypes != null)
						typeSig = corLibTypes.IntPtr;
					return "native int";
				case "System.UIntPtr":
					if (corLibTypes != null)
						typeSig = corLibTypes.UIntPtr;
					return "native unsigned int";
				case "System.TypedReference":
					if (corLibTypes != null)
						typeSig = corLibTypes.TypedReference;
					return "typedref";
				default:
					return null;
			}
		}
	}

	enum ThreeState : byte {
		Unknown,
		No,
		Yes,
	}
}
