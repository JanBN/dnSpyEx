// Licensed under the Apache License, Version 2.0.  See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Reflection;
using Microsoft.Cci;
using Microsoft.CodeAnalysis.CSharp.Symbols;
using Microsoft.CodeAnalysis.ExpressionEvaluator;
using Microsoft.CodeAnalysis.PooledObjects;

namespace Microsoft.CodeAnalysis.CSharp.ExpressionEvaluator
{
    sealed class RenamedParametersMethodSymbol : MethodSymbol
    {
        private readonly MethodSymbol _originalMethod;
        private readonly ParameterSymbol? _thisParameter;
        private readonly ImmutableArray<ParameterSymbol> _parameters;

        public RenamedParametersMethodSymbol(MethodSymbol originalMethod, MethodDebugInfo<TypeSymbol, LocalSymbol> methodDebugInfo)
        {
            _originalMethod = originalMethod;
            var parameters = originalMethod.Parameters;
            var builder = ArrayBuilder<ParameterSymbol>.GetInstance();

            var thisParameter = originalMethod.ThisParameter;
            var hasThisParameter = (object)thisParameter != null;
            if (hasThisParameter)
            {
                _thisParameter = MakeParameterSymbol(-1, GeneratedNames.ThisProxyFieldName(), thisParameter!);
                Debug.Assert(TypeSymbol.Equals(_thisParameter.Type, originalMethod.ContainingType, TypeCompareKind.ConsiderEverything));
            }

            foreach (var p in originalMethod.Parameters)
            {
                var ordinal = p.Ordinal;
                Debug.Assert(ordinal == builder.Count);
                var name = methodDebugInfo.GetParameterName(ordinal + (hasThisParameter ? 1 : 0), p);
                var parameter = MakeParameterSymbol(ordinal, p.Name, p);
                builder.Add(parameter);
            }

            _parameters = builder.ToImmutableAndFree();
        }

        private ParameterSymbol MakeParameterSymbol(int ordinal, string name, ParameterSymbol sourceParameter)
        {
            return SynthesizedParameterSymbol.Create(this, sourceParameter.TypeWithAnnotations, ordinal, sourceParameter.RefKind, name, sourceParameter.RefCustomModifiers, null, sourceParameter.IsNullChecked);
        }

        public override MethodKind MethodKind => _originalMethod.MethodKind;
        public override int Arity => _originalMethod.Arity;
        #nullable enable
        internal override UnmanagedCallersOnlyAttributeData? GetUnmanagedCallersOnlyAttributeData(bool forceComplete) =>
            _originalMethod.GetUnmanagedCallersOnlyAttributeData(forceComplete);
        #nullable disable
        public override bool IsExtensionMethod => _originalMethod.IsExtensionMethod;
        internal override bool HasSpecialName => _originalMethod.HasSpecialName;
        internal override MethodImplAttributes ImplementationAttributes => _originalMethod.ImplementationAttributes;
        internal override bool HasDeclarativeSecurity => _originalMethod.HasDeclarativeSecurity;
        internal override MarshalPseudoCustomAttributeData ReturnValueMarshallingInformation => _originalMethod.ReturnValueMarshallingInformation;
        internal override bool RequiresSecurityObject => _originalMethod.RequiresSecurityObject;
        public override bool HidesBaseMethodsByName => _originalMethod.HidesBaseMethodsByName;
        public override bool IsVararg => _originalMethod.IsVararg;
        public override bool ReturnsVoid => _originalMethod.ReturnsVoid;
        public override bool IsAsync => _originalMethod.IsAsync;
        public override RefKind RefKind => _originalMethod.RefKind;
        public override TypeWithAnnotations ReturnTypeWithAnnotations => _originalMethod.ReturnTypeWithAnnotations;
        public override FlowAnalysisAnnotations ReturnTypeFlowAnalysisAnnotations => _originalMethod.ReturnTypeFlowAnalysisAnnotations;
        public override ImmutableHashSet<string> ReturnNotNullIfParameterNotNull => _originalMethod.ReturnNotNullIfParameterNotNull;
        public override FlowAnalysisAnnotations FlowAnalysisAnnotations => _originalMethod.FlowAnalysisAnnotations;
        public override ImmutableArray<TypeWithAnnotations> TypeArgumentsWithAnnotations => _originalMethod.TypeArgumentsWithAnnotations;
        public override ImmutableArray<TypeParameterSymbol> TypeParameters => _originalMethod.TypeParameters;
        public override ImmutableArray<ParameterSymbol> Parameters => _parameters;
        internal override bool IsDeclaredReadOnly => _originalMethod.IsDeclaredReadOnly;
        internal override bool IsInitOnly => _originalMethod.IsInitOnly;
        public override ImmutableArray<MethodSymbol> ExplicitInterfaceImplementations => _originalMethod.ExplicitInterfaceImplementations;
        public override ImmutableArray<CustomModifier> RefCustomModifiers => _originalMethod.RefCustomModifiers;
        public override Symbol AssociatedSymbol => _originalMethod.AssociatedSymbol;
        internal override CallingConvention CallingConvention => _originalMethod.CallingConvention;
        internal override bool GenerateDebugInfo => _originalMethod.GenerateDebugInfo;
        public override Symbol ContainingSymbol => _originalMethod.ContainingSymbol;
        public override ImmutableArray<Location> Locations => _originalMethod.Locations;
        public override ImmutableArray<SyntaxReference> DeclaringSyntaxReferences => _originalMethod.DeclaringSyntaxReferences;
        public override Accessibility DeclaredAccessibility => _originalMethod.DeclaredAccessibility;
        public override bool IsStatic => _originalMethod.IsStatic;
        public override bool IsVirtual => _originalMethod.IsVirtual;
        public override bool IsOverride => _originalMethod.IsOverride;
        public override bool IsAbstract => _originalMethod.IsAbstract;
        public override bool IsSealed => _originalMethod.IsSealed;
        public override bool IsExtern => _originalMethod.IsExtern;
        internal override ObsoleteAttributeData ObsoleteAttributeData => _originalMethod.ObsoleteAttributeData;

        internal override bool IsMetadataNewSlot(bool ignoreInterfaceImplementationChanges = false) => _originalMethod.IsMetadataNewSlot(ignoreInterfaceImplementationChanges);
        internal override bool IsMetadataVirtual(bool ignoreInterfaceImplementationChanges = false) => _originalMethod.IsMetadataVirtual(ignoreInterfaceImplementationChanges);
        public override DllImportData GetDllImportData() => _originalMethod.GetDllImportData();
        internal override IEnumerable<SecurityAttribute> GetSecurityInformation() => _originalMethod.GetSecurityInformation();
        internal override ImmutableArray<string> GetAppliedConditionalSymbols() => _originalMethod.GetAppliedConditionalSymbols();
        internal override int CalculateLocalSyntaxOffset(int localPosition, SyntaxTree localTree) => _originalMethod.CalculateLocalSyntaxOffset(localPosition, localTree);
        public override bool AreLocalsZeroed => _originalMethod.AreLocalsZeroed;
        internal override bool IsNullableAnalysisEnabled() => _originalMethod.IsNullableAnalysisEnabled();
        internal override bool TryGetThisParameter(out ParameterSymbol thisParameter)
        {
            thisParameter = _thisParameter;
            return true;
        }
    }
}
