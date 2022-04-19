using System;
using System.IO;
using dnlib.PE;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

namespace PatchSubSystem {
	public sealed class PatchSubSystem : Task {
#pragma warning disable CS8618 // Non-nullable field is uninitialized.
		[Required]
		public string TargetSubSystem { get; set; }

		[Required]
		public string OutputFile { get; set; }
#pragma warning restore CS8618 // Non-nullable field is uninitialized.

		public override bool Execute() {
			if (string.IsNullOrWhiteSpace(OutputFile)) {
				Log.LogMessageFromText(nameof(OutputFile) + " is an empty string", MessageImportance.High);
				return false;
			}

			if (string.IsNullOrWhiteSpace(TargetSubSystem)) {
				Log.LogMessageFromText(nameof(TargetSubSystem) + " is an empty string", MessageImportance.High);
				return false;
			}

			if (!File.Exists(OutputFile)) {
				Log.LogMessageFromText("Specified output file does not exist", MessageImportance.High);
				return false;
			}

			if (!Enum.TryParse<Subsystem>(TargetSubSystem, out var targetSubSystem)) {
				Log.LogMessageFromText("Specifed SubSystem is invalid", MessageImportance.High);
				return false;
			}

			var exeFile = Path.ChangeExtension(OutputFile, "exe");

			if (!File.Exists(exeFile)) {
				Log.LogMessageFromText("Apphost for specified output file does not exist", MessageImportance.High);
				return false;
			}

			uint subSystemOffset;
			using (var peImage = new PEImage(exeFile, verify: true)) {
				// 68 = offset from start of optional header to SubSystem value.
				subSystemOffset = (uint)peImage.ImageNTHeaders.OptionalHeader.StartOffset + 68;
			}

			using (var fs = File.Open(exeFile, FileMode.Open, FileAccess.Write)) {
				fs.Position = subSystemOffset;
				var subSystemBytes = BitConverter.GetBytes((ushort)targetSubSystem);
				fs.Write(subSystemBytes, 0, sizeof(ushort));
			}

			return true;
		}
	}
}
