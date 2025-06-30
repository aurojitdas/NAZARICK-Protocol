using PeNet;
using PeNet.Header.Pe;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NAZARICK_Protocol.service.Results
{
    internal class PEAnalysisResult
    {
        public string FilePath { get; }
        public bool IsValidPeFile { get; set; } = false;
        public List<string> SuspiciousImports { get; } = new List<string>();
        public List<string> SectionAnomalies { get; } = new List<string>();
        public List<string> Errors { get; } = new List<string>();
        public bool IsPotentiallySuspicious => SuspiciousImports.Any() || SectionAnomalies.Any();
        public PEAnalysisResult(string filePath)
        {
            FilePath = filePath;
        }

        /// <summary>
        /// Returns a formatted, human-readable report of the analysis.
        /// </summary>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"--- PE Analysis Report for: {Path.GetFileName(FilePath)} ---");

            if (!IsValidPeFile)
            {
                sb.AppendLine("Error: Not a valid PE file or could not be parsed.");
                foreach (var error in Errors)
                {
                    sb.AppendLine($" - {error}");
                }
                return sb.ToString();
            }

            sb.AppendLine($"\n[+] Overall Status: {(IsPotentiallySuspicious ? "SUSPICIOUS" : "Looks Clean")}");

            sb.AppendLine("\n[+] Suspicious Imports:");
            if (!SuspiciousImports.Any())
            {
                sb.AppendLine("  No suspicious imports found.");
            }
            else
            {
                foreach (var import in SuspiciousImports)
                {
                    sb.AppendLine($"  [!] Found: {import}");
                }
            }

            sb.AppendLine("\n[+] Section Anomalies:");
            if (!SectionAnomalies.Any())
            {
                sb.AppendLine("  No section anomalies found.");
            }
            else
            {
                foreach (var anomaly in SectionAnomalies)
                {
                    sb.AppendLine($"  [!] {anomaly}");
                }
            }

            return sb.ToString();




        }
    }
}


