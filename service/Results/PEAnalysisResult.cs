using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NAZARICK_Protocol.service.Results
{
    /// <summary>
    /// Holds the complete results of a Portable Executable (PE) file analysis.
    /// </summary>
    public class PEAnalysisResult
    {
        public string FilePath { get; set; }
        public bool IsValidPeFile { get; set; }
        public int TotalScore { get; set; }
        public string ThreatLevel { get; set; }
        public string Summary { get; set; }

        public List<string> SuspiciousImports { get; set; } = new List<string>();
        public List<string> ImportCombinations { get; set; } = new List<string>();
        public List<string> SectionAnomalies { get; set; } = new List<string>();
        public string SignatureInfo { get; set; }
        public string EntryPointInfo { get; set; }
        public List<string> MetadataInfo { get; set; } = new List<string>();
        public List<string> Errors { get; set; } = new List<string>();

        public PEAnalysisResult(string filePath)
        {
            FilePath = filePath;
        }

        /// <summary>
        /// Returns a formatted, comprehensive report of the entire analysis.
        /// </summary>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"--- PE Analysis Report for: {Path.GetFileName(FilePath)} ---");

            if (!IsValidPeFile)
            {
                sb.AppendLine("\n[!] ERROR: File is not a valid PE file or could not be parsed.");
                foreach (var error in Errors)
                {
                    sb.AppendLine($"    - {error}");
                }
                return sb.ToString();
            }

            // --- Main Summary ---
            sb.AppendLine($"\n[SCORE]     Threat Score: {TotalScore}");
            sb.AppendLine($"[LEVEL]     Threat Level: {ThreatLevel}");
            sb.AppendLine($"[SUMMARY]   {Summary}");

            sb.AppendLine("\n--- Detailed Findings ---");

            // --- Digital Signature ---
            sb.AppendLine("\n[+] Digital Signature");
            sb.AppendLine(string.IsNullOrEmpty(SignatureInfo) ? "    No signature information available." : $"    {SignatureInfo}");

            // --- Entry Point ---
            if (!string.IsNullOrEmpty(EntryPointInfo))
            {
                sb.AppendLine("\n[!] Entry Point Anomalies");
                sb.AppendLine($"    {EntryPointInfo.Trim()}");
            }

            // --- Suspicious Imports ---
            if (SuspiciousImports.Any())
            {
                sb.AppendLine("\n[!] Suspicious Imports Found");
                foreach (var import in SuspiciousImports)
                {
                    sb.AppendLine($"    - {import}");
                }
            }

            // --- Import Combinations ---
            if (ImportCombinations.Any())
            {
                sb.AppendLine("\n[!] Suspicious Import Combinations (Attack Patterns)");
                foreach (var combo in ImportCombinations)
                {
                    sb.AppendLine($"    - {combo}");
                }
            }

            // --- Section Anomalies ---
            if (SectionAnomalies.Any())
            {
                sb.AppendLine("\n[!] Section Anomalies");
                foreach (var anomaly in SectionAnomalies)
                {
                    sb.AppendLine($"    - {anomaly}");
                }
            }

            // --- Metadata ---
            if (MetadataInfo.Any())
            {
                sb.AppendLine("\n[!] Metadata Anomalies");
                foreach (var meta in MetadataInfo)
                {
                    sb.AppendLine($"    - {meta}");
                }
            }

            // --- Clean Bill of Health ---
            if (ThreatLevel == "CLEAN")
            {
                sb.AppendLine("\n[+] No significant suspicious indicators were found.");
            }

            return sb.ToString();
        }
    }
}