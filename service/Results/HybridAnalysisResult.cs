using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NAZARICK_Protocol.service.Results
{
    /// <summary>
    /// Comprehensive result from hybrid analysis
    /// </summary>

    public class HybridAnalysisResult
    {
        public string FilePath { get; set; }
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public DateTime AnalysisTime { get; set; }

        // PE Analysis Results
        public PEAnalysisResult PEAnalysis { get; set; }

        // Entropy Analysis Results
        public double FileEntropy { get; set; }
        public int EntropyScore { get; set; }
        public string EntropyAnalysis { get; set; }

        // Combined Analysis
        public int TotalScore { get; set; }
        public string FinalThreatLevel { get; set; }
        public string Confidence { get; set; }
        public string SizeAnalysis { get; set; }       

        // Cross-analysis findings
        public List<string> CrossAnalysisFindings { get; set; } = new List<string>();

        /// <summary>
        /// Generates a formatted string report of the entire analysis.
        /// </summary>
        /// <returns>A multi-line string summarizing the analysis results.</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();

            sb.AppendLine("========== Hybrid Analysis Report ==========");
            sb.AppendLine($"File: {FileName}");
            sb.AppendLine($"Size: {FileSize / 1024.0:F2} KB");
            sb.AppendLine($"Analyzed On: {AnalysisTime.ToLocalTime()}");
            sb.AppendLine("--------------------------------------------");
            sb.AppendLine($"Final Verdict: {FinalThreatLevel} (Confidence: {Confidence})");
            sb.AppendLine($"Total Score: {TotalScore}");
            sb.AppendLine("============================================");

            if (PEAnalysis != null)
            {
                // Assumes PEAnalysisResult also has a well-defined ToString() method.
                // If not, you would format its properties here manually.
                sb.AppendLine("\n## PE Analysis Details ##");
                sb.Append(PEAnalysis.ToString());
            }

            sb.AppendLine("\n## Entropy Analysis ##");
            sb.AppendLine(EntropyAnalysis ?? "Not performed.");

            if (!string.IsNullOrEmpty(SizeAnalysis))
            {
                sb.AppendLine("\n## Size Analysis ##");
                sb.AppendLine(SizeAnalysis);
            }

            if (CrossAnalysisFindings.Any())
            {
                sb.AppendLine("\n## Cross-Analysis Findings ##");
                foreach (var finding in CrossAnalysisFindings)
                {
                    sb.AppendLine($"- {finding}");
                }
            }

            sb.AppendLine("\n========== End of Report ==========");

            return sb.ToString();
        }

    }

}