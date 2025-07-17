using NAZARICK_Protocol.service.Results;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace NAZARICK_Protocol.service
{
    /// <summary>
    /// Hybrid analyzer that combines PE analysis, entropy analysis, and prepares for YARA integration
    /// </summary>
    public class HybridFileAnalyzer
    {
        private readonly PEAnalyzer _peAnalyzer;
        private readonly EntropyAnalyzer _entropyAnalyzer;

        // Entropy thresholds
        private const double PACKED_ENTROPY_THRESHOLD = 7.5;
        private const double ENCRYPTED_ENTROPY_THRESHOLD = 7.9;
        private const double NORMAL_ENTROPY_MAX = 6.8;

        public HybridFileAnalyzer()
        {
            _peAnalyzer = new PEAnalyzer();
            _entropyAnalyzer = new EntropyAnalyzer();
        }

        /// <summary>
        /// Performs comprehensive analysis combining PE, entropy, and preparing for YARA
        /// </summary>
        public async Task<HybridAnalysisResult> AnalyzeFile(string filePath)
        {
            var result = new HybridAnalysisResult
            {
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                FileSize = new FileInfo(filePath).Length,
                AnalysisTime = DateTime.UtcNow
            };

            // Run analyses in parallel for performance
            var peTask = Task.Run(() => _peAnalyzer.Analyze(filePath));
            var entropyTask = Task.Run(() => _entropyAnalyzer.AnalyzeFileEntropy(filePath));

            await Task.WhenAll(peTask, entropyTask);

            // Get results
            result.PEAnalysis = peTask.Result;
            result.FileEntropy = entropyTask.Result;

            // Analyze entropy results
            AnalyzeEntropyResults(result);

            // Combine scores and determine final threat level
            CalculateFinalScore(result);
            

            return result;
        }

        private void AnalyzeEntropyResults(HybridAnalysisResult result)
        {
            if (result.FileEntropy < 0)
            {
                result.EntropyAnalysis = "Unable to calculate entropy";
                return;
            }

            result.EntropyScore = 0;

            if (result.FileEntropy >= ENCRYPTED_ENTROPY_THRESHOLD)
            {
                result.EntropyScore = 40;
                result.EntropyAnalysis = $"Very high entropy ({result.FileEntropy:F2}) - Likely encrypted or highly compressed [+40 points]";
            }
            else if (result.FileEntropy >= PACKED_ENTROPY_THRESHOLD)
            {
                result.EntropyScore = 25;
                result.EntropyAnalysis = $"High entropy ({result.FileEntropy:F2}) - Possibly packed or compressed [+25 points]";
            }
            else if (result.FileEntropy >= NORMAL_ENTROPY_MAX)
            {
                result.EntropyScore = 10;
                result.EntropyAnalysis = $"Elevated entropy ({result.FileEntropy:F2}) - May contain compressed sections [+10 points]";
            }
            else
            {
                result.EntropyAnalysis = $"Normal entropy ({result.FileEntropy:F2}) - Typical for uncompressed executable [0 points]";
            }

            // Cross-reference with PE analysis
            if (result.PEAnalysis != null && result.PEAnalysis.IsValidPeFile)
            {
                // High entropy + writable/executable sections = very suspicious
                if (result.FileEntropy >= PACKED_ENTROPY_THRESHOLD &&
                    result.PEAnalysis.SectionAnomalies.Any(a => a.Contains("Writable and Executable")))
                {
                    result.EntropyScore += 20;
                    result.CrossAnalysisFindings.Add("High entropy combined with W+X sections suggests packed malware [+20 points]");
                }

                // High entropy + no digital signature = suspicious
                if (result.FileEntropy >= PACKED_ENTROPY_THRESHOLD &&
                    result.PEAnalysis.SignatureInfo?.Contains("not digitally signed") == true)
                {
                    result.EntropyScore += 15;
                    result.CrossAnalysisFindings.Add("High entropy in unsigned file increases suspicion [+15 points]");
                }
            }
        }

        private void CalculateFinalScore(HybridAnalysisResult result)
        {
            // Combine all scores
            result.TotalScore = 0;

            if (result.PEAnalysis != null)
            {
                result.TotalScore += result.PEAnalysis.TotalScore;
            }

            result.TotalScore += result.EntropyScore;

            // Apply modifiers based on file characteristics
            if (result.FileSize < 50 * 1024) // Less than 50KB
            {
                result.TotalScore += 10;
                result.SizeAnalysis = "Very small executable size is suspicious [+10 points]";
            }
            else if (result.FileSize > 100 * 1024 * 1024) // More than 100MB
            {
                result.TotalScore += 5;
                result.SizeAnalysis = "Very large executable size may indicate bundled content [+5 points]";
            }

            // Determine final threat level
            if (result.TotalScore >= 120)
            {
                result.FinalThreatLevel = "CRITICAL";
                result.Confidence = "Very High";
            }
            else if (result.TotalScore >= 80)
            {
                result.FinalThreatLevel = "HIGH";
                result.Confidence = "High";
            }
            else if (result.TotalScore >= 40)
            {
                result.FinalThreatLevel = "MEDIUM";
                result.Confidence = "Medium";
            }
            else if (result.TotalScore >= 15)
            {
                result.FinalThreatLevel = "LOW";
                result.Confidence = "Low";
            }
            else
            {
                result.FinalThreatLevel = "CLEAN";
                result.Confidence = "High";
            }
        }
        
    }
   
}