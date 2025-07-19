using System.Collections.Generic;
using System.Linq;

namespace NAZARICK_Protocol.service.Results{
    
    public class YARAScanReport
    {
       
        public string FilePath { get; }

        public List<string> MatchedRules { get; }
        public HybridAnalysisResult HybridResult { get; set; }

        public int MatchedRulesCount => MatchedRules.Count;

        public bool? isHybridThreatDetected { get; set; }
        public bool isYaraThreatDetected => MatchedRules.Any();


      


        /// <summary>
        /// Initializes a new instance of the FileScanReport class.
        /// </summary>
        /// <param name="filePath">The path to the scanned file.</param>
        /// <param name="scanResults">The list of scan results from dnYara.</param>
        public YARAScanReport(string filePath, List<dnYara.ScanResult> scanResults, HybridAnalysisResult hybridResult)
        {
            FilePath = filePath;
            MatchedRules = scanResults?.Select(r => r.MatchingRule.Identifier).ToList() ?? new List<string>();
            HybridResult = hybridResult;
        }

        public override string ToString()


        {
            if (!isYaraThreatDetected)
            {
                return $"File: {FilePath}\nResult: No threats detected.";
            }

            return $"File: {FilePath}\nResult: Malicious\nMatched Rules ({MatchedRulesCount}): {string.Join(", ", MatchedRules)}";
        }
    }
}
