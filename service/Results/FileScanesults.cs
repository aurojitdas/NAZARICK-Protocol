using System.Collections.Generic;
using System.Linq;

namespace NAZARICK_Protocol.service.Results{
    
    public class FileScanReport
    {
       
        public string FilePath { get; }

        public List<string> MatchedRules { get; }
        
        public int MatchedRulesCount => MatchedRules.Count;
        
        public bool IsMalicious => MatchedRules.Any();

        /// <summary>
        /// Initializes a new instance of the FileScanReport class.
        /// </summary>
        /// <param name="filePath">The path to the scanned file.</param>
        /// <param name="scanResults">The list of scan results from dnYara.</param>
        public FileScanReport(string filePath, List<dnYara.ScanResult> scanResults)
        {
            FilePath = filePath;
            MatchedRules = scanResults?.Select(r => r.MatchingRule.Identifier).ToList() ?? new List<string>();
        }

        public override string ToString()
        {
            if (!IsMalicious)
            {
                return $"File: {FilePath}\nResult: No threats detected.";
            }

            return $"File: {FilePath}\nResult: Malicious\nMatched Rules ({MatchedRulesCount}): {string.Join(", ", MatchedRules)}";
        }
    }
}
