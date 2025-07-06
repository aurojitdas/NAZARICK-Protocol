using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NAZARICK_Protocol.service
{
    public class VirusTotalFileAnalysisResults
    {
       
        public bool IsMalicious { get; set; }        
        public string? ThreatLabel { get; set; }        
        public int MaliciousDetections { get; set; }        
        public int SuspiciousDetections { get; set; }
        public int UndetectedCount { get; set; }       
        public int TotalScans { get; set; }
        public DateTime LastAnalysisDate { get; set; }
        public string? MeaningfulName { get; set; }
        public long FileSize { get; set; }
        public string? Sha256 { get; set; }
        public string? Md5 { get; set; }
        public string? Permalink { get; set; } // Direct link to the report on VirusTotal
    }
}
