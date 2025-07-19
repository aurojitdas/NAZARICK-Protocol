using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using NAZARICK_Protocol.service.Results;

namespace NAZARICK_Protocol
{
    public partial class FullReportWindow : Window
    {
        private YARAScanReport scanReport;
        private string reportContent;

        public FullReportWindow(YARAScanReport report)
        {
            InitializeComponent();
            scanReport = report;
            LoadAnalysisData();
        }

        private void LoadAnalysisData()
        {
            if (scanReport == null)
            {
                MessageBox.Show("No scan report data available.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                this.Close();
                return;
            }

            try
            {
                // Load file information
                FileNameHeader.Text = $"Analysis Report - {Path.GetFileName(scanReport.FilePath)}";
                FilePathHeader.Text = $"File Path: {scanReport.FilePath}";

                if (scanReport.HybridResult != null)
                {
                    AnalysisTimeText.Text = $"Analysis Time: {scanReport.HybridResult.AnalysisTime:yyyy-MM-dd HH:mm:ss}";
                    LoadSummaryData();
                    LoadHybridAnalysisData();
                    LoadPEAnalysisData();
                }
                else
                {
                    AnalysisTimeText.Text = $"Analysis Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
                }

                LoadYARAAnalysisData();
                GenerateReportContent();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading analysis data: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadSummaryData()
        {
            var hybrid = scanReport.HybridResult;

            // Overall threat level (prioritize YARA findings)
            string overallThreat = "CLEAN";
            if (scanReport.isYaraThreatDetected)
                overallThreat = "THREAT DETECTED";
            else if (hybrid.FinalThreatLevel != null && hybrid.FinalThreatLevel.ToUpper() != "CLEAN")
                overallThreat = hybrid.FinalThreatLevel;

            OverallThreatLevelText.Text = overallThreat;
            OverallThreatLevelText.Style = GetThreatLevelStyle(overallThreat);

            // Total score
            int totalScore = hybrid.TotalScore;
            if (scanReport.isYaraThreatDetected)
                totalScore = Math.Max(totalScore, 80); // Boost score if YARA detected threats

            TotalScoreText.Text = $"{totalScore}/100";
            TotalScoreText.Foreground = GetScoreColor(totalScore);

            // File size
            double fileSizeKB = hybrid.FileSize / 1024.0;
            if (fileSizeKB < 1024)
                FileSizeText.Text = $"{fileSizeKB:F2} KB";
            else
                FileSizeText.Text = $"{fileSizeKB / 1024.0:F2} MB";
        }

        private void LoadYARAAnalysisData()
        {
            // YARA Status
            YaraStatusText.Text = scanReport.isYaraThreatDetected ? "THREAT DETECTED" : "CLEAN";
            YaraStatusText.Style = scanReport.isYaraThreatDetected ?
                (Style)FindResource("HighStyle") : (Style)FindResource("CleanStyle");

            // Rules matched count
            YaraRulesCountText.Text = $"{scanReport.MatchedRulesCount} rules matched";

            // Detected threats
            if (scanReport.MatchedRules.Any())
            {
                YaraThreatsText.Text = string.Join("\n• ", scanReport.MatchedRules.Select(r => r));
                if (!YaraThreatsText.Text.StartsWith("• "))
                    YaraThreatsText.Text = "• " + YaraThreatsText.Text;
                YaraThreatsText.Foreground = Brushes.DarkRed;
            }
            else
            {
                YaraThreatsText.Text = "No threats detected";
                YaraThreatsText.Foreground = Brushes.DarkGreen;
            }
        }

        private void LoadPEAnalysisData()
        {
            var peAnalysis = scanReport.HybridResult?.PEAnalysis;

            if (peAnalysis == null)
            {
                SetPEDataUnavailable();
                return;
            }

            // PE Validity
            PeValidityText.Text = peAnalysis.IsValidPeFile ? "Valid PE File" : "Invalid/Not PE File";
            PeValidityText.Foreground = peAnalysis.IsValidPeFile ? Brushes.DarkGreen : Brushes.DarkRed;

            // PE Threat Level
            PeThreatLevelText.Text = peAnalysis.ThreatLevel ?? "Unknown";
            PeThreatLevelText.Style = GetThreatLevelStyle(peAnalysis.ThreatLevel);

            // PE Score
            PeScoreText.Text = $"{peAnalysis.TotalScore}/100";
            PeScoreText.Foreground = GetScoreColor(peAnalysis.TotalScore);

            // Digital Signature
            PeSignatureText.Text = string.IsNullOrEmpty(peAnalysis.SignatureInfo) ?
                "No signature information" : peAnalysis.SignatureInfo;

            // Suspicious Imports
            if (peAnalysis.SuspiciousImports.Any())
            {
                PeSuspiciousImportsText.Text = string.Join("\n• ", peAnalysis.SuspiciousImports);
                if (!PeSuspiciousImportsText.Text.StartsWith("• "))
                    PeSuspiciousImportsText.Text = "• " + PeSuspiciousImportsText.Text;
                PeSuspiciousImportsText.Foreground = Brushes.DarkOrange;
            }
            else
            {
                PeSuspiciousImportsText.Text = "No suspicious imports detected";
                PeSuspiciousImportsText.Foreground = Brushes.DarkGreen;
            }

            // Detailed findings
            LoadPEDetailedFindings(peAnalysis);
        }

        private void LoadPEDetailedFindings(PEAnalysisResult peAnalysis)
        {
            // Section Anomalies
            PeSectionAnomaliesText.Text = peAnalysis.SectionAnomalies.Any() ?
                string.Join("\n• ", peAnalysis.SectionAnomalies) : "No section anomalies detected";
            if (peAnalysis.SectionAnomalies.Any() && !PeSectionAnomaliesText.Text.StartsWith("• "))
                PeSectionAnomaliesText.Text = "• " + PeSectionAnomaliesText.Text;

            // Import Combinations
            PeImportCombinationsText.Text = peAnalysis.ImportCombinations.Any() ?
                string.Join("\n• ", peAnalysis.ImportCombinations) : "No suspicious import combinations detected";
            if (peAnalysis.ImportCombinations.Any() && !PeImportCombinationsText.Text.StartsWith("• "))
                PeImportCombinationsText.Text = "• " + PeImportCombinationsText.Text;

            // Entry Point
            PeEntryPointText.Text = string.IsNullOrEmpty(peAnalysis.EntryPointInfo) ?
                "No entry point anomalies detected" : peAnalysis.EntryPointInfo;

            // Metadata
            PeMetadataText.Text = peAnalysis.MetadataInfo.Any() ?
                string.Join("\n• ", peAnalysis.MetadataInfo) : "No metadata anomalies detected";
            if (peAnalysis.MetadataInfo.Any() && !PeMetadataText.Text.StartsWith("• "))
                PeMetadataText.Text = "• " + PeMetadataText.Text;
        }

        private void LoadHybridAnalysisData()
        {
            var hybrid = scanReport.HybridResult;

            // Final Verdict
            HybridFinalVerdictText.Text = hybrid.FinalThreatLevel ?? "Unknown";
            HybridFinalVerdictText.Style = GetThreatLevelStyle(hybrid.FinalThreatLevel);

            // Confidence
            HybridConfidenceText.Text = hybrid.Confidence ?? "Unknown";

            // Entropy Analysis
            if (!string.IsNullOrEmpty(hybrid.EntropyAnalysis))
            {
                HybridEntropyText.Text = $"{hybrid.EntropyAnalysis} (Score: {hybrid.EntropyScore})";
            }
            else
            {
                HybridEntropyText.Text = $"Entropy: {hybrid.FileEntropy:F3} (Score: {hybrid.EntropyScore})";
            }

            // Size Analysis
            HybridSizeAnalysisText.Text = string.IsNullOrEmpty(hybrid.SizeAnalysis) ?
                "No size anomalies detected" : hybrid.SizeAnalysis;

            // Cross Analysis Findings
            if (hybrid.CrossAnalysisFindings.Any())
            {
                HybridCrossAnalysisText.Text = string.Join("\n• ", hybrid.CrossAnalysisFindings);
                if (!HybridCrossAnalysisText.Text.StartsWith("• "))
                    HybridCrossAnalysisText.Text = "• " + HybridCrossAnalysisText.Text;
                HybridCrossAnalysisText.Foreground = Brushes.DarkOrange;
            }
            else
            {
                HybridCrossAnalysisText.Text = "No cross-analysis findings";
                HybridCrossAnalysisText.Foreground = Brushes.DarkGreen;
            }
        }

        private void SetPEDataUnavailable()
        {
            PeValidityText.Text = "PE analysis not available";
            PeThreatLevelText.Text = "N/A";
            PeScoreText.Text = "N/A";
            PeSignatureText.Text = "N/A";
            PeSuspiciousImportsText.Text = "PE analysis not performed";
            PeSectionAnomaliesText.Text = "PE analysis not performed";
            PeImportCombinationsText.Text = "PE analysis not performed";
            PeEntryPointText.Text = "PE analysis not performed";
            PeMetadataText.Text = "PE analysis not performed";
        }

        private Style GetThreatLevelStyle(string threatLevel)
        {
            if (string.IsNullOrEmpty(threatLevel))
                return (Style)FindResource("ContentStyle");

            switch (threatLevel.ToUpper())
            {
                case "CLEAN":
                    return (Style)FindResource("CleanStyle");
                case "LOW":
                    return (Style)FindResource("LowStyle");
                case "MEDIUM":
                    return (Style)FindResource("MediumStyle");
                case "HIGH":
                case "THREAT DETECTED":
                    return (Style)FindResource("HighStyle");
                case "CRITICAL":
                    return (Style)FindResource("CriticalStyle");
                default:
                    return (Style)FindResource("ContentStyle");
            }
        }

        private Brush GetScoreColor(int score)
        {
            if (score >= 80) return Brushes.DarkRed;
            if (score >= 60) return Brushes.OrangeRed;
            if (score >= 40) return Brushes.Orange;
            if (score >= 20) return Brushes.Gold;
            return Brushes.DarkGreen;
        }

        private void GenerateReportContent()
        {
            var sb = new StringBuilder();
            sb.AppendLine("====================================================");
            sb.AppendLine("           NAZARICK Protocol - Analysis Report");
            sb.AppendLine("====================================================");
            sb.AppendLine($"File: {Path.GetFileName(scanReport.FilePath)}");
            sb.AppendLine($"Path: {scanReport.FilePath}");

            if (scanReport.HybridResult != null)
            {
                sb.AppendLine($"Analysis Time: {scanReport.HybridResult.AnalysisTime:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"File Size: {scanReport.HybridResult.FileSize / 1024.0:F2} KB");
            }

            sb.AppendLine("====================================================");
            sb.AppendLine();

            // Executive Summary
            sb.AppendLine("EXECUTIVE SUMMARY");
            sb.AppendLine("─────────────────");
            sb.AppendLine($"Overall Status: {OverallThreatLevelText.Text}");
            sb.AppendLine($"Total Score: {TotalScoreText.Text}");
            sb.AppendLine();

            // YARA Results
            sb.AppendLine("YARA PATTERN ANALYSIS");
            sb.AppendLine("─────────────────────");
            sb.AppendLine($"Detection Status: {YaraStatusText.Text}");
            sb.AppendLine($"Rules Matched: {YaraRulesCountText.Text}");
            if (scanReport.MatchedRules.Any())
            {
                sb.AppendLine("Detected Threats:");
                foreach (var rule in scanReport.MatchedRules)
                {
                    sb.AppendLine($"  • {rule}");
                }
            }
            else
            {
                sb.AppendLine("No threats detected");
            }
            sb.AppendLine();

            // PE Analysis Results
            sb.AppendLine("PORTABLE EXECUTABLE ANALYSIS");
            sb.AppendLine("───────────────────────────");
            if (scanReport.HybridResult?.PEAnalysis != null)
            {
                var pe = scanReport.HybridResult.PEAnalysis;
                sb.AppendLine($"PE Validity: {PeValidityText.Text}");
                sb.AppendLine($"Threat Level: {PeThreatLevelText.Text}");
                sb.AppendLine($"PE Score: {PeScoreText.Text}");
                sb.AppendLine($"Digital Signature: {PeSignatureText.Text}");

                if (pe.SuspiciousImports.Any())
                {
                    sb.AppendLine("Suspicious Imports:");
                    foreach (var import in pe.SuspiciousImports)
                    {
                        sb.AppendLine($"  • {import}");
                    }
                }

                if (pe.SectionAnomalies.Any())
                {
                    sb.AppendLine("Section Anomalies:");
                    foreach (var anomaly in pe.SectionAnomalies)
                    {
                        sb.AppendLine($"  • {anomaly}");
                    }
                }
            }
            else
            {
                sb.AppendLine("PE analysis not performed or not applicable");
            }
            sb.AppendLine();

            // Hybrid Analysis Results
            sb.AppendLine("HYBRID ANALYSIS RESULTS");
            sb.AppendLine("──────────────────────");
            if (scanReport.HybridResult != null)
            {
                var hybrid = scanReport.HybridResult;
                sb.AppendLine($"Final Verdict: {HybridFinalVerdictText.Text}");
                sb.AppendLine($"Confidence: {HybridConfidenceText.Text}");
                sb.AppendLine($"Entropy Analysis: {HybridEntropyText.Text}");
                sb.AppendLine($"Size Analysis: {HybridSizeAnalysisText.Text}");

                if (hybrid.CrossAnalysisFindings.Any())
                {
                    sb.AppendLine("Cross-Analysis Findings:");
                    foreach (var finding in hybrid.CrossAnalysisFindings)
                    {
                        sb.AppendLine($"  • {finding}");
                    }
                }
            }
            else
            {
                sb.AppendLine("Hybrid analysis not performed");
            }

            sb.AppendLine();
            sb.AppendLine("====================================================");
            sb.AppendLine($"Report generated by NAZARICK Protocol at {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine("====================================================");

            reportContent = sb.ToString();
        }

        #region Button Event Handlers

        private void ExportReport_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var saveDialog = new SaveFileDialog
                {
                    Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                    DefaultExt = "txt",
                    FileName = $"Analysis_Report_{Path.GetFileNameWithoutExtension(scanReport.FilePath)}_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    File.WriteAllText(saveDialog.FileName, reportContent);
                    MessageBox.Show($"Report exported successfully to:\n{saveDialog.FileName}",
                                  "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error exporting report: {ex.Message}",
                              "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CopyToClipboard_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(reportContent);
                MessageBox.Show("Report content copied to clipboard successfully!",
                              "Copy Successful", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error copying to clipboard: {ex.Message}",
                              "Copy Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        #endregion

        #region Static Methods

        /// <summary>
        /// Shows the full analysis report window for a given scan report
        /// </summary>
        /// <param name="scanReport">The YARA scan report containing all analysis results</param>
        /// <param name="owner">The parent window (optional)</param>
        public static void ShowFullReport(YARAScanReport scanReport, Window owner = null)
        {
            try
            {
                var reportWindow = new FullReportWindow(scanReport);
                if (owner != null)
                {
                    reportWindow.Owner = owner;
                }
                reportWindow.ShowDialog();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error displaying full report: {ex.Message}",
                              "Display Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion
    }
}