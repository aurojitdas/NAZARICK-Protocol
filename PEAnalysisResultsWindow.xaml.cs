using System;
using System.IO;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using NAZARICK_Protocol.service.Results;

namespace NAZARICK_Protocol.UI
{
    public partial class PEAnalysisResultsWindow : Window
    {
        public PEAnalysisResultsWindow()
        {
            InitializeComponent();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        public void DisplayAnalysisResult(PEAnalysisResult result)
        {
            if (result == null)
            {
                UpdateSummary("No analysis result", false, 0, 0, "Unknown");
                rtbResults.Document = new FlowDocument(new Paragraph(new Run("No analysis result provided.")));
                return;
            }

            // Update header with file name
            txtTitle.Text = $"PE Analysis - {Path.GetFileName(result.FilePath)}";

            // Update summary section
            UpdateSummary(
                result.IsValidPeFile ? "Valid PE File" : "Invalid PE File",
                result.IsValidPeFile,
                result.SuspiciousImports.Count,
                result.SectionAnomalies.Count,
                GetRiskLevel(result)
            );

            // Update detailed results
            DisplayDetailedResults(result);
        }

        private void UpdateSummary(string fileStatus, bool isValid, int suspiciousCount, int anomaliesCount, string riskLevel)
        {
            // Update file status
            txtFileStatus.Text = fileStatus;
            if (isValid)
            {
                statusIndicator.Fill = new SolidColorBrush(Color.FromRgb(40, 167, 69)); // Green
                txtFileStatus.Foreground = new SolidColorBrush(Color.FromRgb(40, 167, 69));
            }
            else
            {
                statusIndicator.Fill = new SolidColorBrush(Color.FromRgb(220, 53, 69)); // Red
                txtFileStatus.Foreground = new SolidColorBrush(Color.FromRgb(220, 53, 69));
            }

            // Update counts
            txtSuspiciousCount.Text = suspiciousCount.ToString();
            txtAnomaliesCount.Text = anomaliesCount.ToString();

            // Update counts color based on values
            txtSuspiciousCount.Foreground = suspiciousCount > 0 ?
                new SolidColorBrush(Color.FromRgb(255, 90, 90)) :
                new SolidColorBrush(Color.FromRgb(51, 51, 51));

            txtAnomaliesCount.Foreground = anomaliesCount > 0 ?
                new SolidColorBrush(Color.FromRgb(255, 90, 90)) :
                new SolidColorBrush(Color.FromRgb(51, 51, 51));

            // Update risk level
            txtRiskLevel.Text = riskLevel;
            switch (riskLevel.ToLower())
            {
                case "high":
                    txtRiskLevel.Foreground = new SolidColorBrush(Color.FromRgb(220, 53, 69));
                    break;
                case "medium":
                    txtRiskLevel.Foreground = new SolidColorBrush(Color.FromRgb(255, 193, 7));
                    break;
                case "low":
                default:
                    txtRiskLevel.Foreground = new SolidColorBrush(Color.FromRgb(40, 167, 69));
                    break;
            }
        }

        private string GetRiskLevel(PEAnalysisResult result)
        {
            if (!result.IsValidPeFile)
                return "Unknown";

            int totalIssues = result.SuspiciousImports.Count + result.SectionAnomalies.Count;

            if (totalIssues >= 5)
                return "High";
            else if (totalIssues >= 2)
                return "Medium";
            else
                return "Low";
        }

        private void DisplayDetailedResults(PEAnalysisResult result)
        {
            FlowDocument doc = new FlowDocument();
            doc.FontFamily = new FontFamily("Consolas");
            doc.FontSize = 12;
            doc.LineHeight = 18;

            // File Information Section
            AddSection(doc, "File Information", new[]
            {
                $"File Path: {result.FilePath}",
                $"File Name: {Path.GetFileName(result.FilePath)}",
                $"Valid PE File: {(result.IsValidPeFile ? "Yes" : "No")}"
            });

            if (result.IsValidPeFile)
            {
                // Suspicious Imports Section
                if (result.SuspiciousImports.Count > 0)
                {
                    AddSection(doc, $"Suspicious Imports ({result.SuspiciousImports.Count})",
                        result.SuspiciousImports.ToArray(), true);
                }
                else
                {
                    AddSection(doc, "Suspicious Imports", new[] { "No suspicious imports detected." });
                }

                // Section Anomalies
                if (result.SectionAnomalies.Count > 0)
                {
                    AddSection(doc, $"Section Anomalies ({result.SectionAnomalies.Count})",
                        result.SectionAnomalies.ToArray(), true);
                }
                else
                {
                    AddSection(doc, "Section Anomalies", new[] { "No section anomalies detected." });
                }
            }

            // Errors section if any
            if (result.Errors.Count > 0)
            {
                AddSection(doc, "Errors", result.Errors.ToArray(), true);
            }

            rtbResults.Document = doc;
        }

        private void AddSection(FlowDocument doc, string title, string[] items, bool isWarning = false)
        {
            // Section title
            Paragraph titleParagraph = new Paragraph();
            Run titleRun = new Run(title);
            titleRun.FontWeight = FontWeights.Bold;
            titleRun.FontSize = 14;
            titleRun.Foreground = new SolidColorBrush(Color.FromRgb(0, 123, 255));
            titleParagraph.Inlines.Add(titleRun);
            titleParagraph.Margin = new Thickness(0, 15, 0, 8);
            doc.Blocks.Add(titleParagraph);

            // Section items
            foreach (string item in items)
            {
                Paragraph itemParagraph = new Paragraph();
                Run itemRun = new Run($"• {item}");

                if (isWarning)
                {
                    itemRun.Foreground = new SolidColorBrush(Color.FromRgb(220, 53, 69));
                }
                else
                {
                    itemRun.Foreground = new SolidColorBrush(Color.FromRgb(85, 85, 85));
                }

                itemParagraph.Inlines.Add(itemRun);
                itemParagraph.Margin = new Thickness(15, 2, 0, 2);
                doc.Blocks.Add(itemParagraph);
            }
        }

        /// <summary>
        /// Static method to show the analysis results window
        /// </summary>
        /// <param name="result">The PE analysis result to display</param>
        /// <param name="owner">The parent window (optional)</param>
        public static void ShowAnalysisResults(PEAnalysisResult result, Window owner = null)
        {
            var window = new PEAnalysisResultsWindow();
            if (owner != null)
            {
                window.Owner = owner;
            }
            window.DisplayAnalysisResult(result);
            window.ShowDialog();
        }
    }
}