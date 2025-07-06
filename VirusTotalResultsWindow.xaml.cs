using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using NAZARICK_Protocol.service;

namespace NAZARICK_Protocol
{
    public partial class VirusTotalResultsWindow : Window
    {
        private VirusTotalFileAnalysisResults _analysis;

        public VirusTotalResultsWindow()
        {
            InitializeComponent();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void BtnViewReport_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(_analysis?.Permalink))
            {
                try
                {
                    Process.Start(new ProcessStartInfo(_analysis.Permalink) { UseShellExecute = true });
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Unable to open browser: {ex.Message}", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }

        private void Permalink_Click(object sender, MouseButtonEventArgs e)
        {
            BtnViewReport_Click(sender, null);
        }

        public void DisplayAnalysisResult(VirusTotalFileAnalysisResults analysis)
        {
            if (analysis == null)
            {
                UpdateDisplay("No analysis result", 0, 0, 0, 0, "Unknown");
                //txtAnalysisDetails.Text = "No VirusTotal analysis result provided.";
                return;
            }

            _analysis = analysis;

            // Update header with file name
            txtTitle.Text = $"VirusTotal Analysis - {analysis.MeaningfulName ?? "Unknown File"}";

            // Calculate clean count
            int cleanCount = analysis.TotalScans - analysis.MaliciousDetections - analysis.SuspiciousDetections;
            if (cleanCount < 0) cleanCount = 0;

            // Update summary section
            UpdateDisplay(
                analysis.MeaningfulName ?? "Unknown File",
                analysis.MaliciousDetections,
                analysis.SuspiciousDetections,
                cleanCount,
                analysis.TotalScans,
                GetThreatLevel(analysis)
            );

            // Update file information
            UpdateFileInformation(analysis);
        }

        private void UpdateDisplay(string fileName, int malicious, int suspicious, int clean, int total, string threatLevel)
        {
            // Update detection counts
            txtMaliciousCount.Text = malicious.ToString();
            txtSuspiciousCount.Text = suspicious.ToString();
            txtCleanCount.Text = clean.ToString();
            txtTotalEngines.Text = total.ToString();

            // Update threat level and indicator
            txtThreatLevel.Text = threatLevel;
            UpdateThreatIndicator(threatLevel);
        }

        private void UpdateThreatIndicator(string threatLevel)
        {
            switch (threatLevel.ToLower())
            {
                case "high risk":
                case "malicious":
                    threatIndicator.Fill = new SolidColorBrush(Color.FromRgb(220, 53, 69)); // Red
                    txtThreatLevel.Foreground = new SolidColorBrush(Color.FromRgb(220, 53, 69));
                    break;
                case "medium risk":
                case "suspicious":
                    threatIndicator.Fill = new SolidColorBrush(Color.FromRgb(255, 193, 7)); // Yellow
                    txtThreatLevel.Foreground = new SolidColorBrush(Color.FromRgb(255, 193, 7));
                    break;
                case "clean":
                case "low risk":
                default:
                    threatIndicator.Fill = new SolidColorBrush(Color.FromRgb(40, 167, 69)); // Green
                    txtThreatLevel.Foreground = new SolidColorBrush(Color.FromRgb(40, 167, 69));
                    break;
            }
        }

        private string GetThreatLevel(VirusTotalFileAnalysisResults analysis)
        {
            if (analysis.IsMalicious || analysis.MaliciousDetections > 0)
                return "Malicious";
            else if (analysis.SuspiciousDetections > 0)
                return "Suspicious";
            else if (analysis.TotalScans > 0)
                return "Clean";
            else
                return "Unknown";
        }

        private void UpdateFileInformation(VirusTotalFileAnalysisResults analysis)
        {
            txtFileName.Text = analysis.MeaningfulName ?? "Unknown";
            txtFileSize.Text = FormatFileSize(analysis.FileSize);
            txtLastAnalysis.Text = analysis.LastAnalysisDate != default(DateTime)
                ? analysis.LastAnalysisDate.ToString("yyyy-MM-dd HH:mm:ss UTC")
                : "Not available";

            // Update threat classification
            if (!string.IsNullOrEmpty(analysis.ThreatLabel))
            {
                txtThreatLabel.Text = analysis.ThreatLabel;
                txtThreatLabel.Foreground = new SolidColorBrush(Color.FromRgb(220, 53, 69)); // Red for threats
            }
            else
            {
                txtThreatLabel.Text = analysis.IsMalicious ? "Malware Detected" : "No Classification";
                txtThreatLabel.Foreground = analysis.IsMalicious
                    ? new SolidColorBrush(Color.FromRgb(220, 53, 69))
                    : new SolidColorBrush(Color.FromRgb(40, 167, 69));
            }

            txtSha256.Text = analysis.Sha256 ?? "Not available";
            txtMd5.Text = analysis.Md5 ?? "Not available";

            // Handle permalink visibility
            if (!string.IsNullOrEmpty(analysis.Permalink))
            {
                txtPermalink.Visibility = Visibility.Visible;
                btnViewReport.IsEnabled = true;
            }
            else
            {
                txtPermalink.Text = "Not available";
                txtPermalink.Foreground = new SolidColorBrush(Color.FromRgb(102, 102, 102));
                txtPermalink.TextDecorations = null;
                txtPermalink.Cursor = Cursors.Arrow;
                btnViewReport.IsEnabled = false;
            }
        }

        private string FormatFileSize(long bytes)
        {
            if (bytes == 0) return "Unknown";

            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;

            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }

            return $"{len:0.##} {sizes[order]}";
        }

        /// <summary>
        /// method to show the VirusTotal analysis results window
        /// </summary>
        /// <param name="analysis">The VirusTotal analysis result to display</param>
        /// <param name="owner">The parent window (optional)</param>
        public static void ShowAnalysisResults(VirusTotalFileAnalysisResults analysis, Window owner = null)
        {
            var window = new VirusTotalResultsWindow();
            if (owner != null)
            {
                window.Owner = owner;
            }
            window.DisplayAnalysisResult(analysis);
            window.ShowDialog();
        }
    }
}