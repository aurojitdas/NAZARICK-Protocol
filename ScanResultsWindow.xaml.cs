using NAZARICK_Protocol.service;
using NAZARICK_Protocol.service.Results;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Threading.Tasks;

namespace NAZARICK_Protocol
{
    public partial class ScanResultsWindow : Window
    {
        private List<YARAScanReport> scanReports;
        private ScanWindow parentScanWindow;
        private MainWindow mainWindow;
        private VirusTotalAPI vt;

        public ScanResultsWindow(List<YARAScanReport> reports, ScanWindow parent, MainWindow mainWindow)
        {
            InitializeComponent();
            scanReports = reports ?? new List<YARAScanReport>();
            parentScanWindow = parent;
            this.mainWindow = mainWindow;
            vt = new VirusTotalAPI(this.mainWindow);

            // Load results asynchronously to keep UI responsive
            _ = LoadResultsAsync();
        }

        private async Task LoadResultsAsync()
        {
            // Show loading state
            SummaryText.Text = $"Loading {scanReports.Count} results...";
            ResultsListView.ItemsSource = null;

            // Process data structure in background thread (no UI objects)
            List<dynamic> displayResults = null;
            await Task.Run(() =>
            {
                displayResults = scanReports.Select(r => new
                {
                    FilePath = r.FilePath,
                    IsClean = !(r.isYaraThreatDetected || r.isHybridThreatDetected == true),
                    MatchedRulesCount = r.MatchedRulesCount,
                    ThreatsList = r.MatchedRules.Any() ? string.Join(", ", r.MatchedRules) : "None"
                }).Cast<dynamic>().ToList();
            });

            // Create UI objects on main thread
            var finalDisplayResults = displayResults.Select(r => new
            {
                FilePath = r.FilePath,
                StatusText = r.IsClean ? "CLEAN" : "THREAT",
                StatusBackground = r.IsClean ? new SolidColorBrush(Color.FromRgb(230, 255, 230)) : new SolidColorBrush(Color.FromRgb(255, 230, 230)),
                StatusForeground = r.IsClean ? new SolidColorBrush(Color.FromRgb(40, 167, 69)) : new SolidColorBrush(Color.FromRgb(220, 53, 69)),
                MatchedRulesCount = r.MatchedRulesCount,
                ThreatsList = r.ThreatsList
            }).ToList();

            // Update UI on main thread
            ResultsListView.ItemsSource = finalDisplayResults;
            UpdateSummaryStats();
        }

        private void UpdateSummaryStats()
        {
            // Update summary statistics
            int totalFiles = scanReports.Count;
            int maliciousFiles = scanReports.Count(r => r.isYaraThreatDetected || r.isHybridThreatDetected == true);
            int cleanFiles = totalFiles - maliciousFiles;
            int totalRulesMatched = scanReports.Sum(r => r.MatchedRulesCount);

            // New detection counts
            int yaraDetections = scanReports.Count(r => r.isYaraThreatDetected);
            int hybridDetections = scanReports.Count(r => r.isHybridThreatDetected == true);

            // Update summary text
            SummaryText.Text = $"Total Files: {totalFiles} | Clean: {cleanFiles} | Threats: {maliciousFiles} | YARA: {yaraDetections} | Hybrid: {hybridDetections} | Total Rules Matched: {totalRulesMatched}";

            // Update summary cards
            TotalFilesCount.Text = totalFiles.ToString();
            CleanFilesCount.Text = cleanFiles.ToString();
            ThreatFilesCount.Text = maliciousFiles.ToString();
            YaraDetectionCount.Text = yaraDetections.ToString();
            HybridDetectionCount.Text = hybridDetections.ToString();
            TotalRulesCount.Text = totalRulesMatched.ToString();
        }

        #region Button Handlers

        private void ViewResults_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string filePath)
            {
                // Find the corresponding scan report for this file
                var scanReport = scanReports.FirstOrDefault(r => r.FilePath == filePath);

                if (scanReport != null)
                {
                    // Show the comprehensive full report window
                    FullReportWindow.ShowFullReport(scanReport, this);
                }
                else
                {
                    MessageBox.Show($"No scan results found for:\n{filePath}",
                                  "Results Not Found",
                                  MessageBoxButton.OK,
                                  MessageBoxImage.Information);
                }
            }
        }

        private async void SendHashToVT_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string filePath)
            {
                // Create and show the results window with loading
                var resultsWindow = new VirusTotalResultsWindow();
                resultsWindow.Owner = this;
                resultsWindow.Show();
                resultsWindow.ShowLoading("Checking file hash...");                
                string response = await vt.CheckFileHash(HashCalc.CalculateMd5(filePath));

                if (!string.IsNullOrEmpty(response))
                {
                    mainWindow.LogMessage(response);
                }

                VirusTotalFileAnalysisResults? op = vt.ParseFileAnalysis(response);
                if (op != null)
                {
                    resultsWindow.DisplayAnalysisResult(op);
                }
            }
        }

        private async void SendFileToVT_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string filePath)
            {
                // Create and show the results window with loading
                var resultsWindow = new VirusTotalResultsWindow();
                resultsWindow.Owner = this;
                resultsWindow.Show();
                resultsWindow.ShowLoading("Uploading and analyzing file...");

                string response = await vt.UploadAndAnalyzeFile(filePath);

                if (!string.IsNullOrEmpty(response))
                {
                    VirusTotalFileAnalysisResults? op = vt.ParseFileAnalysis(response);
                    if (op != null)
                    {
                        resultsWindow.DisplayAnalysisResult(op);
                    }
                }
            }
        }

        #endregion

        #region Navigation Button Handlers

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            // Show the parent scan window and close this window
            parentScanWindow?.Show();
            this.Close();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            // Close both windows
            parentScanWindow?.Close();
            this.Close();
        }

        #endregion
    }
}