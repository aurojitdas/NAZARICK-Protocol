using NAZARICK_Protocol.service;
using NAZARICK_Protocol.service.Results;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace NAZARICK_Protocol
{
    public partial class ScanResultsWindow : Window
    {
        private List<FileScanReport> scanReports;
        private ScanWindow parentScanWindow;
        private MainWindow mainWindow;
        private VirusTotalAPI vt;

        public ScanResultsWindow(List<FileScanReport> reports, ScanWindow parent, MainWindow mainWindow)
        {
            InitializeComponent();
            scanReports = reports ?? new List<FileScanReport>();
            parentScanWindow = parent;
            this.mainWindow = mainWindow;
            vt = new VirusTotalAPI("68d9e1716c7df15e701bcce1addafd4231c2d288c5869726ecb9a31ff28ba878", this.mainWindow);           
            LoadResults();
        }

        private void LoadResults()
        {
            // Creates display objects for the ListView with styling
            var displayResults = scanReports.Select(r => new
            {
                FilePath = r.FilePath,
                StatusText = r.IsMalicious ? "THREAT" : "CLEAN",
                StatusBackground = r.IsMalicious ? new SolidColorBrush(Color.FromRgb(255, 230, 230)) : new SolidColorBrush(Color.FromRgb(230, 255, 230)),
                StatusForeground = r.IsMalicious ? new SolidColorBrush(Color.FromRgb(220, 53, 69)) : new SolidColorBrush(Color.FromRgb(40, 167, 69)),
                MatchedRulesCount = r.MatchedRulesCount,
                ThreatsList = r.MatchedRules.Any() ? string.Join(", ", r.MatchedRules) : "None"
            }).ToList();

            // Sets the ListView data source
            ResultsListView.ItemsSource = displayResults;

            // Update summary statistics
            int totalFiles = scanReports.Count;
            int maliciousFiles = scanReports.Count(r => r.IsMalicious);
            int cleanFiles = totalFiles - maliciousFiles;
            int totalRulesMatched = scanReports.Sum(r => r.MatchedRulesCount);

            // Update summary text
            SummaryText.Text = $"Total Files: {totalFiles} | Clean: {cleanFiles} | Threats: {maliciousFiles} | Total Rules Matched: {totalRulesMatched}";

            // Update summary cards
            TotalFilesCount.Text = totalFiles.ToString();
            CleanFilesCount.Text = cleanFiles.ToString();
            ThreatFilesCount.Text = maliciousFiles.ToString();
            TotalRulesCount.Text = totalRulesMatched.ToString();
        }

        #region VirusTotal Button Handlers

        private async void SendHashToVT_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string filePath)
            {
                // Dummy code for sending hash to VirusTotal
                //MessageBox.Show($"Sending file hash to VirusTotal for:\n{filePath}",
                //               "Hash to VirusTotal",
                //               MessageBoxButton.OK,
                //               MessageBoxImage.Information);
                string response = //await vt.UploadAndAnalyzeFile(file_path);
                await vt.CheckFileHash("fe115f0be1c1ffd7176b8e1b1f88a41b");
                if (!string.IsNullOrEmpty(response))
                {
                    mainWindow.LogMessage(response);
                }
                VirusTotalFileAnalysisResults? op = vt.ParseFileAnalysis(response);
                if (op != null)
                {
                    ShowVirusTotalAnalysisResults(op);
                }
            }
        }

        private async void SendFileToVT_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string filePath)
            {
                string response = await vt.UploadAndAnalyzeFile(filePath);
                
                if (!string.IsNullOrEmpty(response))
                {
                    VirusTotalFileAnalysisResults? op = vt.ParseFileAnalysis(response);
                    if (op != null)
                    {
                        ShowVirusTotalAnalysisResults(op);
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
        private void ShowVirusTotalAnalysisResults(VirusTotalFileAnalysisResults analysisResult)
        {
            VirusTotalResultsWindow.ShowAnalysisResults(analysisResult, this.mainWindow);
        }
    }
}