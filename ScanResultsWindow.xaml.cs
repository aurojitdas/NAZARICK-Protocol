using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using NAZARICK_Protocol.service.Results;

namespace NAZARICK_Protocol
{
    public partial class ScanResultsWindow : Window
    {
        private List<FileScanReport> scanReports;

        public ScanResultsWindow(List<FileScanReport> reports)
        {
            InitializeComponent();
            scanReports = reports ?? new List<FileScanReport>();
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

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}