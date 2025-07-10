using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
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
            // Create display objects for the ListView
            var displayResults = scanReports.Select(r => new
            {
                FilePath = r.FilePath,
                StatusText = r.IsMalicious ? "THREAT" : "CLEAN",
                MatchedRulesCount = r.MatchedRulesCount,
                ThreatsList = r.MatchedRules.Any() ? string.Join(", ", r.MatchedRules) : "None"
            }).ToList();

            // Set the ListView data source
            ResultsListView.ItemsSource = displayResults;

            // Update summary
            int totalFiles = scanReports.Count;
            int maliciousFiles = scanReports.Count(r => r.IsMalicious);
            int cleanFiles = totalFiles - maliciousFiles;
            int totalRulesMatched = scanReports.Sum(r => r.MatchedRulesCount);

            SummaryText.Text = $"Total Files: {totalFiles} | Clean: {cleanFiles} | Threats: {maliciousFiles} | Total Rules Matched: {totalRulesMatched}";
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}