using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Threading;
using NAZARICK_Protocol.service.Results;

namespace NAZARICK_Protocol
{
    public partial class ScanWindow : Window
    {
        private bool isScanning = false;
        private int filesScanned = 0;
        private int foldersScanned = 0;
        private long dataSizeScanned = 0;
        private int infectedFiles = 0;

        // Store scan results
        private List<FileScanReport> scanResults = new List<FileScanReport>();

        // Expandable sections state
        private bool itemsDetailsExpanded = true;

        public ScanWindow()
        {
            InitializeComponent();
            InitializeScan();
        }

        private void InitializeScan()
        {
            // Initialize UI state
            UpdateScanCounts();
            UpdateExpandableIcons();

            // Set initial state
            ScanStatusText.Text = "Preparing to scan...";
            CurrentFileText.Text = "Initializing scan engine...";
            ScanProgressBar.IsIndeterminate = true;
        }

        #region Public Methods for External Scanning Integration

        /// <summary>
        /// Call this method when starting the scan
        /// </summary>
        public void StartScan()
        {
            Dispatcher.Invoke(() =>
            {
                isScanning = true;
                ScanStatusText.Text = "Scanning for threats...";
                ScanProgressBar.IsIndeterminate = true;
                StopButton.Content = "Stop Scan";

                // Clear previous results
                scanResults.Clear();
                ShowResultsButton.Visibility = Visibility.Collapsed;
            });
        }

        /// <summary>
        /// Update the currently scanned file path
        /// </summary>
        /// <param name="filePath">Full path of the file being scanned</param>
        public void UpdateCurrentFile(string filePath)
        {
            if (!isScanning) return;

            Dispatcher.Invoke(() =>
            {
                CurrentFileText.Text = $"Scanning: {filePath}";
            });
        }

        /// <summary>
        /// Increment the files scanned counter
        /// </summary>
        /// <param name="count">Number of files to add (default: 1)</param>
        public void AddFilesScanned(int count = 1)
        {
            if (!isScanning) return;

            Dispatcher.Invoke(() =>
            {
                filesScanned += count;
                UpdateScanCounts();
            });
        }

        /// <summary>
        /// Increment the folders scanned counter
        /// </summary>
        /// <param name="count">Number of folders to add (default: 1)</param>
        public void AddFoldersScanned(int count = 1)
        {
            if (!isScanning) return;

            Dispatcher.Invoke(() =>
            {
                foldersScanned += count;
                UpdateScanCounts();
            });
        }

        /// <summary>
        /// Add to the total data size scanned
        /// </summary>
        /// <param name="bytes">Number of bytes to add</param>
        public void AddDataScanned(long bytes)
        {
            if (!isScanning) return;

            Dispatcher.Invoke(() =>
            {
                dataSizeScanned += bytes;
                UpdateScanCounts();
            });
        }

        /// <summary>
        /// Report a threat detection
        /// </summary>
        /// <param name="threatName">Name of the detected threat</param>
        /// <param name="filePath">Path of the infected file</param>
        /// <param name="action">Action taken (quarantined, deleted, etc.)</param>
        public void ReportThreatDetected(string threatName, string filePath, string action = "quarantined")
        {
            Dispatcher.Invoke(() =>
            {
                infectedFiles++;
                UpdateScanCounts();

                // Update status to show threat detected
                ScanStatusText.Text = $"Threat detected: {threatName}";
                CurrentFileText.Text = $"Threat found in: {filePath} - {action}";
            });
        }

        /// <summary>
        /// Add a scan result to the results list
        /// </summary>
        /// <param name="scanReport">FileScanReport to add</param>
        public void AddScanResult(FileScanReport scanReport)
        {
            Dispatcher.Invoke(() =>
            {
                scanResults.Add(scanReport);

                // Show results button if we have results
                if (scanResults.Count > 0)
                {
                    ShowResultsButton.Visibility = Visibility.Visible;
                }
            });
        }

        /// <summary>
        /// Update scan progress (0-100)
        /// </summary>
        /// <param name="percentage">Progress percentage (0-100)</param>
        public void UpdateScanProgress(int percentage)
        {
            if (!isScanning) return;

            Dispatcher.Invoke(() =>
            {
                ScanProgressBar.IsIndeterminate = false;
                ScanProgressBar.Value = Math.Max(0, Math.Min(100, percentage));
            });
        }

        /// <summary>
        /// Update scan status message
        /// </summary>
        /// <param name="status">Status message to display</param>
        public void UpdateScanStatus(string status)
        {
            Dispatcher.Invoke(() =>
            {
                ScanStatusText.Text = status;
            });
        }

        /// <summary>
        /// Complete the scan
        /// </summary>
        /// <param name="message">Completion message (optional)</param>
        public void CompleteScan(string message = "Scan completed successfully")
        {
            Dispatcher.Invoke(() =>
            {
                isScanning = false;

                ScanStatusText.Text = message;
                ScanProgressBar.IsIndeterminate = false;
                ScanProgressBar.Value = 100;
                CurrentFileText.Text = message;
                ProgressSection.Visibility = Visibility.Collapsed;

                // Update button state
                StopButton.Content = "Close";
            });
        }

        /// <summary>
        /// Stop the scan
        /// </summary>
        public void StopScan()
        {
            Dispatcher.Invoke(() =>
            {
                isScanning = false;
                ScanStatusText.Text = "Scan stopped by user";
                ScanProgressBar.IsIndeterminate = false;
                CurrentFileText.Text = "Scan stopped";
                StopButton.Content = "Close";
            });
        }

        /// <summary>
        /// Reset all scan counters
        /// </summary>
        public void ResetScanCounters()
        {
            Dispatcher.Invoke(() =>
            {
                filesScanned = 0;
                foldersScanned = 0;
                dataSizeScanned = 0;
                infectedFiles = 0;
                scanResults.Clear();
                ShowResultsButton.Visibility = Visibility.Collapsed;

                UpdateScanCounts();
            });
        }

        /// <summary>
        /// Check if scan is currently running
        /// </summary>
        public bool IsScanRunning => isScanning;

        #endregion

        #region Private Helper Methods

        private void UpdateScanCounts()
        {
            // Update totals
            int totalItems = filesScanned + foldersScanned;
            TotalItemsText.Text = totalItems.ToString("N0");
            FilesCountText.Text = filesScanned.ToString("N0");
            FoldersCountText.Text = foldersScanned.ToString("N0");

            // Convert bytes to readable format
            string dataSize = FormatBytes(dataSizeScanned);
            DataSizeText.Text = dataSize;

            InfectedFilesText.Text = infectedFiles.ToString();

            // Update infected files color
            if (infectedFiles > 0)
            {
                InfectedFilesText.Foreground = System.Windows.Media.Brushes.Red;
            }
        }

        private string FormatBytes(long bytes)
        {
            if (bytes == 0) return "0 B";

            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.#} {sizes[order]}";
        }

        private void UpdateExpandableIcons()
        {
            ItemsExpandIcon.Text = itemsDetailsExpanded ? "▼" : "▲";
            ItemsDetailsPanel.Visibility = itemsDetailsExpanded ? Visibility.Visible : Visibility.Collapsed;
        }

        #endregion

        #region Event Handlers

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            if (isScanning)
            {
                var result = MessageBox.Show("Scan is still running. Do you want to stop it and close?",
                                           "Scan in Progress", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    StopScan();
                    this.Close();
                }
            }
            else
            {
                this.Close();
            }
        }

        private void ToggleItemsScanned_Click(object sender, RoutedEventArgs e)
        {
            itemsDetailsExpanded = !itemsDetailsExpanded;
            UpdateExpandableIcons();
        }

        private void ShowResultsButton_Click(object sender, RoutedEventArgs e)
        {
            // Open the scan results window
            var resultsWindow = new ScanResultsWindow(scanResults);
            resultsWindow.Owner = this;
            resultsWindow.ShowDialog();
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            if (isScanning)
            {
                var result = MessageBox.Show("Are you sure you want to stop the scan?",
                                           "Stop Scan", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    StopScan();
                }
            }
            else
            {
                this.Close();
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            if (isScanning)
            {
                StopScan();
            }
            base.OnClosed(e);
        }

        #endregion
    }
}