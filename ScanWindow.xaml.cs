using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Threading;
using NAZARICK_Protocol.service.Results;
using System.Diagnostics;

namespace NAZARICK_Protocol
{
    public partial class ScanWindow : Window
    {
        private bool isScanning = false;
        private int filesScanned = 0;
        private int foldersScanned = 0;
        private long dataSizeScanned = 0;
        private int infectedFiles = 0;
        private MainWindow _mainWindow;

        // Store scan results
        private List<YARAScanReport> scanResults = new List<YARAScanReport>();

        // Timing and performance tracking
        private DateTime scanStartTime;
        private List<float> cpuReadings = new List<float>();
        private PerformanceCounter cpuCounter;
        private System.Threading.Thread performanceThread;
        private bool shouldUpdatePerformance = false;

        // Expandable sections state
        private bool statsDetailsExpanded = true;

        public ScanWindow(MainWindow mainWindow)
        {
            _mainWindow = mainWindow;
            InitializeComponent();
            InitializeScan();
            InitializePerformanceTracking();
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

        private void InitializePerformanceTracking()
        {
            try
            {
                // Initialize CPU counter for this scan window
                cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue(); // Prime the counter
                System.Threading.Thread.Sleep(100); // Small delay to let counter stabilize
            }
            catch (Exception ex)
            {
                // Log error but don't fail the scan
                _mainWindow.LogMessage($"[WARNING] CPU monitoring unavailable: {ex.Message}");
                cpuCounter = null;
            }
        }

        private void StartPerformanceMonitoring()
        {
            shouldUpdatePerformance = true;
            performanceThread = new System.Threading.Thread(() =>
            {
                while (shouldUpdatePerformance && isScanning)
                {
                    try
                    {
                        if (scanStartTime != default(DateTime))
                        {
                            // Update elapsed time
                            TimeSpan elapsed = DateTime.Now - scanStartTime;
                            Dispatcher.Invoke(() =>
                            {
                                ElapsedTimeText.Text = $"{elapsed.Minutes:D2}:{elapsed.Seconds:D2}";
                            });

                            // Update CPU usage
                            if (cpuCounter != null)
                            {
                                try
                                {
                                    float cpuUsage = cpuCounter.NextValue();
                                    if (cpuUsage >= 0 && cpuUsage <= 100)
                                    {
                                        cpuReadings.Add(cpuUsage);

                                        if (cpuReadings.Count > 0)
                                        {
                                            float average = 0;
                                            foreach (float reading in cpuReadings)
                                            {
                                                average += reading;
                                            }
                                            average /= cpuReadings.Count;

                                            Dispatcher.Invoke(() =>
                                            {
                                                AvgCpuUsageText.Text = $"{average:F1}%";
                                            });
                                        }
                                    }
                                }
                                catch
                                {
                                    // Ignore CPU reading errors
                                }
                            }
                        }
                    }
                    catch
                    {
                        // Ignore any errors in background thread
                    }

                    // Sleep for 1 second before next update
                    System.Threading.Thread.Sleep(1000);
                }
            })
            {
                IsBackground = true
            };

            performanceThread.Start();
        }

        private void StopPerformanceMonitoring()
        {
            shouldUpdatePerformance = false;
            if (performanceThread != null && performanceThread.IsAlive)
            {
                performanceThread.Join(2000); // Wait up to 2 seconds for thread to finish
            }
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
                scanStartTime = DateTime.Now;
                cpuReadings.Clear();

                ScanStatusText.Text = "Scanning for threats...";
                ScanProgressBar.IsIndeterminate = true;
                StopButton.Content = "Stop Scan";

                // Clear previous results
                scanResults.Clear();
                ShowResultsButton.Visibility = Visibility.Collapsed;

                // Reset UI
                ElapsedTimeText.Text = "00:00";
                AvgCpuUsageText.Text = "0%";

                // Start performance monitoring in background thread
                StartPerformanceMonitoring();
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
        public void AddScanResult(YARAScanReport scanReport)
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

                // Stop performance monitoring
                StopPerformanceMonitoring();

                // Show final elapsed time
                if (scanStartTime != default(DateTime))
                {
                    TimeSpan totalElapsed = DateTime.Now - scanStartTime;
                    ElapsedTimeText.Text = $"{totalElapsed.Minutes:D2}:{totalElapsed.Seconds:D2}";
                }

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

                // Stop performance monitoring
                StopPerformanceMonitoring();

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
                cpuReadings.Clear();
                scanResults.Clear();
                ShowResultsButton.Visibility = Visibility.Collapsed;

                ElapsedTimeText.Text = "00:00";
                AvgCpuUsageText.Text = "0%";

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
            StatsExpandIcon.Text = statsDetailsExpanded ? "▼" : "▲";
            StatsDetailsPanel.Visibility = statsDetailsExpanded ? Visibility.Visible : Visibility.Collapsed;
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

        private void ToggleScanStats_Click(object sender, RoutedEventArgs e)
        {
            statsDetailsExpanded = !statsDetailsExpanded;
            UpdateExpandableIcons();
        }

        private void ShowResultsButton_Click(object sender, RoutedEventArgs e)
        {
            // Hide the scan window
            this.Hide();

            // Open the scan results window
            var resultsWindow = new ScanResultsWindow(scanResults, this, this._mainWindow);
            resultsWindow.Show();
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
            try
            {
                if (isScanning)
                {
                    StopScan();
                }

                // Clean up resources
                StopPerformanceMonitoring();

                if (cpuCounter != null)
                {
                    cpuCounter.Dispose();
                    cpuCounter = null;
                }
            }
            catch (Exception ex)
            {
                _mainWindow.LogMessage($"[WARNING] Cleanup error: {ex.Message}");
            }

            base.OnClosed(e);
        }

        #endregion
    }
}