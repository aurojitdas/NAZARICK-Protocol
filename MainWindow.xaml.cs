using Microsoft.Win32;
using Microsoft.WindowsAPICodePack.Dialogs;
using NAZARICK_Protocol.service;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;
using System.IO;

namespace NAZARICK_Protocol
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        PatternWeaver? pw;
        private DispatcherTimer systemTimer;
        private int filesScannedToday = 0;
        private int threatsBlockedToday = 0;

        public MainWindow()
        {
            InitializeComponent();
            this.Closed += MainWindow_Closed;
            pw = new PatternWeaver(this);

            InitializeSystem();
            StartSystemMonitoring();
        }

        private void InitializeSystem()
        {
            LogMessage("[INFO] N.A.Z.A.R.I.C.K. Protocol starting...");
            LogMessage("[INFO] Initializing YARA engine...");

            string yaraResult = pw.initialize_YARA();
            LogMessage($"[INFO] {yaraResult}");

            // Update UI elements
            YaraRulesStatusText.Text = "Loaded successfully";
            YaraRulesCountText.Text = "Rules loaded: Unknown"; // You can update this with actual count
            LastUpdateText.Text = DateTime.Now.ToString("yyyy-MM-dd HH:mm");

            
        }

        private void StartSystemMonitoring()
        {
            systemTimer = new DispatcherTimer();
            systemTimer.Interval = TimeSpan.FromSeconds(5);
            systemTimer.Tick += UpdateSystemInfo;
            systemTimer.Start();
        }

        private void UpdateSystemInfo(object sender, EventArgs e)
        {
            // Simulate system monitoring (replace with actual system calls)
            Random rand = new Random();

            // Update CPU usage
            int cpuUsage = rand.Next(10, 80);
            CpuUsageBar.Value = cpuUsage;
            CpuUsageText.Text = $"{cpuUsage}%";

            // Update Memory usage
            int memoryUsage = rand.Next(40, 90);
            MemoryUsageBar.Value = memoryUsage;
            MemoryUsageText.Text = $"{memoryUsage}%";

            // Update counters
            FilesScannedText.Text = filesScannedToday.ToString();
            ThreatsBlockedText.Text = threatsBlockedToday.ToString();
        }

        public void LogMessage(string message)
        {
            Dispatcher.Invoke(() =>
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss");
                string logEntry = $"[{timestamp}] {message}\n";
                LogsTextBox.AppendText(logEntry);
                LogsTextBox.ScrollToEnd();
            });
        }        

        public void ReportThreatDetected(string threatName, string filePath)
        {
            Dispatcher.Invoke(() =>
            {
                threatsBlockedToday++;
                ThreatsDetectedText.Text = threatsBlockedToday.ToString();

                LogMessage($"[ALERT] Threat detected: {threatName}");
                LogMessage($"[ALERT] File: {filePath}");
                LogMessage($"[INFO] File quarantined successfully");

                // Update system status
                SystemStatusIndicator.Fill = new SolidColorBrush(Colors.Orange);
                SystemStatusText.Text = "Threat detected - Action required";
            });
        }

        private void NavigationTab_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton radioButton && radioButton.Tag is string tag)
            {
                // Hide all pages
                HomePage.Visibility = Visibility.Collapsed;
                ScanPage.Visibility = Visibility.Collapsed;
                SettingsPage.Visibility = Visibility.Collapsed;
                InfoPage.Visibility = Visibility.Collapsed;
                AboutPage.Visibility = Visibility.Collapsed;

               
                switch (tag)
                {
                    case "Home":
                        HomePage.Visibility = Visibility.Visible;
                        break;
                    case "Scan":
                        ScanPage.Visibility = Visibility.Visible;
                        break;
                    case "Settings":
                        SettingsPage.Visibility = Visibility.Visible;                        
                        break;
                    case "Info":
                        InfoPage.Visibility = Visibility.Visible;                        
                        break;
                    case "About":
                        AboutPage.Visibility = Visibility.Visible;                        
                        break;
                }
            }
        }

        private async void MainScanButton_Click(object sender, RoutedEventArgs e)
        {
            LogMessage("[INFO] Starting quick scan...");

            // Update scan info
            ScanInfoTextBox.Text = "Starting quick scan...\n";

            try
            {   ScanInfoTextBox.AppendText(pw.initialize_YARA() + "\n");
                string filePath = getFilePath();
                if (!string.IsNullOrEmpty(filePath))
                {
                    //LogMessage($"[INFO] Scanning file: {filePath}");
                    pw.scanFile(filePath);
                    filesScannedToday++;
                }               
            }
            catch (Exception ex)
            {
                LogMessage($"[ERROR] Scan failed: {ex.Message}");                
                ScanInfoTextBox.AppendText($"Error: {ex.Message}\n");
            }
        }

        private void ChangeRulesButton_Click(object sender, RoutedEventArgs e)
        {
            LogMessage("[INFO] Opening rules folder selection dialog...");

            String rulesFolder = rulesFolderSelect();
            if (rulesFolder != null)
            {
                LogMessage($"[INFO] Rules folder selected: {rulesFolder}");
                MessageBox.Show("Selected Folder: " + rulesFolder,
                                          "Scan Rules",
                                          MessageBoxButton.OK,
                                          MessageBoxImage.Information);
            }
            else
            {
                LogMessage("[INFO] Rules selection cancelled by user");
                MessageBox.Show("Rules Selection Cancelled",
                                          "Scan Rules",
                                          MessageBoxButton.OK,
                                          MessageBoxImage.Information);
            }
        }

        public String getFilePath()
        {
            String? file_Path = null;
            LogMessage("[INFO] Opening file selection dialog...");

            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "All files (*.*)|*.*|Executable files (*.exe)|*.exe|Text files (*.txt)|*.txt";
            openFileDialog.Title = "Select file to scan";

            bool? result = openFileDialog.ShowDialog();
            if (result == true)
            {
                file_Path = openFileDialog.FileName;
                LogMessage($"[INFO] File selected for scanning: {file_Path}");
                ScanInfoTextBox.Text = file_Path;
            }
            else
            {
                LogMessage("[INFO] File selection cancelled by user");
                ScanInfoTextBox.Text = "File Selection Cancelled\n";
            }
            return file_Path;
        }

        public String rulesFolderSelect()
        {
            String? folder_Path = null;
            CommonOpenFileDialog dialog = new CommonOpenFileDialog();
            dialog.IsFolderPicker = true;
            dialog.Title = "Select YARA Rules Folder";

            CommonFileDialogResult result = dialog.ShowDialog();
            if (result == CommonFileDialogResult.Ok)
            {
                folder_Path = dialog.FileName;
                LogMessage($"[INFO] Rules folder selected: {folder_Path}");
                ScanInfoTextBox.Text = folder_Path;
            }
            else
            {
                LogMessage("[INFO] Rules folder selection cancelled");
                ScanInfoTextBox.Text = "Folder selection cancelled.";
            }

            return folder_Path;
        }
        
        private void MainWindow_Closed(object sender, EventArgs e)
        {
            LogMessage("[INFO] Shutting down N.A.Z.A.R.I.C.K. Protocol...");

            systemTimer?.Stop();

            if (pw != null)
            {
                pw.cleanup();
                LogMessage("[INFO] YARA engine cleanup completed");
            }

            LogMessage("[INFO] Application shutdown complete");
            Application.Current.Shutdown();
        }
    }
}