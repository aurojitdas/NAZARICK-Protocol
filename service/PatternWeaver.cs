using dnYara;
using dnYara.Interop;
using MS.WindowsAPICodePack.Internal;
using NAZARICK_Protocol.service.Results;
using NAZARICK_Protocol.UI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace NAZARICK_Protocol.service
{
    internal class PatternWeaver
    {
        YaraContext? context;
        Compiler? compiler;
        CompiledRules? rules;
        Scanner? scanner;
        MainWindow mainWindow;
        private ScanWindow currentScanWindow;
        private VirusTotalAPI vt;
        PEAnalyzer Pe;
        FileScanReport scanReport;
        private CancellationTokenSource cancellationTokenSource;

        public PatternWeaver(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
            vt = new VirusTotalAPI("68d9e1716c7df15e701bcce1addafd4231c2d288c5869726ecb9a31ff28ba878", this.mainWindow);
        }

        public async Task<String> initialize_YARA()
        {
            try
            {
                mainWindow.LogMessage("Initializing YARA Compiler!!...");
                context = new YaraContext();
                compiler = new Compiler();
                mainWindow.LogMessage("YARA Compiler initialization SUCCESS!!...");

                // Make rule loading async to prevent UI freezing
                await addRuleFilesAsync("rules\\");
                await compileRulesAsync();

                Pe = new PEAnalyzer();
                return "YARA Initialized Successfully";
            }
            catch (Exception ex)
            {
                mainWindow.LogMessage($"YARA initialization failed: {ex.Message}");
                return $"YARA initialization failed: {ex.Message}";
            }
        }

        public async Task addRuleFilesAsync(String folder_path)
        {
            int rules_no = 0;
            string absoluteFolderPath = Path.GetFullPath(folder_path);

            if (!Directory.Exists(folder_path))
            {
                mainWindow.LogMessage($"Error: Folder '{absoluteFolderPath}' does not exist.");
                return;
            }

            try
            {
                var ruleFiles = Directory.EnumerateFiles(absoluteFolderPath, "*.yar", SearchOption.AllDirectories)
                                        .Concat(Directory.EnumerateFiles(absoluteFolderPath, "*.yara", SearchOption.AllDirectories))
                                        .ToList();

                if (!ruleFiles.Any())
                {
                    mainWindow.LogMessage($"No YARA rule files (*.yar, *.yara) found in '{absoluteFolderPath}'.");
                    return;
                }

                mainWindow.LogMessage($"Found {ruleFiles.Count} rule files. Loading...");

                // Processing rules in batches to prevent memory issues
                const int batchSize = 50;
                int totalBatches = (int)Math.Ceiling((double)ruleFiles.Count / batchSize);

                for (int batchIndex = 0; batchIndex < totalBatches; batchIndex++)
                {
                    var batch = ruleFiles.Skip(batchIndex * batchSize).Take(batchSize);

                    foreach (var ruleFile in batch)
                    {
                        try
                        {
                            if (compiler != null)
                            {
                                // Add progress reporting
                                mainWindow.LogMessage($"Loading rule file {rules_no + 1}/{ruleFiles.Count}: {Path.GetFileName(ruleFile)}");

                                // Validate rule file before adding
                                if (await IsValidRuleFileAsync(ruleFile))
                                {
                                    if (compiler != null)
                                    {
                                        compiler.AddRuleFile(ruleFile);
                                        rules_no++;
                                    }                                    
                                }
                                else
                                {
                                    mainWindow.LogMessage($"Skipping invalid rule file: {ruleFile}");
                                }
                            }
                            else
                            {
                                mainWindow.LogMessage("Compiler init error!!...");
                                return;
                            }
                        }
                        catch (Exception ex)
                        {
                            mainWindow.LogMessage($"Error adding rule file '{ruleFile}': {ex.Message}");
                            // Continueing with other files instead of failing completely
                        }
                    }

                    // UI to update between batches
                    await Task.Delay(10);

                    // Update progress
                    mainWindow.Dispatcher.Invoke(() =>
                    {
                        mainWindow.YaraRulesCountText.Text = $"Rules loaded: {rules_no}/{ruleFiles.Count}";
                    });
                }

                mainWindow.LogMessage($"All rule files processed. Loaded {rules_no} rules successfully.");
            }
            catch (Exception ex)
            {
                mainWindow.LogMessage($"An unexpected error occurred during rule loading: {ex.Message}");
            }
        }

        private async Task<bool> IsValidRuleFileAsync(string ruleFile)
        {
            try
            {
                // Basic validation - check if file exists and is readable
                if (!File.Exists(ruleFile))
                    return false;

                // Check file size 
                var fileInfo = new FileInfo(ruleFile);
                if (fileInfo.Length > 10 * 1024 * 1024) // 10MB limit
                {
                    mainWindow.LogMessage($"Skipping large rule file: {ruleFile} ({fileInfo.Length / 1024 / 1024}MB)");
                    return false;
                }

                // Quick syntax check 
                var content = await File.ReadAllTextAsync(ruleFile);
                return content.Contains("rule ") && !string.IsNullOrWhiteSpace(content);
            }
            catch
            {
                return false;
            }
        }

        public async Task compileRulesAsync()
        {
            try
            {
                mainWindow.LogMessage("Compiling YARA rules... This may take a while for large rule sets.");

                // Running compilation in a separate task to prevent UI blocking
                await Task.Run(() =>
                {
                    if (rules!=null)
                    {
                        rules = compiler.Compile();
                    }
                   
                });

                mainWindow.Dispatcher.Invoke(() =>
                {
                    mainWindow.YaraRulesStatusText.Text = "Compiled successfully";
                });

                mainWindow.LogMessage("YARA rules Compilation SUCCESS!!...");
            }
            catch (Exception ex)
            {
                mainWindow.LogMessage($"YARA rules compilation failed: {ex.Message}");
                throw;
            }
        }

        // Adding method to compile rules with progress reporting
        public async Task compileRulesWithProgressAsync(IProgress<string> progress = null)
        {
            try
            {
                progress?.Report("Starting compilation...");
                mainWindow.LogMessage("Compiling YARA rules... This may take a while for large rule sets.");

                cancellationTokenSource = new CancellationTokenSource();

                await Task.Run(() =>
                {
                    try
                    {
                        rules = compiler.Compile();
                    }
                    catch (Exception ex)
                    {
                        progress?.Report($"Compilation error: {ex.Message}");
                        throw;
                    }
                }, cancellationTokenSource.Token);

                progress?.Report("Compilation completed successfully");

                mainWindow.Dispatcher.Invoke(() =>
                {
                    mainWindow.YaraRulesStatusText.Text = "Compiled successfully";
                });

                mainWindow.LogMessage("YARA rules Compilation SUCCESS!!...");
            }
            catch (OperationCanceledException)
            {
                mainWindow.LogMessage("YARA rules compilation was cancelled.");
                throw;
            }
            catch (Exception ex)
            {
                mainWindow.LogMessage($"YARA rules compilation failed: {ex.Message}");
                throw;
            }
        }

        // Adding method to cancel operations
        public void CancelOperation()
        {
            cancellationTokenSource?.Cancel();
        }

        // Optimizing memory usage during scanning
        public async Task scanFile(String file_path)
        {
            ShowScanWindow(mainWindow);
            List<ScanResult> scanResults = null;

            if (file_path != null)
            {
                try
                {
                    if (scanner == null)
                    {
                        scanner = new Scanner();
                    }

                    mainWindow.LogMessage("Scanning !!...");
                    currentScanWindow.UpdateCurrentFile(file_path);

                    // Runing scan in background thread
                    scanResults = await Task.Run(() => scanner.ScanFile(file_path, rules));

                    currentScanWindow.AddFilesScanned();

                    // scan report and add to scan window
                    FileScanReport scanReport = new FileScanReport(file_path, scanResults);
                    currentScanWindow.AddScanResult(scanReport);

                    mainWindow.LogMessage("Scan SUCCESS!!...");
                    currentScanWindow.CompleteScan();
                    displayScanResults(scanResults, file_path);
                }
                catch (Exception ex)
                {
                    mainWindow.LogMessage($"Scan error: {ex.Message}");
                    currentScanWindow?.CompleteScan();
                }
            }
            else
            {
                mainWindow.LogMessage("Scan Cancelled!!...");
            }
        }

        public async Task scanFiles(List<String> files)
        {
            ShowScanWindow(mainWindow);

            if (files != null)
            {
                try
                {
                    if (scanner == null)
                    {
                        scanner = new Scanner();
                    }

                    mainWindow.LogMessage("Scanning !!...");

                    foreach (string file in files)
                    {
                        currentScanWindow.UpdateCurrentFile(file);

                        // Running each scan in background to prevent UI freezing
                        var scanResults = await Task.Run(() => scanner.ScanFile(file, rules));

                        currentScanWindow.AddFilesScanned();
                        scanReport = new FileScanReport(file, scanResults);
                        currentScanWindow.AddScanResult(scanReport);
                        displayScanResults(scanResults, file);

                        // Small delay to allow UI updates
                        await Task.Delay(10);
                    }

                    currentScanWindow.CompleteScan();
                    mainWindow.LogMessage("Scan SUCCESS!!...");
                }
                catch (Exception ex)
                {
                    mainWindow.LogMessage($"Scan error: {ex.Message}");
                    currentScanWindow?.CompleteScan();
                }
            }
            else
            {
                mainWindow.LogMessage("Scan Cancelled!!...");
            }
        }

        public void cleanup()
        {
            try
            {
                mainWindow.LogMessage("Cleaning up YARA resources...\n");

                // Canceling any ongoing operations
                if (cancellationTokenSource != null && !cancellationTokenSource.IsCancellationRequested)
                {
                    cancellationTokenSource.Cancel();
                    mainWindow.LogMessage("Cancellation requested for ongoing operations.\n");
                }

                // Waiting briefly for operations to cancel
                Thread.Sleep(300);

                // Waiting briefly for operations to cancel
               // Thread.Sleep(200);

                // Dispose scanner 
                if (scanner != null)
                {
                    try
                    {
                        scanner = null;
                        mainWindow.LogMessage("Scanner disposed.\n");
                    }
                    catch (Exception ex)
                    {
                        mainWindow.LogMessage($"Warning: Scanner disposal error: {ex.Message}\n");
                    }
                }

                // Dispose compiled rules 
                if (rules != null)
                {
                    try
                    {
                        rules.Dispose();
                        rules = null;
                        mainWindow.LogMessage("Compiled rules disposed.\n");
                    }
                    catch (Exception ex)
                    {
                        mainWindow.LogMessage($"Warning: Rules disposal error: {ex.Message}\n");
                    }
                }

                // Dispose compiler 
                if (compiler != null)
                {
                    try
                    {
                        compiler.Dispose();
                        compiler = null;
                        mainWindow.LogMessage("Compiler disposed.\n");
                    }
                    catch (Exception ex)
                    {
                        mainWindow.LogMessage($"Warning: Compiler disposal error: {ex.Message}\n");
                    }
                }

                // Dispose YARA context 
                if (context != null)
                {
                    try
                    {
                        context.Dispose();
                        context = null;
                        mainWindow.LogMessage("YARA Context disposed.\n");
                    }
                    catch (Exception ex)
                    {
                        mainWindow.LogMessage($"Warning: Context disposal error: {ex.Message}\n");
                    }
                }

                // Dispose cancellation token source
                try
                {
                    cancellationTokenSource?.Dispose();
                    cancellationTokenSource = null;
                }
                catch (Exception ex)
                {
                    mainWindow.LogMessage($"Warning: CancellationTokenSource disposal error: {ex.Message}\n");
                }

                mainWindow.LogMessage("YARA cleanup complete.\n");
                mainWindow.ScanInfoTextBox?.ScrollToEnd();
            }
            catch (Exception ex)
            {
                // Catch any unexpected errors during cleanup
                mainWindow.LogMessage($"Error during YARA cleanup: {ex.Message}\n");
            }
        }

        private void displayScanResults(List<ScanResult> scanResults, string filepath)
        {
            if (scanResults != null && scanResults.Count > 0)
            {
                mainWindow.LogMessage($"--- THREATS DETECTED IN {Path.GetFileName(filepath)} ---\n");
                foreach (var result in scanResults)
                {
                    mainWindow.LogMessage($"Rule matched: {result.MatchingRule.Identifier}\n");
                    mainWindow.ReportThreatDetected(result.MatchingRule.Identifier, filepath);
                    currentScanWindow.ReportThreatDetected(result.MatchingRule.Identifier, filepath);
                }
                mainWindow.LogMessage($"Total rules matched: {scanResults.Count}\n");
            }
            else
            {
                mainWindow.LogMessage("No threats detected.\n");
            }
        }

        private void ShowScanWindow(MainWindow mainWindow)
        {
            currentScanWindow = new ScanWindow(mainWindow);
            currentScanWindow.Show();
            currentScanWindow.StartScan();
        }

        private void ShowPEAnalysisResults(PEAnalysisResult analysisResult)
        {
            PEAnalysisResultsWindow.ShowAnalysisResults(analysisResult, this.mainWindow);
        }
    }
}