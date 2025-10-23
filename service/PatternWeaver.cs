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
        PEAnalyzer Pe;
        YARAScanReport scanReport;

        public PatternWeaver(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
           
        }
        public String initialize_YARA()
        {
            mainWindow.LogMessage("Initializing YARA Compiler!!...");
            context = new YaraContext();
            compiler = new Compiler();
            mainWindow.LogMessage("YARA Compiler initialization SUCCESS!!...");            
            addRuleFiles("rules\\");
            compileRules();
            Pe = new PEAnalyzer();
            //scanFile("C:\\Windows\\System32\\notepad.exe");
            //cleanup();
            return "YARA Initialized Succesfully";
        }

        public void addRuleFiles(String folder_path)
        {
            int rules_no = 0;
            string absoluteFolderPath = Path.GetFullPath(folder_path);
            if (!Directory.Exists(folder_path))
            {
                mainWindow.LogMessage($"Error: Folder '{absoluteFolderPath}' does not exist.");
                
            }
            mainWindow.LogMessage("Loading YARA rules...");
            try
            {               
                var ruleFiles = Directory.EnumerateFiles(absoluteFolderPath, "*.yar", SearchOption.AllDirectories)
                                        .Concat(Directory.EnumerateFiles(absoluteFolderPath, "*.yara", SearchOption.AllDirectories))
                                        .ToList();

                if (!ruleFiles.Any())
                {
                    mainWindow.LogMessage($"No YARA rule files (*.yar, *.yara) found in '{absoluteFolderPath}'.");
                    
                }                

                foreach (var ruleFile in ruleFiles)
                {
                    try
                    {
                       
                        if (compiler != null)
                        {

                            //mainWindow.LogMessage($"Adding rule file: {ruleFile}");
                            compiler.AddRuleFile(ruleFile);
                            //mainWindow.LogMessage("YARA rules Load SUCCESS!!...");
                            rules_no++;
                        }
                        else
                        {
                            mainWindow.LogMessage("Compiler init error!!...");
                        }

                    }
                    catch (Exception ex)
                    {
                        mainWindow.LogMessage($"Error adding rule file '{ruleFile}': {ex.Message}aaa");
                    }
                }
                mainWindow.YaraRulesCountText.Text = "Rules loaded: "+ rules_no;                
                mainWindow.LogMessage("All rule files processed. Attempting to compile rules...");
               
            }
            catch (Exception ex)
            {
                mainWindow.LogMessage($"An unexpected error occurred during rule compilation: {ex.Message}");
                
            }           
        }

        public void compileRules()
        {
            rules = compiler.Compile();
            mainWindow.YaraRulesStatusText.Text = "Compiled successfully";
            mainWindow.LogMessage("YARA rules Compilation SUCCESS!!...");
            
        }

        public async Task scanFile(String file_path)
        {
            ShowScanWindow(mainWindow);
            List<ScanResult> scanResults;
            if (file_path != null)
            {
                if (scanner != null) { }
                else
                {
                    scanner = new Scanner();
                }

                mainWindow.LogMessage("Scanning !!...");

                // Move scanning work to background thread
                await Task.Run(async () =>
                {
                    try
                    {
                        HybridFileAnalyzer hy = new HybridFileAnalyzer();
                        HybridAnalysisResult hybridResult = await hy.AnalyzeFile(file_path);
                        mainWindow.LogMessage(hybridResult.ToString());

                        currentScanWindow.UpdateCurrentFile(file_path);

                        // Get file size and add to data scanned
                        try
                        {
                            FileInfo fileInfo = new FileInfo(file_path);
                            if (fileInfo.Exists)
                            {
                                currentScanWindow.AddDataScanned(fileInfo.Length);
                            }
                        }
                        catch (Exception ex)
                        {
                            mainWindow.LogMessage($"Error getting file size for {file_path}: {ex.Message}");
                        }

                        scanResults = scanner.ScanFile(file_path, rules);
                        currentScanWindow.AddFilesScanned();

                        // Create scan report and add to scan window
                        YARAScanReport scanReport = new YARAScanReport(file_path, scanResults, hybridResult);

                        bool hybridThreatsFound = IsHybridThreatDetected(hybridResult);

                        // If any threats detected, 
                        if (hybridThreatsFound)
                        {
                            scanReport.isHybridThreatDetected = true;
                        }

                        currentScanWindow.AddScanResult(scanReport);
                        displayScanResults(scanResults, file_path);
                    }
                    catch (Exception ex)
                    {
                        mainWindow.LogMessage($"Error during scan: {ex.Message}");
                    }
                });

                mainWindow.LogMessage("Scan SUCCESS!!...");
                currentScanWindow.CompleteScan();
            }
            else
            {
                mainWindow.LogMessage("Scan Cancelled!!...");
            }

        }

        public async Task scanFiles(List<String> files, string originalFolderPath = null)
        {
            ShowScanWindow(mainWindow);

            // original folder path, to count directories
            if (!string.IsNullOrEmpty(originalFolderPath) && Directory.Exists(originalFolderPath))
            {
                try
                {
                    var directories = Directory.GetDirectories(originalFolderPath, "*", SearchOption.AllDirectories);
                    currentScanWindow.AddFoldersScanned(directories.Length + 1); // +1 for root
                }
                catch (Exception ex)
                {
                    mainWindow.LogMessage($"Could not count directories: {ex.Message}");
                }
            }

            List<ScanResult> scanResults = null;
            if (files != null)
            {
                if (scanner != null) { }
                else
                {
                    scanner = new Scanner();
                }
                mainWindow.LogMessage("Scanning !!...");

                // Moving the scanning loop to a background task (teh ui was gettnig stuck here)
                await Task.Run(async () =>
                {
                    foreach (string file in files)
                    {
                        // Checking if scan should continue (if user stops it)
                        if (!currentScanWindow.IsScanRunning)
                            break;

                        try
                        {
                            HybridFileAnalyzer hy = new HybridFileAnalyzer();
                            HybridAnalysisResult hybridResult = await hy.AnalyzeFile(file);

                            // Update UI on main thread
                            currentScanWindow.UpdateCurrentFile(file);

                            // Get file size and add to data scanned
                            try
                            {
                                FileInfo fileInfo = new FileInfo(file);
                                if (fileInfo.Exists)
                                {
                                    currentScanWindow.AddDataScanned(fileInfo.Length);
                                }
                            }
                            catch (Exception ex)
                            {
                                mainWindow.LogMessage($"Error getting file size for {file}: {ex.Message}");
                            }

                            scanResults = scanner.ScanFile(file, rules);
                            currentScanWindow.AddFilesScanned();
                            scanReport = new YARAScanReport(file, scanResults, hybridResult);
                            bool hybridThreatsFound = IsHybridThreatDetected(hybridResult);

                            // If any threats detected, 
                            if (hybridThreatsFound)
                            {
                                scanReport.isHybridThreatDetected = true;
                            }

                            currentScanWindow.AddScanResult(scanReport);
                            displayScanResults(scanResults, file);

                            // Small delay to allow UI to update and remain responsive
                            await Task.Delay(10);
                        }
                        catch (Exception ex)
                        {
                            mainWindow.LogMessage($"Error scanning file {file}: {ex.Message}");
                        }
                    }
                });

                currentScanWindow.CompleteScan();
                mainWindow.LogMessage("Scan SUCCESS!!...");
            }
            else
            {
                mainWindow.LogMessage("Scan Cancelled!!...");
            }

        }

        public async Task scanFile_RealTimeMonitor(String file_path)
        {
           
            List<ScanResult> scanResults;
            if (file_path != null)
            {
                if (scanner != null) { }
                else
                {
                    scanner = new Scanner();
                }

                mainWindow.LogMessage("Scanning !!...");

                HybridFileAnalyzer hy = new HybridFileAnalyzer();
                HybridAnalysisResult hybridResult = await hy.AnalyzeFile(file_path);
                //mainWindow.LogMessage(result.ToString());

                scanResults = scanner.ScanFile(file_path, rules);                

                // Create scan report and add to scan window
                YARAScanReport scanReport = new YARAScanReport(file_path, scanResults,hybridResult);

                // Check if either analysis found threats
                bool yaraThreatsFound = scanReport.isYaraThreatDetected;
                bool hybridThreatsFound = IsHybridThreatDetected(hybridResult);

                // If any threats detected, show alert window
                if (yaraThreatsFound || hybridThreatsFound)
                {
                   // ShowScanWindow(mainWindow);
                    scanReport.isHybridThreatDetected = true;
                    mainWindow.LogMessage($"REAL-TIME THREAT DETECTED: {Path.GetFileName(file_path)}");
                    //displayScanResults(scanResults, file_path);
                    ShowRealTimeResults(scanReport);


                }

                mainWindow.LogMessage($"Real-time scan completed: {Path.GetFileName(file_path)}");
                mainWindow.LogMessage("Scan SUCCESS!!...");           

            }
            else
            {
                mainWindow.LogMessage("Scan Cancelled!!...");
            }

        }
        /// <summary>
        /// Determines if the hybrid analysis detected any threats based on analyzer's scoring system
        /// </summary>
        private bool IsHybridThreatDetected(HybridAnalysisResult hybridResult)
        {
            if (hybridResult == null) return false;

            // Check threat level
            if (hybridResult.FinalThreatLevel != null)
            {
                string threatLevel = hybridResult.FinalThreatLevel.ToUpper();

                // Considers MEDIUM, HIGH, CRITICAL as threats
                if (threatLevel == "CRITICAL" ||
                    threatLevel == "HIGH" ||
                    threatLevel == "MEDIUM")
                {
                    return true;
                }
            }

            // Check if total score exceeds MEDIUM threshold (40+ is considered suspicious)
            if (hybridResult.TotalScore >= 40)
            {
                return true;
            }

            // Check for cross-analysis findings
            if (hybridResult.CrossAnalysisFindings != null && hybridResult.CrossAnalysisFindings.Any())
            {
                return true;
            }

            return false;
        }



        public void cleanup()
        {
            mainWindow.LogMessage("Cleaning up YARA resources...\n"); // For debugging

            // Dispose scanner 
            if (scanner != null)
            {                
                scanner = null; // Set to null to indicate it's disposed
                mainWindow.LogMessage("Scanner disposed.\n");
            }

            // Dispose compiled rules 
            if (rules != null)
            {
                rules.Dispose();
                rules = null;
                mainWindow.LogMessage("Compiled rules disposed.\n");
            }

            // Dispose compiler 
            if (compiler != null)
            {
                compiler.Dispose();
                compiler = null;
                mainWindow.LogMessage("Compiler disposed.\n");
            }

            // Dispose YARA context 
            if (context != null)
            {
                context.Dispose();
                context = null;
                mainWindow.LogMessage("YARA Context disposed.\n");                
            }

            mainWindow.LogMessage("YARA cleanup complete.\n");
            mainWindow.ScanInfoTextBox.ScrollToEnd();
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

                    // Only call currentScanWindow if it exists (for manual scans)
                    if (currentScanWindow != null)
                    {
                        currentScanWindow.ReportThreatDetected(result.MatchingRule.Identifier, filepath);
                    }
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
            //currentScanWindow.Owner = this;
            currentScanWindow.Show(); // Use Show() instead of ShowDialog() for non-blocking

            // Start the scan window
            currentScanWindow.StartScan();
        }

        private void ShowPEAnalysisResults(PEAnalysisResult analysisResult)
        {
            PEAnalysisResultsWindow.ShowAnalysisResults(analysisResult, this.mainWindow);
        }

        /// <summary>
        /// Show real-time scan results using existing ScanResultsWindow
        /// </summary>
        private void ShowRealTimeResults(YARAScanReport scanReport)
        {
            // Create a dummy scan window for the results system
            var dummyScanWindow = new ScanWindow(mainWindow);
            dummyScanWindow.Hide(); // Hide it since we don't need to show it

            // Create results window with single result
            var singleResultList = new List<YARAScanReport> { scanReport };
            ScanResultsWindow resultsWindow = new ScanResultsWindow(singleResultList, dummyScanWindow, mainWindow);
           
            //resultsWindow.Title = "N.A.Z.A.R.I.C.K. Protocol - Real-Time Threat Detected";

            // Show the results window
            resultsWindow.Show();

            // Bring to front and focus
            
        }
    }

}
