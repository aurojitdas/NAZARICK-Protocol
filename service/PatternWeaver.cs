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
        private VirusTotalAPI vt;
        PEAnalyzer Pe;
        FileScanReport scanReport;

        public PatternWeaver(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
            vt = new VirusTotalAPI("68d9e1716c7df15e701bcce1addafd4231c2d288c5869726ecb9a31ff28ba878", this.mainWindow);
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
                        mainWindow.LogMessage("Loading YARA rules...");
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
            ShowScanWindow();
            List<ScanResult> scanResults;
            if (file_path != null)
            {
                if (scanner != null) { }
                else
                {
                    scanner = new Scanner();
                }

                mainWindow.LogMessage("Scanning !!...");
                string response = //await vt.UploadAndAnalyzeFile(file_path);
                await vt.CheckFileHash("fe115f0be1c1ffd7176b8e1b1f88a41b");
                if (!string.IsNullOrEmpty(response)) {
                    mainWindow.LogMessage(response);
                 }
                VirusTotalFileAnalysisResults? op = vt.ParseFileAnalysis(response);
                ShowVirusTotalAnalysisResults(op);
               


                // mainWindow.LogMessage(op.MeaningfulName);
                // mainWindow.LogMessage(op.IsMalicious.ToString());
                // mainWindow.LogMessage(op.MaliciousDetections.ToString());
                // mainWindow.LogMessage(op.ThreatLabel);

                //PEAnalysisResult pr = Pe.Analyze(file_path);
                //ShowPEAnalysisResults(pr);

                currentScanWindow.UpdateCurrentFile(file_path);
                scanResults = scanner.ScanFile(file_path, rules);
                currentScanWindow.AddFilesScanned();
                mainWindow.LogMessage("Scan SUCCESS!!...");
                //mainWindow.LogMessage(pr.ToString());
                currentScanWindow.CompleteScan();
                displayScanResults(scanResults, file_path);

            }
            else
            {
                mainWindow.LogMessage("Scan Cancelled!!...");
            }
                
        }

        public async Task scanFiles(List<String> files)
        {
            ShowScanWindow();
            List<ScanResult> scanResults =null;
            if (files != null)
            {
                if (scanner != null) { }
                else
                {
                    scanner = new Scanner();
                }
                mainWindow.LogMessage("Scanning !!...");
                foreach (string file in files)
                {
                    currentScanWindow.UpdateCurrentFile(file);
                    scanResults = scanner.ScanFile(file, rules);
                    currentScanWindow.AddFilesScanned();
                    scanReport = new FileScanReport(file,scanResults);
                    displayScanResults(scanResults, file);
                }
                currentScanWindow.CompleteScan();              
                mainWindow.LogMessage("Scan SUCCESS!!...");               
               

            }
            else
            {
                mainWindow.LogMessage("Scan Cancelled!!...");
            }

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

        private void displayScanResults(List<ScanResult> scanResults,string filepath)
        {
            if (scanResults != null && scanResults.Count > 0)
            {
                mainWindow.LogMessage($"--- THREATS DETECTED IN {Path.GetFileName(filepath)} ---\n");
                foreach (var result in scanResults)
                {
                    mainWindow.LogMessage($"Rule matched: {result.MatchingRule.Identifier}\n");
                    mainWindow.ReportThreatDetected(result.MatchingRule.Identifier,filepath);
                    currentScanWindow.ReportThreatDetected(result.MatchingRule.Identifier,filepath);
                }
                mainWindow.LogMessage($"Total rules matched: {scanResults.Count}\n");
            }
            else
            {
                mainWindow.LogMessage("No threats detected.\n");
            }
        }

        private void ShowScanWindow()
        {
            currentScanWindow = new ScanWindow();
            //currentScanWindow.Owner = this;
            currentScanWindow.Show(); // Use Show() instead of ShowDialog() for non-blocking

            // Start the scan window
            currentScanWindow.StartScan();
        }

        private void ShowPEAnalysisResults(PEAnalysisResult analysisResult)
        {
            PEAnalysisResultsWindow.ShowAnalysisResults(analysisResult, this.mainWindow);
        }
        private void ShowVirusTotalAnalysisResults(VirusTotalFileAnalysisResults analysisResult)
        {
            VirusTotalResultsWindow.ShowAnalysisResults(analysisResult, this.mainWindow);
        }
    }

}
