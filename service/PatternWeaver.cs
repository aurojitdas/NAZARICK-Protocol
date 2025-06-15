using dnYara;
using dnYara.Interop;
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

        public PatternWeaver(MainWindow mainWindow)
        {
            this.mainWindow = mainWindow;
        }
        public String initialize_YARA()
        {
            mainWindow.ScanInfoTextBox.AppendText("Initializing YARA Compiler!!...\n");
            context = new YaraContext();
            compiler = new Compiler();
            mainWindow.ScanInfoTextBox.AppendText("YARA Compiler initialization SUCCESS!!...\n");
            mainWindow.ScanInfoTextBox.ScrollToEnd();
            addRuleFiles("rules\\");
            compileRules();
            //scanFile("C:\\Windows\\System32\\notepad.exe");
            //cleanup();
            return "YARA Initialized Succesfully";
        }

        public void addRuleFiles(String folder_path)
        {
            string absoluteFolderPath = Path.GetFullPath(folder_path);
            if (!Directory.Exists(folder_path))
            {
                mainWindow.ScanInfoTextBox.AppendText($"Error: Folder '{absoluteFolderPath}' does not exist.");
                
            }

            try
            {               
                var ruleFiles = Directory.EnumerateFiles(absoluteFolderPath, "*.yar", SearchOption.AllDirectories)
                                        .Concat(Directory.EnumerateFiles(absoluteFolderPath, "*.yara", SearchOption.AllDirectories))
                                        .ToList();

                if (!ruleFiles.Any())
                {
                    mainWindow.ScanInfoTextBox.AppendText($"No YARA rule files (*.yar, *.yara) found in '{absoluteFolderPath}'.");
                    
                }                

                foreach (var ruleFile in ruleFiles)
                {
                    try
                    {
                        mainWindow.ScanInfoTextBox.AppendText("Loading YARA rules...\n");
                        if (compiler != null)
                        {

                            mainWindow.ScanInfoTextBox.AppendText($"Adding rule file: {ruleFile}\n");
                            compiler.AddRuleFile(ruleFile);
                            mainWindow.ScanInfoTextBox.AppendText("YARA rules Load SUCCESS!!...\n");

                        }
                        else
                        {
                            mainWindow.ScanInfoTextBox.AppendText("Compiler init error!!...\n");
                        }

                    }
                    catch (Exception ex)
                    {
                        mainWindow.ScanInfoTextBox.AppendText($"Error adding rule file '{ruleFile}': {ex.Message}aaa\n");
                    }
                }

                mainWindow.ScanInfoTextBox.AppendText("All rule files processed. Attempting to compile rules...\n");
               
            }
            catch (Exception ex)
            {
                mainWindow.ScanInfoTextBox.AppendText($"An unexpected error occurred during rule compilation: {ex.Message}");
                
            }           
        }

        public void compileRules()
        {
            rules = compiler.Compile();
            mainWindow.ScanInfoTextBox.AppendText("YARA rules Compilation SUCCESS!!...\n");
            mainWindow.ScanInfoTextBox.ScrollToEnd();
        }

        public void scanFile(String file_path)
        {
            List<ScanResult> scanResults;
            if (file_path != null)
            {
                if (scanner != null)
                {
                    mainWindow.ScanInfoTextBox.AppendText("Scanning !!...\n");
                    scanResults = scanner.ScanFile(file_path, rules);
                    mainWindow.ScanInfoTextBox.AppendText("Scan SUCCESS!!...\n");
                    mainWindow.ScanInfoTextBox.ScrollToEnd();
                    displayScanResults(scanResults);
                }
                else
                {
                    mainWindow.ScanInfoTextBox.AppendText("Scanning !!...\n"+file_path);
                    scanner = new Scanner();
                    scanResults  = scanner.ScanFile(file_path, rules);
                    mainWindow.ScanInfoTextBox.AppendText("Scan SUCCESS!!...\n");
                    displayScanResults(scanResults);
                    mainWindow.ScanInfoTextBox.ScrollToEnd();
                }
                
            }
            else
            {
                mainWindow.ScanInfoTextBox.AppendText("Scan Cancelled!!...\n");
            }
                
        }

        public void cleanup()
        {
            mainWindow.ScanInfoTextBox.AppendText("Cleaning up YARA resources...\n"); // For debugging

            // Dispose scanner 
            if (scanner != null)
            {                
                scanner = null; // Set to null to indicate it's disposed
                mainWindow.ScanInfoTextBox.AppendText("Scanner disposed.\n");
            }

            // Dispose compiled rules 
            if (rules != null)
            {
                rules.Dispose();
                rules = null;
                mainWindow.ScanInfoTextBox.AppendText("Compiled rules disposed.\n");
            }

            // Dispose compiler 
            if (compiler != null)
            {
                compiler.Dispose();
                compiler = null;
                mainWindow.ScanInfoTextBox.AppendText("Compiler disposed.\n");
            }

            // Dispose YARA context 
            if (context != null)
            {
                context.Dispose();
                context = null;
                mainWindow.ScanInfoTextBox.AppendText("YARA Context disposed.\n");                
            }

            mainWindow.ScanInfoTextBox.AppendText("YARA cleanup complete.\n");
            mainWindow.ScanInfoTextBox.ScrollToEnd();
        }

        private void displayScanResults(List<ScanResult> scanResults)
        {
            if (scanResults != null && scanResults.Count > 0)
            {
                mainWindow.ScanInfoTextBox.AppendText($"\n--- THREATS DETECTED ---\n");
                foreach (var result in scanResults)
                {
                    mainWindow.ScanInfoTextBox.AppendText($"Rule matched: {result.MatchingRule.Identifier}\n");
                }
                mainWindow.ScanInfoTextBox.AppendText($"Total rules matched: {scanResults.Count}\n");
            }
            else
            {
                mainWindow.ScanInfoTextBox.AppendText("No threats detected.\n");
            }
        }

    }

}
