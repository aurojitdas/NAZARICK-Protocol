using dnYara;
using dnYara.Interop;
using System;
using System.Collections.Generic;
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
            addRuleFiles("rules\\rule.yara");
            //scanFile("C:\\Windows\\System32\\notepad.exe");
            //cleanup();
            return "ScanSuccess";
        }

        public void addRuleFiles(String file_path)
        {
            if (compiler!=null)
            {
                mainWindow.ScanInfoTextBox.AppendText("Loading YARA rules...\n");
                compiler.AddRuleFile(file_path);
                mainWindow.ScanInfoTextBox.AppendText("YARA rules Load SUCCESS!!...\n");
                rules = compiler.Compile();
                mainWindow.ScanInfoTextBox.AppendText("YARA rules Compilation SUCCESS!!...\n");
                mainWindow.ScanInfoTextBox.ScrollToEnd();
            }
            else
            {
                mainWindow.ScanInfoTextBox.AppendText("Compiler init error!!...\n");
            }
            
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
                }
                else
                {
                    mainWindow.ScanInfoTextBox.AppendText("Scanning !!...\n"+file_path);
                    scanner = new Scanner();
                    scanResults = scanner.ScanFile(file_path, rules);
                    mainWindow.ScanInfoTextBox.AppendText("Scan SUCCESS!!...\n");
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


    }



}
