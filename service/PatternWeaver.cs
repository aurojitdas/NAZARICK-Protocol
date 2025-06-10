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
            addRuleFiles("");
            scanFile("");
            cleanup();
            return "ScanSuccess";
        }

        public void addRuleFiles(String file_path)
        {
            if (compiler!=null)
            {
                mainWindow.ScanInfoTextBox.AppendText("Loading YARA rules...\n");
                compiler.AddRuleFile("rules\\rule.yara");
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
            if (scanner!=null)
            {
                mainWindow.ScanInfoTextBox.AppendText("Scanning !!...\n");
                scanResults = scanner.ScanFile("C:\\Windows\\System32\\notepad.exe", rules);
                mainWindow.ScanInfoTextBox.AppendText("Scan SUCCESS!!...\n");
                mainWindow.ScanInfoTextBox.ScrollToEnd();
            }
            else
            {
                mainWindow.ScanInfoTextBox.AppendText("Scanning !!...\n");
                scanner = new Scanner();
                scanResults = scanner.ScanFile("C:\\Windows\\System32\\notepad.exe", rules);
                mainWindow.ScanInfoTextBox.AppendText("Scan SUCCESS!!...\n");
                mainWindow.ScanInfoTextBox.ScrollToEnd();
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
