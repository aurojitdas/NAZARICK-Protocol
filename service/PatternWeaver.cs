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
        public String initialize_YARA()
        {
            YaraContext context = new YaraContext();
            Compiler compiler = new Compiler();
            compiler.AddRuleFile("rules\\rule.yara");
            rules = compiler.Compile();
            scanner = new Scanner();
            List<ScanResult> scanResults = scanner.ScanFile("C:\\Windows\\System32\\notepad.exe", rules);
            Cleanup();
            return "ScanSuccess";
        }

        public void Cleanup()
        {
            Console.WriteLine("Cleaning up YARA resources..."); // For debugging

            // Dispose scanner 
            if (scanner != null)
            {                
                scanner = null; // Set to null to indicate it's disposed
                Console.WriteLine("Scanner disposed.");
            }

            // Dispose compiled rules 
            if (rules != null)
            {
                rules.Dispose();
                rules = null;
                Console.WriteLine("Compiled rules disposed.");
            }

            // Dispose compiler 
            if (compiler != null)
            {
                compiler.Dispose();
                compiler = null;
                Console.WriteLine("Compiler disposed.");
            }

            // Dispose YARA context 
            if (context != null)
            {
                context.Dispose();
                context = null;
                Console.WriteLine("YARA Context disposed.");
            }

            Console.WriteLine("YARA cleanup complete.");
        }


    }



}
