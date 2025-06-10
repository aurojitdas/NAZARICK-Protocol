using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using dnYara;

namespace NAZARICK_Protocol.service
{
    internal class PatternWeaver
    {
        YaraContext? context;
        Compiler? compiler;
        public String initialize_YARA()
        {
            YaraContext context = new YaraContext();
            Compiler compiler = new Compiler();
            compiler.AddRuleFile("C:\\Users\\Aurojit-VM1\\source\\repos\\NAZARICK Protocol\\rules\\rule.yara");
            CompiledRules rules = compiler.Compile();
            Scanner scanner = new Scanner();
            List<ScanResult> scanResults = scanner.ScanFile("C:\\Windows\\System32\\notepad.exe", rules);
            return "ScanSuccess";
        }
       

    }



}
