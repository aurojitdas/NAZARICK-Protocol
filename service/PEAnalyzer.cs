using NAZARICK_Protocol.service.Results;
using PeNet;
using PeNet.Header.Pe;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace NAZARICK_Protocol.service
{
    /// <summary>
    /// Performs static analysis on Windows PE (Portable Executable) files
    /// to detect suspicious imports and section characteristics.
    /// </summary>
    internal class PEAnalyzer
    {
        // A list of function imports that are often used by malware.
        // Need to update thsi shit
        private static readonly HashSet<string> SuspiciousFunctionNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Process Injection & Memory Manipulation
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "ReadProcessMemory",
            "ResumeThread", "QueueUserAPC", "SetThreadContext", "NtMapViewOfSection",

            // Keylogging & Hooking
            "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "GetRawInputData",

            // Networking & Downloading Payloads
            "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
            "InternetReadFile", "HttpSendRequestA", "HttpSendRequestW", "socket", "send", "recv",

            // Loading Libraries / Finding Functions at Runtime
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll",

            // Anti-Analysis & Anti-Debugging
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "NtQueryInformationProcess",

            // Cryptography (often used to decrypt malicious payloads)
            "CryptDecrypt", "CryptAcquireContext", "BCryptDecrypt",
            
            // Filesystem & Persistence
            "CreateFileW", "WriteFile", "RegCreateKeyExA", "RegSetValueExA"
        };


        /// <summary>
        /// Analyzes a given file for suspicious imports and section anomalies.
        /// </summary>
        /// <param name="filePath">The path to the executable file to analyze.</param>
        /// <returns>A PEAnalysisResult object containing the findings.</returns>
        public PEAnalysisResult Analyze(string filePath)
        {
            var result = new PEAnalysisResult(filePath);

            if (!File.Exists(filePath))
            {
                result.Errors.Add("File does not exist." +filePath);
                return result;
            }

            try
            {
                
                var peFile = new PeFile(filePath);
                result.IsValidPeFile = true;
                
                CheckSuspiciousImports(peFile, result);
                
                CheckSectionAnomalies(peFile, result);
            }
            catch (Exception ex)
            {
                // Catch errors from PeNet if the file is not a valid PE,
                result.IsValidPeFile = false;
                result.Errors.Add($"PE parsing failed: {ex.Message} "+filePath);
            }

            return result;
        }

        /// <summary>
        /// Checks the PE file's imported functions against a list of suspicious ones.
        /// </summary>
        private void CheckSuspiciousImports(PeFile peFile, PEAnalysisResult result)
        {
            if (peFile.ImportedFunctions == null) return;

            foreach (var import in peFile.ImportedFunctions)
            {
                if (import.Name != null && SuspiciousFunctionNames.Contains(import.Name))
                {
                    result.SuspiciousImports.Add($"{import.Name} (from {import.DLL})");
                }
            }
        }

        /// <summary>
        /// Analyzes PE sections for anomalies like writable+executable flags.
        /// </summary>
        private void CheckSectionAnomalies(PeFile peFile, PEAnalysisResult result)
        {
            if (peFile.ImageSectionHeaders == null) return;

            foreach (var section in peFile.ImageSectionHeaders)
            {
                bool isExecutable = section.Characteristics.HasFlag(ScnCharacteristicsType.MemExecute);
                bool isWritable = section.Characteristics.HasFlag(ScnCharacteristicsType.MemWrite);

                // ANOMALY 1: Section is both writable and executable.
                // Often used by packers and malware to run unpacked code.
                if (isExecutable && isWritable)
                {
                    result.SectionAnomalies.Add($"Section '{section.Name}' is both Writable and Executable. This is highly suspicious.");
                }

                // ANOMALY 2: Virtual size is much larger than raw size.
                // This indicates a BSS-like section that a packer will fill with code at runtime.
                // flag it if virtual size is at least 10x raw size, and raw size isn't zero.
                if (section.VirtualSize > (section.SizeOfRawData * 10) && section.SizeOfRawData > 0)
                {
                    result.SectionAnomalies.Add($"Section '{section.Name}' has a Virtual Size ({section.VirtualSize}) that is significantly larger than its Raw Size ({section.SizeOfRawData}).");
                }
            }
        }
    }
}
