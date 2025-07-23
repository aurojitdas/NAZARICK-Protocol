using NAZARICK_Protocol.service.Results;
using PeNet;
using PeNet.Header.Pe;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace NAZARICK_Protocol.service
{
    /// <summary>
    /// Enhanced PE analyzer with scoring system to reduce false positives
    /// </summary>
    internal class PEAnalyzer
    {
        // Categorized imports with different threat levels
        private static readonly Dictionary<string, int> SuspiciousImports = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            // HIGH RISK (20-30 points) - Direct process manipulation
            ["CreateRemoteThread"] = 25,
            ["WriteProcessMemory"] = 25,
            ["VirtualAllocEx"] = 20,
            ["SetThreadContext"] = 25,
            ["QueueUserAPC"] = 25,
            ["NtMapViewOfSection"] = 30,
            ["RtlCreateUserThread"] = 30,

            // HIGH RISK - Keylogging & Hooking
            ["SetWindowsHookExA"] = 20,
            ["SetWindowsHookExW"] = 20,
            ["GetAsyncKeyState"] = 15,
            ["GetKeyState"] = 10,
            ["GetRawInputData"] = 15,

            // MEDIUM RISK (10-15 points) - Network operations
            ["URLDownloadToFileA"] = 15,
            ["URLDownloadToFileW"] = 15,
            ["InternetOpenA"] = 10,
            ["InternetOpenW"] = 10,
            ["InternetReadFile"] = 10,
            ["HttpSendRequestA"] = 10,
            ["HttpSendRequestW"] = 10,
            ["WinHttpOpen"] = 10,
            ["WSAStartup"] = 8,
            ["socket"] = 8,
            ["connect"] = 8,
            ["send"] = 5,
            ["recv"] = 5,

            // MEDIUM RISK - Anti-debugging
            ["IsDebuggerPresent"] = 5,
            ["CheckRemoteDebuggerPresent"] = 8,
            ["NtQueryInformationProcess"] = 15,
            ["OutputDebugStringA"] = 10,
            ["NtSetInformationThread"] = 20,

            // LOW RISK (1-5 points) - Common but potentially misused
            ["LoadLibraryA"] = 2,
            ["LoadLibraryW"] = 2,
            ["GetProcAddress"] = 3,
            ["CreateFileA"] = 1,
            ["CreateFileW"] = 1,
            ["WriteFile"] = 1,
            ["ReadFile"] = 1,
            ["RegCreateKeyExA"] = 5,
            ["RegCreateKeyExW"] = 5,
            ["RegSetValueExA"] = 5,
            ["RegSetValueExW"] = 5,

            // MEDIUM RISK - Cryptography (often used to decrypt payloads)
            ["CryptDecrypt"] = 12,
            ["CryptEncrypt"] = 10,
            ["CryptAcquireContext"] = 8,
            ["BCryptDecrypt"] = 12,
            ["BCryptEncrypt"] = 10,

            // HIGH RISK - Service manipulation
            ["CreateServiceA"] = 20,
            ["CreateServiceW"] = 20,
            ["StartServiceA"] = 15,
            ["StartServiceW"] = 15,

            // HIGH RISK - Token manipulation
            ["AdjustTokenPrivileges"] = 20,
            ["OpenProcessToken"] = 8,
            ["ImpersonateLoggedOnUser"] = 25,

            // Additional suspicious APIs
            ["VirtualProtect"] = 15,
            ["VirtualProtectEx"] = 20,
            ["NtUnmapViewOfSection"] = 20,
            ["LdrLoadDll"] = 15,
            ["RtlAdjustPrivilege"] = 20,
            ["SeDebugPrivilege"] = 25,
            ["NtRaiseHardError"] = 30,
            ["NtTerminateProcess"] = 20
        };

        // Suspicious import combinations that indicate specific attack patterns
        private static readonly List<(string[] Functions, string Description, int BonusScore)> SuspiciousCombinations = new List<(string[], string, int)>
        {
            (new[] { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" }, "Classic Process Injection", 30),
            (new[] { "SetWindowsHookExA", "GetAsyncKeyState" }, "Keylogger Pattern", 25),
            (new[] { "SetWindowsHookExW", "GetAsyncKeyState" }, "Keylogger Pattern", 25),
            (new[] { "OpenProcessToken", "AdjustTokenPrivileges" }, "Privilege Escalation", 20),
            (new[] { "CreateServiceA", "StartServiceA" }, "Service Installation", 15),
            (new[] { "CreateServiceW", "StartServiceW" }, "Service Installation", 15),
            (new[] { "InternetOpenA", "InternetReadFile", "WriteFile" }, "Downloader Pattern", 20),
            (new[] { "InternetOpenW", "InternetReadFile", "WriteFile" }, "Downloader Pattern", 20),
            (new[] { "VirtualProtect", "GetProcAddress", "LoadLibraryA" }, "Dynamic API Resolution", 15),
            (new[] { "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess" }, "Anti-Debug Cluster", 25)
        };

        // Trusted certificate subjects
        private static readonly HashSet<string> TrustedSigners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft Corporation",
            "Microsoft Windows",
            "Microsoft Windows Publisher",
            "Google LLC",
            "Google Inc",
            "Adobe Inc.",
            "Adobe Systems Incorporated",
            "Intel Corporation",
            "NVIDIA Corporation",
            "Oracle Corporation",
            "Mozilla Corporation",
            "Apple Inc.",
            "Vmware, Inc",
            "Amazon.com Services LLC"
        };

        public PEAnalysisResult Analyze(string filePath)
        {
            var result = new PEAnalysisResult(filePath);

            if (!File.Exists(filePath))
            {
                result.Errors.Add($"File does not exist: {filePath}");
                return result;
            }

            try
            {
                var peFile = new PeFile(filePath);
                result.IsValidPeFile = true;

                // Run all analysis modules
                int importScore = AnalyzeImports(peFile, result);
                int sectionScore = AnalyzeSections(peFile, result);
                int signatureScore = AnalyzeDigitalSignature(filePath, result);
                int entryPointScore = AnalyzeEntryPoint(peFile, result);
                int metadataScore = AnalyzeMetadata(peFile, result);

                // Calculate total score
                result.TotalScore = importScore + sectionScore + signatureScore + entryPointScore + metadataScore;

                // Determine threat level
                if (result.TotalScore >= 100)
                {
                    result.ThreatLevel = "CRITICAL";
                    result.Summary = "File exhibits multiple high-risk characteristics typical of malware.";
                }
                else if (result.TotalScore >= 60)
                {
                    result.ThreatLevel = "HIGH";
                    result.Summary = "File shows several suspicious characteristics that warrant investigation.";
                }
                else if (result.TotalScore >= 30)
                {
                    result.ThreatLevel = "MEDIUM";
                    result.Summary = "File has some suspicious elements but may be legitimate.";
                }
                else if (result.TotalScore >= 10)
                {
                    result.ThreatLevel = "LOW";
                    result.Summary = "File appears mostly legitimate with minor suspicious elements.";
                }
                else
                {
                    result.ThreatLevel = "CLEAN";
                    result.Summary = "File appears to be legitimate software.";
                }
            }
            catch (Exception ex)
            {
                result.IsValidPeFile = false;
                result.Errors.Add($"PE parsing failed: {ex.Message}");
            }

            return result;
        }

        private int AnalyzeImports(PeFile peFile, PEAnalysisResult result)
        {
            int score = 0;
            var foundImports = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (peFile.ImportedFunctions == null) return score;

            foreach (var import in peFile.ImportedFunctions)
            {
                if (import.Name != null && SuspiciousImports.TryGetValue(import.Name, out int importScore))
                {
                    foundImports.Add(import.Name);
                    score += importScore;
                    result.SuspiciousImports.Add($"{import.Name} (from {import.DLL}) [+{importScore} points]");
                }
            }

            // Check for suspicious combinations
            foreach (var (functions, description, bonusScore) in SuspiciousCombinations)
            {
                if (functions.All(f => foundImports.Contains(f)))
                {
                    score += bonusScore;
                    result.ImportCombinations.Add($"{description} detected [+{bonusScore} points]");
                }
            }

            return score;
        }

        private int AnalyzeSections(PeFile peFile, PEAnalysisResult result)
        {
            int score = 0;

            if (peFile.ImageSectionHeaders == null) return score;

            foreach (var section in peFile.ImageSectionHeaders)
            {
                bool isExecutable = section.Characteristics.HasFlag(ScnCharacteristicsType.MemExecute);
                bool isWritable = section.Characteristics.HasFlag(ScnCharacteristicsType.MemWrite);

                // Writable + Executable = Major red flag
                if (isExecutable && isWritable)
                {
                    score += 50;
                    result.SectionAnomalies.Add($"Section '{section.Name}' is both Writable and Executable [+50 points]");
                }

                // Unusual section names
                string sectionName = section.Name.TrimEnd('\0');
                if (string.IsNullOrWhiteSpace(sectionName) || sectionName.Length == 1)
                {
                    score += 10;
                    result.SectionAnomalies.Add($"Section has suspicious name: '{sectionName}' [+10 points]");
                }

                // Virtual size much larger than raw size
                if (section.VirtualSize > 0 && section.SizeOfRawData > 0)
                {
                    double ratio = (double)section.VirtualSize / section.SizeOfRawData;
                    if (ratio > 10)
                    {
                        score += 20;
                        result.SectionAnomalies.Add($"Section '{section.Name}' has Virtual/Raw size ratio of {ratio:F1} [+20 points]");
                    }
                }

                // Zero raw size but large virtual size (common in packers)
                if (section.SizeOfRawData == 0 && section.VirtualSize > 1024)
                {
                    score += 15;
                    result.SectionAnomalies.Add($"Section '{section.Name}' has zero raw size but {section.VirtualSize} virtual size [+15 points]");
                }
            }

            return score;
        }

        private int AnalyzeDigitalSignature(string filePath, PEAnalysisResult result)
        {
            int score = 0;

            try
            {
                // PowerShell to get signature info andles both embedded and catalog
                using (var ps = PowerShell.Create())
                {
                    ps.AddCommand("Get-AuthenticodeSignature")
                      .AddParameter("FilePath", filePath);

                    var results = ps.Invoke();

                    if (results.Count > 0)
                    {
                        var signature = results[0];
                        var status = signature.Properties["Status"]?.Value?.ToString();
                        var signerCert = signature.Properties["SignerCertificate"]?.Value as X509Certificate2;

                        switch (status)
                        {
                            case "Valid":
                                if (signerCert != null)
                                {
                                    string subject = signerCert.Subject;
                                    bool isTrusted = TrustedSigners.Any(trusted =>
                                        subject.Contains(trusted, StringComparison.OrdinalIgnoreCase));

                                    if (isTrusted)
                                    {
                                        score -= 120;
                                        result.SignatureInfo = $"File has valid signature from trusted entity: {subject} [-50 points]";
                                    }
                                    else
                                    {
                                        result.SignatureInfo = $"File has valid signature from: {subject} [0 points]";
                                    }
                                }
                                else
                                {
                                    score -= 30;
                                    result.SignatureInfo = "File has valid signature (catalog-signed) [-30 points]";
                                }
                                break;

                            case "NotSigned":
                                score += 20;
                                result.SignatureInfo = "File is not digitally signed [+20 points]";
                                break;

                            case "HashMismatch":
                            case "NotTrusted":
                            case "UnknownError":
                                score += 30;
                                result.SignatureInfo = $"File has invalid signature: {status} [+30 points]";
                                break;

                            default:
                                score += 10;
                                result.SignatureInfo = $"File signature status unknown: {status} [+10 points]";
                                break;
                        }
                    }
                    else
                    {
                        score += 20;
                        result.SignatureInfo = "Unable to determine signature status [+20 points]";
                    }
                }
            }
            catch (Exception ex)
            {
                // Fallback to original method if PowerShell fails
                return AnalyzeDigitalSignatureOriginal(filePath, result);
            }

            return score;
        }

        private int AnalyzeDigitalSignatureOriginal(string filePath, PEAnalysisResult result)
        {
            // original old method as fallback
            int score = 0;
            try
            {
                var cert = X509Certificate.CreateFromSignedFile(filePath);
                var cert2 = new X509Certificate2(cert);

                using (var chain = new X509Chain())
                {
                    bool isChainValid = chain.Build(cert2);

                    if (!isChainValid)
                    {
                        score += 30;
                        var status = chain.ChainStatus.FirstOrDefault();
                        result.SignatureInfo = $"File has an INVALID signature. Reason: {status.StatusInformation.Trim()} [+30 points]";
                        return score;
                    }

                    string subject = cert2.Subject;
                    bool isTrusted = TrustedSigners.Any(trusted => subject.Contains(trusted, StringComparison.OrdinalIgnoreCase));

                    if (isTrusted)
                    {
                        score -= 50;
                        result.SignatureInfo = $"File signed by a trusted entity: {subject} [-50 points]";
                    }
                    else
                    {
                        result.SignatureInfo = $"File has a valid signature from: {subject} [0 points]";
                    }
                }
            }
            catch (CryptographicException)
            {
                score += 20;
                result.SignatureInfo = "File is not digitally signed [+20 points]";
            }
            catch (Exception ex)
            {
                score += 10;
                result.SignatureInfo = $"An error occurred during signature validation: {ex.Message} [+10 points]";
            }

            return score;
        }

        private int AnalyzeEntryPoint(PeFile peFile, PEAnalysisResult result)
        {
            int score = 0;

            if (peFile.ImageNtHeaders == null) return score;

            uint entryPoint = peFile.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

            // Finds which section contains the entry point
            var entrySection = peFile.ImageSectionHeaders?.FirstOrDefault(s =>
                entryPoint >= s.VirtualAddress &&
                entryPoint < s.VirtualAddress + s.VirtualSize);

            if (entrySection != null)
            {
                string sectionName = entrySection.Name.TrimEnd('\0');

                // Entry point not in .text section is suspicious
                if (!sectionName.Equals(".text", StringComparison.OrdinalIgnoreCase))
                {
                    score += 25;
                    result.EntryPointInfo = $"Entry point in unusual section: '{sectionName}' [+25 points]";
                }

                // Entry point in last section common packer behavior
                if (peFile.ImageSectionHeaders.Last() == entrySection)
                {
                    score += 20;
                    result.EntryPointInfo += $" Entry point in last section [+20 points]";
                }
            }

            return score;
        }

        private int AnalyzeMetadata(PeFile peFile, PEAnalysisResult result)
        {
            int score = 0;
            const uint deadbeefTimestamp = 0xDEADBEEF; // Correct value

            // Check compile time
            if (peFile.ImageNtHeaders?.FileHeader?.TimeDateStamp != null)
            {
                var timestamp = peFile.ImageNtHeaders.FileHeader.TimeDateStamp;

                // Debug: Log the actual timestamp value
               // result.MetadataInfo.Add($"Raw timestamp: {timestamp} (0x{timestamp:X8})");

                // Check for common placeholder values
                if (timestamp == deadbeefTimestamp)
                {
                    result.MetadataInfo.Add("Compile time is a known placeholder (0xDEADBEEF) [0 points]");
                }
                else if (timestamp == 0)
                {
                    score += 15;
                    result.MetadataInfo.Add("Compile time is zero (suspicious) [+15 points]");
                }
                else
                {
                    try
                    {
                        // PE timestamps are seconds since January 1, 1970 00:00:00 UTC
                        var compileTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                            .AddSeconds(timestamp);

                        var compileTimeLocal = compileTime.ToLocalTime();
                        var now = DateTime.UtcNow;

                        // More reasonable date range
                        var minDate = new DateTime(1990, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                        var maxDate = now.AddDays(30); // Allow some future dates for build systems

                        if (compileTime < minDate)
                        {
                            score += 20;
                            result.MetadataInfo.Add($"Suspicious compile time (too old): {compileTimeLocal:yyyy-MM-dd HH:mm:ss} [+20 points]");
                        }
                        else if (compileTime > maxDate)
                        {
                            score += 25;
                            result.MetadataInfo.Add($"Suspicious compile time (future date): {compileTimeLocal:yyyy-MM-dd HH:mm:ss} [+25 points]");
                        }
                        else
                        {
                            result.MetadataInfo.Add($"Compile time: {compileTimeLocal:yyyy-MM-dd HH:mm:ss} [0 points]");
                        }
                    }
                    catch (Exception ex)
                    {
                        score += 10;
                        result.MetadataInfo.Add($"Invalid timestamp: 0x{timestamp:X8} - {ex.Message} [+10 points]");
                    }
                }
            }

            return score;
        }
    } 
}