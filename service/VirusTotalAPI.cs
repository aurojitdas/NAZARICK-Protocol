// VirusTotalAPI.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;

namespace NAZARICK_Protocol.service
{
    internal class VirusTotalAPI
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private const string BaseUrl = "https://www.virustotal.com/api/v3/";
        private const long MaxFileSize = 32 * 1024 * 1024; // 32MB limit
        MainWindow _mw;

        public VirusTotalAPI(MainWindow mw)
        {
            _mw = mw;
            _apiKey = Properties.Settings.Default.VirusTotalApiKey;
            
            // Check for missing API key
            if (string.IsNullOrWhiteSpace(_apiKey))
            {
                ShowMissingApiKeyDialog();
                //throw new InvalidOperationException("VirusTotal API key not configured.");
            }

            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
            _httpClient.BaseAddress = new Uri(BaseUrl);
        }

        private async void ShowMissingApiKeyDialog()
        {

            Application.Current.Dispatcher.Invoke(() =>
            {
               
                Window owner = _mw ?? Application.Current.MainWindow;

                MessageBox.Show(owner,
                    "Please configure your VirusTotal API key in the Settings window.",
                    "API Key Missing",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            });

        }
        public async Task<string> CheckFileHash(string fileHash)
        {
            try
            {
                // The API endpoint for file hash lookup
                string requestUrl = $"files/{fileHash}";
                HttpResponseMessage response = await _httpClient.GetAsync(requestUrl);
                response.EnsureSuccessStatusCode(); // Throws an exception if not a success status code.
                string jsonResponse = await response.Content.ReadAsStringAsync();
                return jsonResponse;
            }
            catch (HttpRequestException e)
            {
                _mw.LogMessage($"Request Error: {e.Message}");
                // Handle specific status codes if needed (e.g., 404 for not found, 429 for rate limit)
                if (e.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                {
                    _mw.LogMessage("Rate limit exceeded. Please wait before trying again.");
                }
                return null;
            }
            catch (Exception e)
            {
                _mw.LogMessage($"An unexpected error occurred: {e.Message}");
                return null;
            }
        }

        /// <summary>
        /// Uploads a file to VirusTotal, waits for analysis completion, and returns the results.
        /// </summary>
        /// <param name="filePath">The path to the file to upload and analyze.</param>
        /// <param name="maxWaitTimeSeconds">Maximum time to wait for analysis completion (default: 300 seconds).</param>
        /// <returns>Analysis results as JSON string, or null if upload/analysis fails.</returns>
        public async Task<string> UploadAndAnalyzeFile(string filePath, int maxWaitTimeSeconds = 300)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                _mw.LogMessage("File path is invalid or file does not exist.");
                return null;
            }

            try
            {
                FileInfo fileInfo = new FileInfo(filePath);

                // Check file size limit
                if (fileInfo.Length > MaxFileSize)
                {
                    _mw.LogMessage($"File size ({fileInfo.Length} bytes) exceeds the 32MB limit.");
                    return null;
                }

                _mw.LogMessage($"Uploading file: {fileInfo.Name} ({fileInfo.Length} bytes)");

                // Upload the file
                string analysisId = await UploadFile(filePath);
                if (string.IsNullOrEmpty(analysisId))
                {
                    return null;
                }

                _mw.LogMessage($"Analysis ID: {analysisId}. Waiting for results...");

                // Poll for results
                int waitTime = 0;
                const int pollInterval = 10; // seconds

                while (waitTime < maxWaitTimeSeconds)
                {
                    await Task.Delay(pollInterval * 1000);
                    waitTime += pollInterval;

                    string analysisResponse = await GetAnalysisResults(analysisId);
                    if (!string.IsNullOrEmpty(analysisResponse))
                    {
                        // Check if analysis is complete
                        if (IsAnalysisComplete(analysisResponse))
                        {
                            _mw.LogMessage("Analysis completed successfully.");
                            return analysisResponse;
                        }
                        else
                        {
                            _mw.LogMessage($"Analysis in progress... ({waitTime}s elapsed)");
                        }
                    }
                }

                _mw.LogMessage("Analysis timed out. You can check results later using the analysis ID.");
                return null;
            }
            catch (Exception e)
            {
                _mw.LogMessage($"An unexpected error occurred: {e.Message}");
                return null;
            }
        }

        /// <summary>
        /// Uploads a file to VirusTotal for analysis.
        /// </summary>
        /// <param name="filePath">The path to the file to upload.</param>
        /// <returns>Analysis ID string, or null if upload fails.</returns>
        private async Task<string> UploadFile(string filePath)
        {
            try
            {
                using var form = new MultipartFormDataContent();
                using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                using var fileContent = new StreamContent(fileStream);

                fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                form.Add(fileContent, "file", Path.GetFileName(filePath));

                string requestUrl = "files";
                HttpResponseMessage response = await _httpClient.PostAsync(requestUrl, form);
                response.EnsureSuccessStatusCode();

                string jsonResponse = await response.Content.ReadAsStringAsync();
                _mw.LogMessage($"File uploaded successfully. Analysis initiated.");

                // Parse and return analysis ID
                using JsonDocument doc = JsonDocument.Parse(jsonResponse);
                JsonElement root = doc.RootElement;

                if (root.TryGetProperty("data", out JsonElement data) &&
                    data.TryGetProperty("id", out JsonElement id))
                {
                    return id.GetString();
                }

                return null;
            }
            catch (HttpRequestException e)
            {
                _mw.LogMessage($"Upload Request Error: {e.Message}");
                if (e.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                {
                    _mw.LogMessage("Rate limit exceeded. Please wait before trying again.");
                }
                return null;
            }
            catch (Exception e)
            {
                _mw.LogMessage($"An unexpected error occurred during upload: {e.Message}");
                return null;
            }
        }

        /// <summary>
        /// Gets the analysis results using the analysis ID.
        /// </summary>
        /// <param name="analysisId">The analysis ID returned from the upload.</param>
        /// <returns>JSON response containing the analysis results, or null if request fails.</returns>
        private async Task<string> GetAnalysisResults(string analysisId)
        {
            try
            {
                string requestUrl = $"analyses/{analysisId}";
                HttpResponseMessage response = await _httpClient.GetAsync(requestUrl);
                response.EnsureSuccessStatusCode();

                string jsonResponse = await response.Content.ReadAsStringAsync();
                return jsonResponse;
            }
            catch (HttpRequestException e)
            {
                _mw.LogMessage($"Analysis Request Error: {e.Message}");
                if (e.StatusCode == System.Net.HttpStatusCode.TooManyRequests)
                {
                    _mw.LogMessage("Rate limit exceeded. Please wait before trying again.");
                }
                return null;
            }
            catch (Exception e)
            {
                _mw.LogMessage($"An unexpected error occurred while getting analysis: {e.Message}");
                return null;
            }
        }

        /// <summary>
        /// Check if analysis is complete based on the response
        /// </summary>
        /// <param name="analysisResponse">The analysis response JSON.</param>
        /// <returns>True if analysis is complete, false otherwise.</returns>
        private bool IsAnalysisComplete(string analysisResponse)
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(analysisResponse);
                JsonElement root = doc.RootElement;

                if (root.TryGetProperty("data", out JsonElement data) &&
                    data.TryGetProperty("attributes", out JsonElement attributes) &&
                    attributes.TryGetProperty("status", out JsonElement status))
                {
                    string statusValue = status.GetString();
                    return statusValue == "completed";
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Parses a raw JSON response into a complete file analysis object.
        /// </summary>
        /// <param name="jsonResponse">The raw JSON string</param>
        /// <returns>A VirusTotalFileAnalysis object with all details, or null if parsing fails.</returns>
        public VirusTotalFileAnalysisResults? ParseFileAnalysis(string jsonResponse)
        {
            if (string.IsNullOrEmpty(jsonResponse))
            {
                return null;
            }

            try
            {
                using JsonDocument doc = JsonDocument.Parse(jsonResponse);
                JsonElement root = doc.RootElement;
                JsonElement data = root.GetProperty("data");
                JsonElement attributes = data.GetProperty("attributes");

                // Check if analysis response from upload or response from hash lookup
                bool isAnalysisResponse = data.GetProperty("type").GetString() == "analysis";

                JsonElement stats;
                JsonElement fileInfo;

                if (isAnalysisResponse)
                {
                    //For upload analysis
                    stats = attributes.GetProperty("stats");
                    // Get File info
                    fileInfo = root.GetProperty("meta").GetProperty("file_info");
                }
                else
                {
                    // For hash lookup responses
                    //get last analysis stats
                    stats = attributes.GetProperty("last_analysis_stats");
                    fileInfo = attributes;
                }

                // Extract filename using improved logic
                string extractedFilename = ExtractFilename(attributes, fileInfo, isAnalysisResponse);

                var analysis = new VirusTotalFileAnalysisResults
                {
                    // Scan statistics
                    MaliciousDetections = stats.GetProperty("malicious").GetInt32(),
                    SuspiciousDetections = stats.GetProperty("suspicious").GetInt32(),
                    UndetectedCount = stats.GetProperty("undetected").GetInt32(),

                    // File attributes with improved filename extraction
                    FileName = extractedFilename,
                    MeaningfulName = extractedFilename, // For backward compatibility
                    Sha256 = fileInfo.TryGetProperty("sha256", out var sha256) ? sha256.GetString() : "N/A",
                    Md5 = fileInfo.TryGetProperty("md5", out var md5) ? md5.GetString() : "N/A",
                    FileSize = fileInfo.TryGetProperty("size", out var size) ? size.GetInt64() : 0,
                    Permalink = data.TryGetProperty("links", out var links) && links.TryGetProperty("self", out var self)
                               ? self.GetString() : "N/A",

                    // Convert Unix timestamp to DateTime
                    LastAnalysisDate = isAnalysisResponse && attributes.TryGetProperty("date", out var analysisDate) && analysisDate.TryGetInt64(out long unixTime1)
                                        ? DateTimeOffset.FromUnixTimeSeconds(unixTime1).DateTime
                                        : attributes.TryGetProperty("last_analysis_date", out var date) && date.TryGetInt64(out long unixTime2)
                                        ? DateTimeOffset.FromUnixTimeSeconds(unixTime2).DateTime
                                        : DateTime.MinValue
                };

                // Calculate properties
                analysis.IsMalicious = analysis.MaliciousDetections > 0;
                analysis.TotalScans = analysis.MaliciousDetections +
                                      analysis.SuspiciousDetections +
                                      analysis.UndetectedCount +
                                      stats.GetProperty("harmless").GetInt32() +
                                      (stats.TryGetProperty("timeout", out var timeout) ? timeout.GetInt32() : 0);

                // gets the common threat name
                if (attributes.TryGetProperty("popular_threat_classification", out var threatClassification) &&
                    threatClassification.TryGetProperty("suggested_threat_label", out var threatLabelElement))
                {
                    analysis.ThreatLabel = threatLabelElement.GetString();
                }
                else
                {
                    analysis.ThreatLabel = "N/A";
                }

                return analysis;
            }
            catch (JsonException e)
            {
                _mw.LogMessage($"JSON Parsing Error: {e.Message}");
                return null;
            }
            catch (KeyNotFoundException e)
            {
                _mw.LogMessage($"Could not find an expected key in JSON response: {e.Message}");
                return null;
            }
        }

        /// <summary>
        /// Extracts filename from VirusTotal response using multiple fallback strategies
        /// </summary>
        /// <param name="attributes">The attributes section of the response</param>
        /// <param name="fileInfo">The file info section</param>
        /// <param name="isAnalysisResponse">Whether this is an analysis or hash lookup response</param>
        /// <returns>Best available filename</returns>
        private string ExtractFilename(JsonElement attributes, JsonElement fileInfo, bool isAnalysisResponse)
        {
            // Check meaningful_name
            if (attributes.TryGetProperty("meaningful_name", out var meaningfulName) &&
                !string.IsNullOrWhiteSpace(meaningfulName.GetString()))
            {
                return meaningfulName.GetString();
            }

            // Check names array (most common location)
            if (attributes.TryGetProperty("names", out var names) && names.ValueKind == JsonValueKind.Array)
            {
                var namesList = names.EnumerateArray()
                    .Select(n => n.GetString())
                    .Where(n => !string.IsNullOrWhiteSpace(n))
                    .ToList();

                if (namesList.Any())
                {
                    // Return the most common name or first one
                    return namesList.GroupBy(x => x)
                        .OrderByDescending(g => g.Count())
                        .First().Key;
                }
            }

            // Check type_description (sometimes contains filename info)
            if (attributes.TryGetProperty("type_description", out var typeDesc) &&
                !string.IsNullOrWhiteSpace(typeDesc.GetString()))
            {
                string desc = typeDesc.GetString();
                // Extract filename if it contains one (e.g., "Executable file (example.exe)")
                var match = System.Text.RegularExpressions.Regex.Match(desc, @"\(([^)]+\.[^)]+)\)");
                if (match.Success)
                {
                    return match.Groups[1].Value;
                }
            }

            // Check file info for original name (for upload responses)
            if (isAnalysisResponse && fileInfo.TryGetProperty("name", out var fileName) &&
                !string.IsNullOrWhiteSpace(fileName.GetString()))
            {
                return fileName.GetString();
            }

            // Check submission_names array
            if (attributes.TryGetProperty("submission_names", out var submissionNames) &&
                submissionNames.ValueKind == JsonValueKind.Array)
            {
                var submissionNamesList = submissionNames.EnumerateArray()
                    .Select(n => n.GetString())
                    .Where(n => !string.IsNullOrWhiteSpace(n))
                    .ToList();

                if (submissionNamesList.Any())
                {
                    return submissionNamesList.First();
                }
            }

            // Priority 6: Generate filename from hash and file type
            string fileExtension = GetFileExtension(attributes);
            if (fileInfo.TryGetProperty("sha256", out var sha256))
            {
                return $"{sha256.GetString().Substring(0, 8)}{fileExtension}";
            }
            if (fileInfo.TryGetProperty("md5", out var md5))
            {
                return $"{md5.GetString().Substring(0, 8)}{fileExtension}";
            }

            return "unknown_file";
        }

        /// <summary>
        /// Determines file extension based on VirusTotal response data
        /// </summary>
        /// <param name="attributes">The attributes section of the response</param>
        /// <returns>Appropriate file extension</returns>
        private string GetFileExtension(JsonElement attributes)
        {
            if (attributes.TryGetProperty("type_description", out var typeDesc))
            {
                string desc = typeDesc.GetString().ToLower();

                // Common file type mappings
                if (desc.Contains("executable") || desc.Contains(".exe")) return ".exe";
                if (desc.Contains("dll") || desc.Contains("dynamic link library")) return ".dll";
                if (desc.Contains("pdf")) return ".pdf";
                if (desc.Contains("zip") || desc.Contains("archive")) return ".zip";
                if (desc.Contains("document") || desc.Contains("word")) return ".doc";
                if (desc.Contains("image") || desc.Contains("bitmap")) return ".img";
                if (desc.Contains("text")) return ".txt";
                if (desc.Contains("script")) return ".bat";
                if (desc.Contains("msi") || desc.Contains("installer")) return ".msi";
                if (desc.Contains("jar")) return ".jar";
                if (desc.Contains("apk")) return ".apk";
            }

            if (attributes.TryGetProperty("magic", out var magic))
            {
                string magicDesc = magic.GetString().ToLower();
                if (magicDesc.Contains("pe32")) return ".exe";
                if (magicDesc.Contains("pdf")) return ".pdf";
                if (magicDesc.Contains("zip")) return ".zip";
                if (magicDesc.Contains("elf")) return ".elf";
                if (magicDesc.Contains("mach-o")) return ".bin";
            }

            // Check file type tags
            if (attributes.TryGetProperty("type_tags", out var typeTags) &&
                typeTags.ValueKind == JsonValueKind.Array)
            {
                var tags = typeTags.EnumerateArray().Select(t => t.GetString().ToLower()).ToList();
                if (tags.Contains("executable")) return ".exe";
                if (tags.Contains("pe32")) return ".exe";
                if (tags.Contains("pdf")) return ".pdf";
                if (tags.Contains("archive")) return ".zip";
                if (tags.Contains("installer")) return ".msi";
            }

            return ".bin"; // Default binary extension
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}