using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace NAZARICK_Protocol.service
{
    internal class VirusTotalAPI
    {

        private readonly HttpClient _httpClient;
        private readonly string _apiKey;
        private const string BaseUrl = "https://www.virustotal.com/api/v3/";
        MainWindow _mw;

        public VirusTotalAPI(string apiKey, MainWindow mw)
        {
            _apiKey = apiKey;
            _mw = mw;
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
            _httpClient.BaseAddress = new Uri(BaseUrl);
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


        // =============== NEW, COMPREHENSIVE PARSER ===============
        /// <summary>
        /// Parses a raw JSON response into a complete file analysis object.
        /// </summary>
        /// <param name="jsonResponse">The raw JSON string from the CheckFileHash method.</param>
        /// <returns>A VirusTotalFileAnalysis object with all details, or null if parsing fails.</returns>
        public VirusTotalFileAnalysis? ParseFileAnalysis(string jsonResponse)
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
                JsonElement stats = attributes.GetProperty("last_analysis_stats");

                var analysis = new VirusTotalFileAnalysis
                {
                    // Scan statistics
                    MaliciousDetections = stats.GetProperty("malicious").GetInt32(),
                    SuspiciousDetections = stats.GetProperty("suspicious").GetInt32(),
                    UndetectedCount = stats.GetProperty("undetected").GetInt32(),

                    // File attributes
                    MeaningfulName = attributes.TryGetProperty("meaningful_name", out var name) ? name.GetString() : "N/A",
                    Sha256 = attributes.TryGetProperty("sha256", out var sha256) ? sha256.GetString() : "N/A",
                    Md5 = attributes.TryGetProperty("md5", out var md5) ? md5.GetString() : "N/A",
                    FileSize = attributes.TryGetProperty("size", out var size) ? size.GetInt64() : 0,
                    Permalink = data.GetProperty("links").GetProperty("self").GetString(),

                    // Convert Unix timestamp to DateTime
                    LastAnalysisDate = attributes.TryGetProperty("last_analysis_date", out var date) && date.TryGetInt64(out long unixTime)
                                        ? DateTimeOffset.FromUnixTimeSeconds(unixTime).DateTime
                                        : DateTime.MinValue
                };

                // Calculated properties
                analysis.IsMalicious = analysis.MaliciousDetections > 0;
                analysis.TotalScans = analysis.MaliciousDetections +
                                      analysis.SuspiciousDetections +
                                      analysis.UndetectedCount +
                                      stats.GetProperty("harmless").GetInt32() +
                                      stats.GetProperty("timeout").GetInt32();

                // Try to get the common threat name, if available
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



    }
}
