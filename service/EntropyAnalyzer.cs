using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NAZARICK_Protocol.service
{
    public class EntropyAnalyzer
    {
        /// <summary>
        /// Calculates the Shannon Entropy for a given file.
        /// </summary>
        /// <param name="filePath">The path to the file to analyze.</param>
        /// <returns>The entropy value (a double between 0.0 and 8.0). Returns -1.0 if the file cannot be read.</returns>
        public double AnalyzeFileEntropy(string filePath)
        {
            try
            {
                // Read all bytes from the file.
                byte[] fileBytes = File.ReadAllBytes(filePath);

                // Perform the entropy calculation on the byte array.
                return CalculateShannonEntropy(fileBytes);
            }
            catch (IOException ex)
            {
                Console.WriteLine($"Error reading file: {ex.Message}");
                return -1.0;
            }
            catch (Exception ex)
            {             
                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                return -1.0;
            }
        }

        /// <summary>
        /// Calculates the Shannon entropy for a given byte array.
        /// Entropy is a measure of randomness or uncertainty.
        /// The formula is: E = -Σ(P(i) * log2(P(i))) for each byte value i.
        /// </summary>
        /// <param name="data">The byte array to analyze.</param>
        /// <returns>The entropy value (between 0 and 8).</returns>
        private double CalculateShannonEntropy(byte[] data)
        {
            // Returning 0 for empty or null data to avoid division by zero.
            if (data == null || data.Length == 0)
            {
                return 0.0;
            }

            // an array to store the frequency of each byte value (0-255).
            var byteCounts = new long[256];
            foreach (var b in data)
            {
                byteCounts[b]++;
            }

            double entropy = 0.0;
            long totalBytes = data.Length;

            
            for (int i = 0; i < 256; i++)
            {
                
                if (byteCounts[i] > 0)
                {
                    // Calculate the probability of this byte value appearing.
                    double probability = (double)byteCounts[i] / totalBytes;

                    // Add to the total entropy.
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return entropy;
        }
    }
}
