using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NAZARICK_Protocol.service
{
    internal class HashCalc
    {
        /// Calculates the SHA256 hash of a file.       
        public static string CalculateSha256(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File not found: {filePath}");
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                using (FileStream fileStream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = sha256.ComputeHash(fileStream);
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in hashBytes)
                    {
                        sb.Append(b.ToString("x2")); // Convert to hexadecimal
                    }
                    return sb.ToString();
                }
            }
        }


        /// Calculates the MD5 hash of a file.        
        public static string CalculateMd5(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"File not found: {filePath}");
            }

            using (MD5 md5 = MD5.Create())
            {
                using (FileStream fileStream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = md5.ComputeHash(fileStream);
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in hashBytes)
                    {
                        sb.Append(b.ToString("x2")); // Convert to hexadecimal
                    }
                    return sb.ToString();
                }
            }
        }
    }
}
