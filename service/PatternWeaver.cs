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
        [DllImport("C:\\Users\\Aurojit-VM1\\source\\repos\\YggdrasilPatternWeaver\\x64\\Debug\\YggdrasilPatternWeaver.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr init_yara();

        [DllImport("C:\\Users\\Aurojit-VM1\\source\\repos\\YggdrasilPatternWeaver\\x64\\Debug\\YggdrasilPatternWeaver.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void free_string(IntPtr ptr);

        public string info()
        {
            IntPtr ptr = IntPtr.Zero; // Initialize pointer to null
            string result = string.Empty;
            try
            {
                // Call the C++ function. It returns an IntPtr representing the memory address
                // of the C-style string allocated in the DLL.
                ptr = init_yara();

                // Check if the pointer is not null (i.e., memory was successfully allocated)
                if (ptr != IntPtr.Zero)
                {
                    // Marshal.PtrToStringAnsi converts a pointer to a null-terminated ANSI C-style string (char*)
                    // into a managed C# System.String. If your C++ DLL uses wchar_t*, you would use PtrToStringUni.
                    result = Marshal.PtrToStringAnsi(ptr);
                }
                else
                {
                    // Handle the case where the C++ function failed to allocate memory or returned null
                    Console.WriteLine("C++ init_yara returned a null pointer.");
                    result = "Error: Could not retrieve message from DLL.";
                }
            }
            finally
            {
                // IMPORTANT: This block ensures that the memory is freed even if an exception occurs
                // during the marshalling process.
                if (ptr != IntPtr.Zero)
                {
                    // Call the C++ function to free the memory that it allocated.
                    // This prevents memory leaks.
                    free_string(ptr);
                }
            }

            return result;
        }
    }
}
