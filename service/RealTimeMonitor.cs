using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NAZARICK_Protocol.service
{
    internal class RealTimeMonitor : IDisposable
    {
        private FileSystemWatcher _watcher;
        private readonly string _watchPath;

        /// <summary>
        /// Event that is triggered when a file is created, updated, or renamed.
        /// The string argument is the full path of the affected file.
        /// </summary>
        public event Action<string> FileChanged;

        /// <summary>
        /// Initializes a new instance of the RealTimeMonitor class.
        /// </summary>
        /// <param name="path">The absolute path of the directory to monitor.</param>
        /// <exception cref="ArgumentException">Thrown if the path is null, empty, or not a valid directory.</exception>
        public RealTimeMonitor(string path)
        {
            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
                throw new ArgumentException("The specified path is invalid or does not exist.", nameof(path));
            }
            _watchPath = path;
        }

        public void Start()
        {
            if (_watcher != null)
            {
                return; // Already running
            }

            _watcher = new FileSystemWatcher(_watchPath)
            {
                // Watch for changes to the file's last write time and its name.
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName,
                Filter = "*.*",
                IncludeSubdirectories = true,
                EnableRaisingEvents = true
            };

            // All events (Created, Changed, Renamed) will trigger a method.
            _watcher.Created += OnFileEvent;
            _watcher.Changed += OnFileEvent;
            _watcher.Renamed += OnFileRenamed;
        }

        /// <summary>
        /// Stops monitoring the directory.
        /// </summary>
        public void Stop()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Created -= OnFileEvent;
                _watcher.Changed -= OnFileEvent;
                _watcher.Renamed -= OnFileRenamed;
                _watcher.Dispose();
                _watcher = null;
            }
        }

        /// <summary>
        /// Handles the Created and Changed events from the FileSystemWatcher.
        /// </summary>
        private void OnFileEvent(object sender, FileSystemEventArgs e)
        {
            // Trigger the event with the path of the file that was created or changed.
            FileChanged?.Invoke(e.FullPath);
        }

        /// <summary>
        /// Handles the Renamed event from the FileSystemWatcher.
        /// </summary>
        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            // Triggers the event with the new path of the file that was renamed.
            FileChanged?.Invoke(e.FullPath);
        }
        public void Dispose()
        {
            Stop();
        }
    }
}
