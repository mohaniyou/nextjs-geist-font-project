using System;
using System.IO;
using System.Windows.Controls;
using System.Windows.Threading;

namespace AntiVMSpoofTool.Utils
{
    public static class Logger
    {
        private static TextBox _outputTextBox;
        private static readonly string LogFilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "AntiVMSpoofTool",
            "logs.txt"
        );

        public static void Init(TextBox output)
        {
            _outputTextBox = output;
            
            try
            {
                // Create the logs directory if it doesn't exist
                string logDirectory = Path.GetDirectoryName(LogFilePath);
                if (!Directory.Exists(logDirectory))
                {
                    Directory.CreateDirectory(logDirectory);
                }

                // Add initial log entry
                Log("Logger initialized");
            }
            catch (Exception ex)
            {
                // If we can't create the log directory, just write to the UI
                LogToUI($"Failed to initialize file logging: {ex.Message}");
            }
        }

        public static void Log(string message)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string logMessage = $"[{timestamp}] {message}";

            LogToUI(logMessage);
            LogToFile(logMessage);
        }

        private static void LogToUI(string message)
        {
            if (_outputTextBox != null)
            {
                // Ensure UI updates happen on the UI thread
                _outputTextBox.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                {
                    _outputTextBox.AppendText(message + Environment.NewLine);
                    _outputTextBox.ScrollToEnd();
                }));
            }
        }

        private static void LogToFile(string message)
        {
            try
            {
                // Append the log message to the file
                File.AppendAllText(LogFilePath, message + Environment.NewLine);
            }
            catch (Exception)
            {
                // If file logging fails, just continue with UI logging
                // We don't want to throw exceptions here as it could disrupt the application
            }
        }

        public static void ClearLogs()
        {
            try
            {
                if (_outputTextBox != null)
                {
                    _outputTextBox.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                    {
                        _outputTextBox.Clear();
                    }));
                }

                if (File.Exists(LogFilePath))
                {
                    File.WriteAllText(LogFilePath, string.Empty);
                }

                Log("Logs cleared");
            }
            catch (Exception ex)
            {
                LogToUI($"Failed to clear logs: {ex.Message}");
            }
        }

        public static string GetLogFilePath()
        {
            return LogFilePath;
        }
    }
}
