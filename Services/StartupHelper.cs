using System;
using System.Reflection;
using Microsoft.Win32;
using AntiVMSpoofTool.Utils;

namespace AntiVMSpoofTool.Services
{
    public static class StartupHelper
    {
        private const string StartupKey = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run";
        private const string AppName = "AntiVMSpoofTool";

        public static void EnableStartup()
        {
            try
            {
                string appPath = Assembly.GetExecutingAssembly().Location;
                
                // If the executable is a .dll (common in .NET Core), adjust the path to point to the .exe
                if (appPath.EndsWith(".dll"))
                {
                    appPath = appPath.Substring(0, appPath.Length - 4) + ".exe";
                }

                // Add quotes around the path in case it contains spaces
                appPath = $"\"{appPath}\"";

                RegistryHelper.SetRegistryValue(StartupKey, AppName, appPath);
                Logger.Log("Application startup enabled successfully");
            }
            catch (Exception ex)
            {
                string error = $"Failed to enable startup: {ex.Message}";
                Logger.Log(error);
                throw new Exception(error, ex);
            }
        }

        public static void DisableStartup()
        {
            try
            {
                RegistryHelper.DeleteRegistryValue(StartupKey, AppName);
                Logger.Log("Application startup disabled successfully");
            }
            catch (Exception ex)
            {
                string error = $"Failed to disable startup: {ex.Message}";
                Logger.Log(error);
                throw new Exception(error, ex);
            }
        }

        public static bool IsStartupEnabled()
        {
            try
            {
                object value = RegistryHelper.GetRegistryValue(StartupKey, AppName);
                return value != null;
            }
            catch
            {
                return false;
            }
        }
    }
}
