using System;
using Microsoft.Win32;
using AntiVMSpoofTool.Utils;

namespace AntiVMSpoofTool.Services
{
    public static class RegistryHelper
    {
        public static void SetRegistryValue(string keyPath, string valueName, object value)
        {
            try
            {
                Registry.SetValue(keyPath, valueName, value);
                Logger.Log($"Registry value set successfully: {keyPath}\\{valueName} = {value}");
            }
            catch (UnauthorizedAccessException)
            {
                string error = $"Access denied while setting registry key: {keyPath}\\{valueName}. Ensure the application is running with administrative privileges.";
                Logger.Log(error);
                throw new UnauthorizedAccessException(error);
            }
            catch (Exception ex)
            {
                string error = $"Failed to set registry key {keyPath}\\{valueName}: {ex.Message}";
                Logger.Log(error);
                throw new Exception(error, ex);
            }
        }

        public static object GetRegistryValue(string keyPath, string valueName, object defaultValue = null)
        {
            try
            {
                object value = Registry.GetValue(keyPath, valueName, defaultValue);
                Logger.Log($"Registry value read successfully: {keyPath}\\{valueName}");
                return value;
            }
            catch (UnauthorizedAccessException)
            {
                string error = $"Access denied while reading registry key: {keyPath}\\{valueName}";
                Logger.Log(error);
                throw new UnauthorizedAccessException(error);
            }
            catch (Exception ex)
            {
                string error = $"Failed to read registry key {keyPath}\\{valueName}: {ex.Message}";
                Logger.Log(error);
                throw new Exception(error, ex);
            }
        }

        public static void DeleteRegistryValue(string keyPath, string valueName)
        {
            try
            {
                string[] pathParts = keyPath.Split('\\');
                string hive = pathParts[0];
                string subKeyPath = string.Join("\\", pathParts, 1, pathParts.Length - 1);

                using (RegistryKey key = GetRegistryKey(hive))
                {
                    using (RegistryKey subKey = key.OpenSubKey(subKeyPath, true))
                    {
                        if (subKey != null)
                        {
                            subKey.DeleteValue(valueName, false);
                            Logger.Log($"Registry value deleted successfully: {keyPath}\\{valueName}");
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                string error = $"Access denied while deleting registry key: {keyPath}\\{valueName}";
                Logger.Log(error);
                throw new UnauthorizedAccessException(error);
            }
            catch (Exception ex)
            {
                string error = $"Failed to delete registry key {keyPath}\\{valueName}: {ex.Message}";
                Logger.Log(error);
                throw new Exception(error, ex);
            }
        }

        private static RegistryKey GetRegistryKey(string hive)
        {
            return hive.ToUpper() switch
            {
                "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
                "HKEY_CURRENT_USER" => Registry.CurrentUser,
                "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
                "HKEY_USERS" => Registry.Users,
                "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig,
                _ => throw new ArgumentException($"Invalid registry hive: {hive}")
            };
        }
    }
}
