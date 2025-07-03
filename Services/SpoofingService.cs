using System;
using System.Threading.Tasks;
using System.Management;
using Microsoft.Win32;
using AntiVMSpoofTool.Utils;

namespace AntiVMSpoofTool.Services
{
    public static class SpoofingService
    {
        private const string BIOS_KEY_PATH = @"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS";
        private const string MACHINE_GUID_KEY_PATH = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography";
        private const string COMPUTER_NAME_KEY_PATH = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName";

        public static async Task SpoofBIOS()
        {
            await Task.Run(() =>
            {
                try
                {
                    // Set BIOS information to appear as a gaming motherboard
                    RegistryHelper.SetRegistryValue(BIOS_KEY_PATH, "SystemManufacturer", "ASUSTeK COMPUTER INC.");
                    RegistryHelper.SetRegistryValue(BIOS_KEY_PATH, "SystemProductName", "ROG STRIX Z590-E GAMING");
                    RegistryHelper.SetRegistryValue(BIOS_KEY_PATH, "SystemVersion", "Rev 1.xx");
                    RegistryHelper.SetRegistryValue(BIOS_KEY_PATH, "SystemFamily", "Gaming");
                    
                    // Set additional BIOS values
                    RegistryHelper.SetRegistryValue(BIOS_KEY_PATH, "BaseBoardManufacturer", "ASUSTeK COMPUTER INC.");
                    RegistryHelper.SetRegistryValue(BIOS_KEY_PATH, "BaseBoardProduct", "ROG STRIX Z590-E GAMING");
                    RegistryHelper.SetRegistryValue(BIOS_KEY_PATH, "BaseBoardVersion", "Rev X.0x");
                }
                catch (Exception ex)
                {
                    Logger.Log($"Error in SpoofBIOS: {ex.Message}");
                    throw new Exception("Failed to spoof BIOS information", ex);
                }
            });
        }

        public static async Task ChangeMachineGuid()
        {
            await Task.Run(() =>
            {
                try
                {
                    string newGuid = Guid.NewGuid().ToString();
                    RegistryHelper.SetRegistryValue(MACHINE_GUID_KEY_PATH, "MachineGuid", newGuid);
                }
                catch (Exception ex)
                {
                    Logger.Log($"Error in ChangeMachineGuid: {ex.Message}");
                    throw new Exception("Failed to change Machine GUID", ex);
                }
            });
        }

        public static async Task ChangeHostName(string newHostName)
        {
            await Task.Run(() =>
            {
                try
                {
                    RegistryHelper.SetRegistryValue(COMPUTER_NAME_KEY_PATH, "ComputerName", newHostName);
                    
                    // Also update the active computer name
                    RegistryHelper.SetRegistryValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
                        "ComputerName", newHostName);
                    
                    // Update Hostname in TCP/IP parameters
                    RegistryHelper.SetRegistryValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                        "Hostname", newHostName);
                    RegistryHelper.SetRegistryValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                        "NV Hostname", newHostName);
                }
                catch (Exception ex)
                {
                    Logger.Log($"Error in ChangeHostName: {ex.Message}");
                    throw new Exception("Failed to change hostname", ex);
                }
            });
        }

        public static async Task<bool> DetectVirtualization()
        {
            return await Task.Run(() =>
            {
                try
                {
                    // Check multiple virtualization indicators
                    if (CheckSystemBiosName() || 
                        CheckVideoController() || 
                        CheckProcessorName() || 
                        CheckSystemManufacturer())
                    {
                        return true;
                    }

                    return false;
                }
                catch (Exception ex)
                {
                    Logger.Log($"Error in DetectVirtualization: {ex.Message}");
                    throw new Exception("Failed to detect virtualization", ex);
                }
            });
        }

        private static bool CheckSystemBiosName()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string manufacturer = obj["Manufacturer"]?.ToString().ToLower() ?? "";
                        string version = obj["Version"]?.ToString().ToLower() ?? "";
                        
                        if (manufacturer.Contains("vmware") ||
                            manufacturer.Contains("virtualbox") ||
                            manufacturer.Contains("qemu") ||
                            version.Contains("virtual"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking BIOS: {ex.Message}");
            }
            return false;
        }

        private static bool CheckVideoController()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["Name"]?.ToString().ToLower() ?? "";
                        if (name.Contains("vmware") ||
                            name.Contains("virtualbox") ||
                            name.Contains("qemu") ||
                            name.Contains("virtual"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking video controller: {ex.Message}");
            }
            return false;
        }

        private static bool CheckProcessorName()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["Name"]?.ToString().ToLower() ?? "";
                        if (name.Contains("virtual") ||
                            name.Contains("qemu"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking processor: {ex.Message}");
            }
            return false;
        }

        private static bool CheckSystemManufacturer()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string manufacturer = obj["Manufacturer"]?.ToString().ToLower() ?? "";
                        string model = obj["Model"]?.ToString().ToLower() ?? "";
                        
                        if (manufacturer.Contains("vmware") ||
                            manufacturer.Contains("virtualbox") ||
                            manufacturer.Contains("qemu") ||
                            model.Contains("virtual"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking system manufacturer: {ex.Message}");
            }
            return false;
        }
    }
}
