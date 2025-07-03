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

        public static async Task<(bool IsVM, Dictionary<string, bool> Details)> DetectVirtualization()
        {
            return await Task.Run(() =>
            {
                var detectionResults = new Dictionary<string, bool>();
                try
                {
                    // BIOS and System Information
                    detectionResults["BIOS Signature"] = CheckSystemBiosName();
                    detectionResults["System Manufacturer"] = CheckSystemManufacturer();
                    
                    // Hardware Checks
                    detectionResults["Video Controller"] = CheckVideoController();
                    detectionResults["Processor Features"] = CheckProcessorName();
                    detectionResults["MAC Address"] = CheckMACAddress();
                    detectionResults["Memory Configuration"] = CheckMemoryConfiguration();
                    
                    // Advanced Checks
                    detectionResults["CPU Instructions"] = CheckCPUInstructions();
                    detectionResults["Registry Artifacts"] = CheckRegistryArtifacts();
                    detectionResults["Process List"] = CheckVMProcesses();
                    detectionResults["Services"] = CheckVMServices();
                    detectionResults["Driver Signatures"] = CheckDriverSignatures();
                    detectionResults["Hardware IDs"] = CheckHardwareIDs();
                    
                    // Performance Characteristics
                    detectionResults["Thermal Information"] = CheckThermalInformation();
                    detectionResults["Storage Characteristics"] = CheckStorageCharacteristics();
                    
                    // VM-Specific Files
                    detectionResults["VM Files"] = CheckVMFiles();

                    bool isVM = detectionResults.Values.Any(x => x);
                    Logger.Log($"Virtualization detection completed. Found {detectionResults.Count(x => x.Value)} indicators.");
                    
                    return (isVM, detectionResults);
                }
                catch (Exception ex)
                {
                    Logger.Log($"Error in DetectVirtualization: {ex.Message}");
                    throw new Exception("Failed to detect virtualization", ex);
                }
            });
        }

        private static bool CheckMACAddress()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string macAddress = obj["MACAddress"]?.ToString()?.ToUpper() ?? "";
                        // Check for known VM vendor MAC address prefixes
                        if (macAddress.StartsWith("00:05:69") || // VMware
                            macAddress.StartsWith("00:0C:29") || // VMware
                            macAddress.StartsWith("00:1C:14") || // VMware
                            macAddress.StartsWith("00:50:56") || // VMware
                            macAddress.StartsWith("08:00:27") || // VirtualBox
                            macAddress.StartsWith("52:54:00"))   // QEMU/KVM
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking MAC address: {ex.Message}");
            }
            return false;
        }

        private static bool CheckMemoryConfiguration()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        // Check for suspicious memory configurations
                        ulong totalPhysicalMemory = Convert.ToUInt64(obj["TotalPhysicalMemory"]);
                        if (totalPhysicalMemory < 2147483648) // Less than 2GB
                        {
                            return true;
                        }

                        // Check if memory is a perfect power of 2 (common in VMs)
                        double log = Math.Log(totalPhysicalMemory, 2);
                        if (log == Math.Floor(log))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking memory configuration: {ex.Message}");
            }
            return false;
        }

        private static bool CheckCPUInstructions()
        {
            try
            {
                // Check if CPU virtualization extensions are exposed
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string features = obj["Description"]?.ToString().ToLower() ?? "";
                        if (features.Contains("hypervisor") ||
                            features.Contains("vmx") ||
                            features.Contains("svm"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking CPU instructions: {ex.Message}");
            }
            return false;
        }

        private static bool CheckRegistryArtifacts()
        {
            try
            {
                // Check common VM registry keys
                string[] vmRegistryPaths = {
                    @"SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers",
                    @"SYSTEM\CurrentControlSet\Services\Disk\Enum",
                    @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 2",
                    @"SYSTEM\CurrentControlSet\Control\SystemInformation",
                    @"SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers"
                };

                foreach (string path in vmRegistryPaths)
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            string[] valueNames = key.GetValueNames();
                            foreach (string value in valueNames)
                            {
                                string data = key.GetValue(value)?.ToString().ToLower() ?? "";
                                if (data.Contains("vmware") ||
                                    data.Contains("virtual") ||
                                    data.Contains("vbox") ||
                                    data.Contains("qemu"))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking registry artifacts: {ex.Message}");
            }
            return false;
        }

        private static bool CheckVMProcesses()
        {
            try
            {
                string[] vmProcesses = {
                    "vmtoolsd",
                    "vmwaretray",
                    "vmwareuser",
                    "VGAuthService",
                    "vmacthlp",
                    "vboxservice",
                    "vboxtray",
                    "vmusrvc",
                    "prl_tools",
                    "prl_cc"
                };

                foreach (var process in System.Diagnostics.Process.GetProcesses())
                {
                    if (vmProcesses.Contains(process.ProcessName.ToLower()))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking VM processes: {ex.Message}");
            }
            return false;
        }

        private static bool CheckVMServices()
        {
            try
            {
                string[] vmServices = {
                    "vmtools",
                    "vmware",
                    "vboxservice",
                    "parallels"
                };

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service"))
                {
                    foreach (ManagementObject service in searcher.Get())
                    {
                        string serviceName = service["Name"]?.ToString().ToLower() ?? "";
                        if (vmServices.Any(vm => serviceName.Contains(vm)))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking VM services: {ex.Message}");
            }
            return false;
        }

        private static bool CheckDriverSignatures()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SystemDriver"))
                {
                    foreach (ManagementObject driver in searcher.Get())
                    {
                        string driverName = driver["Name"]?.ToString().ToLower() ?? "";
                        if (driverName.Contains("vmmouse") ||
                            driverName.Contains("vmscsi") ||
                            driverName.Contains("vboxguest") ||
                            driverName.Contains("vmxnet"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking driver signatures: {ex.Message}");
            }
            return false;
        }

        private static bool CheckHardwareIDs()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity"))
                {
                    foreach (ManagementObject device in searcher.Get())
                    {
                        string hardwareID = device["HardwareID"]?.ToString().ToLower() ?? "";
                        if (hardwareID.Contains("ven_15ad") || // VMware
                            hardwareID.Contains("ven_80ee") || // VirtualBox
                            hardwareID.Contains("qemu"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking hardware IDs: {ex.Message}");
            }
            return false;
        }

        private static bool CheckThermalInformation()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_TemperatureProbe"))
                {
                    // Most VMs don't implement temperature sensors
                    if (!searcher.Get().GetEnumerator().MoveNext())
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking thermal information: {ex.Message}");
                // Many VMs will throw an exception here due to missing WMI classes
                return true;
            }
            return false;
        }

        private static bool CheckStorageCharacteristics()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject disk in searcher.Get())
                    {
                        string model = disk["Model"]?.ToString().ToLower() ?? "";
                        string manufacturer = disk["Manufacturer"]?.ToString().ToLower() ?? "";
                        
                        if (model.Contains("virtual") ||
                            model.Contains("vmware") ||
                            model.Contains("vbox") ||
                            manufacturer.Contains("vmware") ||
                            manufacturer.Contains("virtualbox") ||
                            manufacturer.Contains("qemu"))
                        {
                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking storage characteristics: {ex.Message}");
            }
            return false;
        }

        private static bool CheckVMFiles()
        {
            string[] vmPaths = {
                @"C:\Windows\System32\drivers\vmmouse.sys",
                @"C:\Windows\System32\drivers\vmhgfs.sys",
                @"C:\Windows\System32\drivers\VBoxMouse.sys",
                @"C:\Windows\System32\drivers\VBoxGuest.sys",
                @"C:\Windows\System32\drivers\VBoxSF.sys",
                @"C:\Windows\System32\drivers\VBoxVideo.sys",
                @"C:\Program Files\VMware",
                @"C:\Program Files\Oracle\VirtualBox Guest Additions"
            };

            try
            {
                foreach (string path in vmPaths)
                {
                    if (File.Exists(path) || Directory.Exists(path))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error checking VM files: {ex.Message}");
            }
            return false;
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
