using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using AntiVMSpoofTool.Utils;

namespace AntiVMSpoofTool.Services
{
    public static class AdvancedDetectionService
    {
        private const uint CPUID_VENDOR_INFO = 0x40000000;
        private const uint CPUID_HYPERVISOR_INFO = 1;
        private const ushort VMWARE_PORT = 0x5658;
        private const uint VMWARE_MAGIC = 0x564D5868; // 'VMXh'

        public static async Task<Dictionary<string, bool>> DetectVirtualization()
        {
            return await Task.Run(() =>
            {
                var results = new Dictionary<string, bool>();

                try
                {
                    // CPUID Detection
                    DetectCPUID(results);

                    // VMware I/O Port Detection
                    DetectVMwarePort(results);

                    // Hardware Breakpoint Detection
                    DetectDebugger(results);

                    // Timing Attack Detection
                    DetectTimingAnomalies(results);

                    // Mouse/Input Detection
                    DetectInputAnomalies(results);

                    // Process/Program Detection
                    DetectSuspiciousProcesses(results);

                    // Screen Resolution Check
                    DetectScreenAnomalies(results);

                    // Mutex Detection
                    DetectVMMutexes(results);

                    // Performance Counter Analysis
                    DetectPerformanceAnomalies(results);

                    Logger.Log($"Advanced detection completed with {results.Count} checks");
                }
                catch (Exception ex)
                {
                    Logger.Log($"Error in advanced detection: {ex.Message}");
                }

                return results;
            });
        }

        private static void DetectCPUID(Dictionary<string, bool> results)
        {
            try
            {
                // Check hypervisor presence (Leaf 1)
                var (_, _, ecx, _) = NativeMethods.CPUID(CPUID_HYPERVISOR_INFO, 0);
                bool hypervisorPresent = (ecx & (1 << 31)) != 0;
                results["Hypervisor Present (CPUID)"] = hypervisorPresent;

                // Check vendor ID (Leaf 0x40000000)
                var (_, ebx, ecx2, edx) = NativeMethods.CPUID(CPUID_VENDOR_INFO, 0);
                var vendorId = Encoding.ASCII.GetString(
                    BitConverter.GetBytes(ebx)
                    .Concat(BitConverter.GetBytes(ecx2))
                    .Concat(BitConverter.GetBytes(edx))
                    .ToArray());

                results["VMware Vendor ID"] = vendorId.Contains("VMware");
                results["VBox Vendor ID"] = vendorId.Contains("VBoxVBox");
                results["KVM Vendor ID"] = vendorId.Contains("KVMKVMKVM");
            }
            catch (Exception ex)
            {
                Logger.Log($"Error in CPUID detection: {ex.Message}");
            }
        }

        private static void DetectVMwarePort(Dictionary<string, bool> results)
        {
            try
            {
                // Try VMware backdoor I/O port
                NativeMethods.OutPort(VMWARE_PORT, VMWARE_MAGIC);
                uint response = NativeMethods.InPort(VMWARE_PORT);
                results["VMware I/O Port"] = (response == VMWARE_MAGIC);
            }
            catch (Exception)
            {
                // If this fails, we're likely not in VMware
                results["VMware I/O Port"] = false;
            }
        }

        private static void DetectDebugger(Dictionary<string, bool> results)
        {
            try
            {
                // Check for debugger
                results["Debugger Present"] = NativeMethods.IsDebuggerPresent();

                // Check hardware breakpoints
                var context = new NativeMethods.CONTEXT();
                var thread = NativeMethods.GetCurrentThread();
                if (NativeMethods.GetThreadContext(thread, ref context))
                {
                    results["Hardware Breakpoints"] = context.Dr0 != 0 || context.Dr1 != 0 || 
                                                    context.Dr2 != 0 || context.Dr3 != 0;
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error in debugger detection: {ex.Message}");
            }
        }

        private static void DetectTimingAnomalies(Dictionary<string, bool> results)
        {
            try
            {
                // Measure execution time of a simple operation
                long frequency;
                NativeMethods.QueryPerformanceFrequency(out frequency);

                long start, end;
                NativeMethods.QueryPerformanceCounter(out start);
                
                // Perform some quick operations
                for (int i = 0; i < 1000; i++)
                {
                    Math.Sqrt(i);
                }

                NativeMethods.QueryPerformanceCounter(out end);

                // Calculate time taken in microseconds
                double microseconds = (end - start) * 1000000.0 / frequency;
                
                // If execution time is suspiciously high, might be running in a VM
                results["Timing Anomaly"] = microseconds > 1000; // Threshold of 1ms
            }
            catch (Exception ex)
            {
                Logger.Log($"Error in timing detection: {ex.Message}");
            }
        }

        private static void DetectInputAnomalies(Dictionary<string, bool> results)
        {
            try
            {
                // Check screen resolution
                int width = NativeMethods.GetSystemMetrics(NativeMethods.SM_CXSCREEN);
                int height = NativeMethods.GetSystemMetrics(NativeMethods.SM_CYSCREEN);

                // Common VM resolutions
                results["Common VM Resolution"] = (width == 800 && height == 600) ||
                                                (width == 1024 && height == 768);

                // Check mouse movement
                NativeMethods.POINT initialPos, finalPos;
                NativeMethods.GetCursorPos(out initialPos);
                Task.Delay(100).Wait(); // Wait a bit
                NativeMethods.GetCursorPos(out finalPos);

                results["No Mouse Movement"] = initialPos.X == finalPos.X && 
                                             initialPos.Y == finalPos.Y;
            }
            catch (Exception ex)
            {
                Logger.Log($"Error in input detection: {ex.Message}");
            }
        }

        private static void DetectSuspiciousProcesses(Dictionary<string, bool> results)
        {
            try
            {
                var suspiciousProcesses = new[]
                {
                    "vmtoolsd", "vmwaretray", "vmwareuser", "VGAuthService",
                    "vmacthlp", "vboxservice", "vboxtray", "wireshark",
                    "fiddler", "procmon", "filemon", "regmon", "processhacker",
                    "x64dbg", "ollydbg", "ida", "ida64", "immunity debugger"
                };

                foreach (var process in Process.GetProcesses())
                {
                    foreach (var suspicious in suspiciousProcesses)
                    {
                        if (process.ProcessName.ToLower().Contains(suspicious))
                        {
                            results[$"Suspicious Process: {suspicious}"] = true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error in process detection: {ex.Message}");
            }
        }

        private static void DetectScreenAnomalies(Dictionary<string, bool> results)
        {
            try
            {
                // Check for common VM screen resolutions
                int width = NativeMethods.GetSystemMetrics(NativeMethods.SM_CXSCREEN);
                int height = NativeMethods.GetSystemMetrics(NativeMethods.SM_CYSCREEN);

                results["Low Resolution"] = width <= 1024 || height <= 768;
                results["Standard VM Resolution"] = (width == 1024 && height == 768) ||
                                                  (width == 800 && height == 600);
            }
            catch (Exception ex)
            {
                Logger.Log($"Error in screen detection: {ex.Message}");
            }
        }

        private static void DetectVMMutexes(Dictionary<string, bool> results)
        {
            var vmMutexes = new[]
            {
                "VBoxMouse", "VBoxGuest", "VBoxMiniRdDN", "VBoxTrayIPC",
                "VMwareUser", "VMwareService"
            };

            foreach (var mutex in vmMutexes)
            {
                try
                {
                    var handle = NativeMethods.CreateMutex(IntPtr.Zero, false, mutex);
                    if (handle != IntPtr.Zero)
                    {
                        if (NativeMethods.GetLastError() == NativeMethods.ERROR_ALREADY_EXISTS)
                        {
                            results[$"VM Mutex Found: {mutex}"] = true;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Log($"Error checking mutex {mutex}: {ex.Message}");
                }
            }
        }

        private static void DetectPerformanceAnomalies(Dictionary<string, bool> results)
        {
            try
            {
                // Get system info
                NativeMethods.SYSTEM_INFO sysInfo;
                NativeMethods.GetSystemInfo(out sysInfo);

                // Check for suspicious CPU configuration
                results["Low CPU Count"] = sysInfo.NumberOfProcessors <= 2;
                results["Suspicious CPU Type"] = sysInfo.ProcessorType != 586; // Most modern CPUs are type 586

                // Check system uptime
                ulong uptime = NativeMethods.GetTickCount64();
                results["Short Uptime"] = uptime < 300000; // Less than 5 minutes
            }
            catch (Exception ex)
            {
                Logger.Log($"Error in performance detection: {ex.Message}");
            }
        }
    }
}
