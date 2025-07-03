using System;
using System.Windows;
using AntiVMSpoofTool.Services;
using AntiVMSpoofTool.Utils;

namespace AntiVMSpoofTool
{
    public partial class MainWindow : Window
    {
        private const string DEFAULT_HOSTNAME = "GAMING-PC";

        public MainWindow()
        {
            InitializeComponent();
            InitializeUI();
        }

        private void InitializeUI()
        {
            // Initialize logger
            Logger.Init(txtLog);
            Logger.Log("Application started");

            // Wire up event handlers
            btnRunSpoof.Click += BtnRunSpoof_Click;
            btnDetectVM.Click += BtnDetectVM_Click;
            chkRunOnStartup.Checked += ChkRunOnStartup_CheckedChanged;
            chkRunOnStartup.Unchecked += ChkRunOnStartup_CheckedChanged;
        }

        private async void BtnRunSpoof_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                btnRunSpoof.IsEnabled = false;
                Logger.Log("Starting spoofing operations...");

                if (chkSpoofBIOS.IsChecked == true)
                {
                    Logger.Log("Spoofing BIOS information...");
                    await SpoofingService.SpoofBIOS();
                }

                if (chkChangeGUID.IsChecked == true)
                {
                    Logger.Log("Changing Machine GUID...");
                    await SpoofingService.ChangeMachineGuid();
                }

                if (chkChangeHostName.IsChecked == true)
                {
                    Logger.Log("Changing hostname...");
                    await SpoofingService.ChangeHostName(DEFAULT_HOSTNAME);
                }

                Logger.Log("All spoofing operations completed successfully!");
                MessageBox.Show("Spoofing operations completed successfully!", "Success", 
                              MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Logger.Log($"Error during spoofing: {ex.Message}");
                MessageBox.Show($"An error occurred during spoofing:\n\n{ex.Message}", 
                              "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                btnRunSpoof.IsEnabled = true;
            }
        }

        private async void BtnDetectVM_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                btnDetectVM.IsEnabled = false;
                Logger.Log("Running virtualization detection...");

                bool isVM = await SpoofingService.DetectVirtualization();
                string message = isVM ? 
                    "Virtualization detected! You may want to run the spoofing operations." : 
                    "No virtualization detected.";

                Logger.Log($"Detection result: {message}");
                MessageBox.Show(message, "Detection Result", 
                              MessageBoxButton.OK, 
                              isVM ? MessageBoxImage.Warning : MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Logger.Log($"Error during VM detection: {ex.Message}");
                MessageBox.Show($"An error occurred during VM detection:\n\n{ex.Message}", 
                              "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                btnDetectVM.IsEnabled = true;
            }
        }

        private void ChkRunOnStartup_CheckedChanged(object sender, RoutedEventArgs e)
        {
            try
            {
                if (chkRunOnStartup.IsChecked == true)
                {
                    StartupHelper.EnableStartup();
                    Logger.Log("Auto-start enabled");
                }
                else
                {
                    StartupHelper.DisableStartup();
                    Logger.Log("Auto-start disabled");
                }
            }
            catch (Exception ex)
            {
                Logger.Log($"Error changing startup setting: {ex.Message}");
                MessageBox.Show($"Failed to change startup setting:\n\n{ex.Message}", 
                              "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                
                // Revert checkbox state
                chkRunOnStartup.IsChecked = !chkRunOnStartup.IsChecked;
            }
        }
    }
}
