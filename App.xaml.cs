using System;
using System.Security.Principal;
using System.Windows;

namespace AntiVMSpoofTool
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            if (!IsAdministrator())
            {
                MessageBox.Show("This application requires administrative privileges. Please run as Administrator.", 
                              "Insufficient Rights", MessageBoxButton.OK, MessageBoxImage.Error);
                Environment.Exit(1);
            }

            base.OnStartup(e);
        }

        private bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}
