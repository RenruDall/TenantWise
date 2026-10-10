// TenantWise.App — Program.cs
using System;
using System.Windows;

namespace TenantWise.App
{
    public static class Program
    {
        [STAThread]
        public static int Main()
        {
            // One TenantWise window per Windows user: two would share the activity log and the sign-in.
            using (var single = new System.Threading.Mutex(true, "Local\\TenantWise.App", out var first))
            {
                if (!first)
                {
                    MessageBox.Show("TenantWise is already open.", "TenantWise", MessageBoxButton.OK, MessageBoxImage.Information);
                    return 0;
                }
                try { return Run(); }
                finally { single.ReleaseMutex(); }
            }
        }

        private static int Run()
        {
            var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
            app.DispatcherUnhandledException += (s, e) =>
            {
                MessageBox.Show("Something went wrong:\n\n" + e.Exception.Message, "TenantWise", MessageBoxButton.OK, MessageBoxImage.Error);
                e.Handled = true;
            };
            return app.Run(new MainWindow());
        }
    }
}
