using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace ApprovalDialog
{
    public partial class MainWindow : Window
    {
        private readonly DispatcherTimer _timer;
        private int _remainingSeconds;
        private string _decision = "deny"; // Default to deny for safety

        // Exit codes matching the Go implementation
        private const int EXIT_ALLOW_ONCE = 0;
        private const int EXIT_ALLOW_ALWAYS = 1;
        private const int EXIT_DENY = 2;
        private const int EXIT_TIMEOUT = 3;

        // Win32 API for loading system icons
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr ExtractIconEx(string lpszFile, int nIconIndex, IntPtr[] phiconLarge, IntPtr[] phiconSmall, int nIcons);

        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr hIcon);

        public MainWindow()
        {
            InitializeComponent();

            // Set window icon to Windows shield icon
            SetShieldIcon();

            // Set up the UI with request details
            ProcessText.Text = App.ProcessName;
            PidText.Text = App.ProcessId.ToString();
            TargetText.Text = App.Port > 0 ? $"{App.Target}:{App.Port}" : App.Target;
            ProtocolText.Text = App.Protocol.ToUpper();

            // Show path if available
            if (!string.IsNullOrEmpty(App.ProcessPath))
            {
                PathLabel.Visibility = Visibility.Visible;
                PathText.Visibility = Visibility.Visible;
                PathText.Text = App.ProcessPath;
            }

            // Set up timeout timer
            _remainingSeconds = App.TimeoutSeconds;
            UpdateTimeoutText();

            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            // Handle window closing (X button, Alt+F4, etc.)
            Closing += MainWindow_Closing;

            // Focus deny button (safe default)
            DenyButton.Focus();
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            _remainingSeconds--;
            UpdateTimeoutText();

            if (_remainingSeconds <= 0)
            {
                _timer.Stop();
                _decision = "timeout";
                OutputDecision(EXIT_TIMEOUT);
            }
        }

        private void UpdateTimeoutText()
        {
            TimeoutText.Text = $"Auto-deny in {_remainingSeconds}s";
        }

        private void AllowOnceButton_Click(object sender, RoutedEventArgs e)
        {
            _timer.Stop();
            _decision = "allow_once";
            OutputDecision(EXIT_ALLOW_ONCE);
        }

        private void AllowAlwaysButton_Click(object sender, RoutedEventArgs e)
        {
            _timer.Stop();
            _decision = "allow_always";
            OutputDecision(EXIT_ALLOW_ALWAYS);
        }

        private void DenyButton_Click(object sender, RoutedEventArgs e)
        {
            _timer.Stop();
            _decision = "deny";
            OutputDecision(EXIT_DENY);
        }

        private void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // If window is closed without a decision, treat as deny
            _timer.Stop();
            if (_decision == "deny")
            {
                OutputDecision(EXIT_DENY);
            }
        }

        private void OutputDecision(int exitCode)
        {
            // Output decision to stdout for the parent process to read
            Console.WriteLine(_decision);
            Application.Current.Shutdown(exitCode);
        }

        private void SetShieldIcon()
        {
            try
            {
                // Extract shield icon from Windows (icon index 77 in imageres.dll is the shield)
                IntPtr[] largeIcons = new IntPtr[1];
                IntPtr[] smallIcons = new IntPtr[1];

                // Try imageres.dll first (Windows Vista+)
                string iconPath = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\imageres.dll");
                ExtractIconEx(iconPath, 77, largeIcons, smallIcons, 1);

                if (largeIcons[0] != IntPtr.Zero)
                {
                    Icon = Imaging.CreateBitmapSourceFromHIcon(
                        largeIcons[0],
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromEmptyOptions());
                    DestroyIcon(largeIcons[0]);
                }
                if (smallIcons[0] != IntPtr.Zero)
                {
                    DestroyIcon(smallIcons[0]);
                }
            }
            catch
            {
                // Ignore icon errors - app will work without custom icon
            }
        }
    }
}
