using System;
using System.Windows;

namespace ApprovalDialog
{
    public partial class App : Application
    {
        public static string ProcessName { get; private set; } = "unknown";
        public static string ProcessPath { get; private set; } = "";
        public static int ProcessId { get; private set; } = 0;
        public static string Target { get; private set; } = "unknown";
        public static int Port { get; private set; } = 0;
        public static string Protocol { get; private set; } = "tcp";
        public static int TimeoutSeconds { get; private set; } = 30;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            ParseArguments(e.Args);
        }

        private void ParseArguments(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--process-name":
                    case "-n":
                        if (i + 1 < args.Length) ProcessName = args[++i];
                        break;
                    case "--process-path":
                    case "-p":
                        if (i + 1 < args.Length) ProcessPath = args[++i];
                        break;
                    case "--pid":
                        if (i + 1 < args.Length && int.TryParse(args[++i], out int pid)) ProcessId = pid;
                        break;
                    case "--target":
                    case "-t":
                        if (i + 1 < args.Length) Target = args[++i];
                        break;
                    case "--port":
                        if (i + 1 < args.Length && int.TryParse(args[++i], out int port)) Port = port;
                        break;
                    case "--protocol":
                        if (i + 1 < args.Length) Protocol = args[++i];
                        break;
                    case "--timeout":
                        if (i + 1 < args.Length && int.TryParse(args[++i], out int timeout)) TimeoutSeconds = timeout;
                        break;
                }
            }
        }
    }
}
