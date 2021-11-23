using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Windows.UI.Popups;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using HWND = System.IntPtr;

namespace WindowsHelloAuthenticator
{
    class Program
    {

        // Exit codes
        public const byte ERR_VERIFY_HELLO_NOT_SUPPORTED = 170; // Avoid reserved exit codes of UNIX
        public const byte ERR_VERIFY_CREDENTIAL_EXISTS = 171;
        public const byte ERR_VERIFY_CREDENTIAL_NOT_FOUND = 172;
        public const byte ERR_VERIFY_DEVICE_IS_LOCKED = 173;
        public const byte ERR_VERIFY_UNKNOWN_ERR = 175;         // Skip 174 because the number should correspond to KeyCredentialStatus.Success if exists
        public const byte ERR_VERIFY_USER_CANCELLED = 176;
        public const byte ERR_VERIFY_USER_PREFS_PASSWD = 177;

        static int CredentialStatusToExitCode(KeyCredentialStatus status)
        {
            return 171 + (int)status; // Avoid reserved exit codes of UNIX
        }

        static string ExitCodeToMessage(int code, string key_name)
        {
            switch (code)
            {
                case 0:
                    return "Success.";
                case ERR_VERIFY_HELLO_NOT_SUPPORTED:
                    return "Windows Hello is not supported in this device.";
                case ERR_VERIFY_CREDENTIAL_EXISTS:
                    return "The credential already exists. Creation failed.";
                case ERR_VERIFY_CREDENTIAL_NOT_FOUND:
                    return "The credential '" + key_name + "' does not exist.";
                case ERR_VERIFY_DEVICE_IS_LOCKED:
                    return "The Windows Hello security device is locked.";
                case ERR_VERIFY_UNKNOWN_ERR:
                    return "Unknown error.";
                case ERR_VERIFY_USER_CANCELLED:
                    return "The user cancelled.";
                case ERR_VERIFY_USER_PREFS_PASSWD:
                    return "The user prefers to enter password. Aborted.";
                default:
                    return "Unkwon internal error.";
            }
        }

        [DllImport("user32.dll", SetLastError = true)]
        static extern HWND FindWindow(string lpClassName, string lpWindowName);

        [DllImport("User32.dll", SetLastError = true)]
        static extern bool SetForegroundWindow(HWND hWnd);

        [DllImport("User32.dll", SetLastError = true)]
        static extern bool ShowWindowAsync(HWND hWnd, int nCmdShow);
        public const int SW_SHOWMINIMIZED = 2;
        public const int SW_SHOW = 5;
        public const int SW_RESTORE = 9;
        public const int SW_SHOWDEFAULT = 10;


        static async Task<bool> FocusHelloWindow(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Console.WriteLine("[wsl-hello] Searching for window...");
            HWND hwnd = FindWindow("Credential Dialog Xaml Host", null);

            while ((int)hwnd == 0)
            {
                await Task.Delay(500);
                Console.WriteLine("[wsl-hello] Still searching...");
                hwnd = FindWindow("Credential Dialog Xaml Host", null);
                token.ThrowIfCancellationRequested();
            }

            Console.WriteLine($"[wsl-hello] Window found, hWnd: {hwnd}");

            Console.WriteLine("[wsl-hello] Attempting to focus using SetForegroundWindow...");
            var success = SetForegroundWindow(hwnd);
            Console.WriteLine($"[wsl-hello] SetForegroundWindow {(success ? "successful" : "unsuccessful")}.");

            if (success) return true;

            Console.WriteLine("[wsl-hello] Attempting to focus using ShowWindowAsync...");
            ShowWindowAsync(hwnd, SW_SHOWMINIMIZED);

            Console.WriteLine("[wsl-hello] Attempting SW_SHOWRESTORE...");
            ShowWindowAsync(hwnd, SW_RESTORE);

            await Task.Delay(2000);
            Console.WriteLine("[wsl-hello] Attempting SW_SHOWDEFAULT...");
            ShowWindowAsync(hwnd, SW_SHOWDEFAULT);

            await Task.Delay(2000);
            Console.WriteLine("[wsl-hello] Attempting SW_SHOW...");
            ShowWindowAsync(hwnd, SW_SHOW);

            return true;

        }

        static async Task<(int err, byte[] sig)> VerifyUser(string key_name, string contentToSign)
        {
            if (await KeyCredentialManager.IsSupportedAsync() == false)
            {
                await (new MessageDialog("KeyCredentialManager not supported")).ShowAsync();
                return (ERR_VERIFY_HELLO_NOT_SUPPORTED, null);
            }

            var key = await KeyCredentialManager.OpenAsync(key_name);
            if (key.Status != KeyCredentialStatus.Success)
            {
                return (CredentialStatusToExitCode(key.Status), null);
            }

            var buf = CryptographicBuffer.ConvertStringToBinary(contentToSign, BinaryStringEncoding.Utf8);

            var tokenSource = new CancellationTokenSource();
            _ = FocusHelloWindow(tokenSource.Token);

            var signRes = await key.Credential.RequestSignAsync(buf);

            tokenSource.Cancel();

            if (signRes.Status != KeyCredentialStatus.Success)
            {
                return (CredentialStatusToExitCode(key.Status), null);
            }

            byte[] sig;
            CryptographicBuffer.CopyToByteArray(signRes.Result, out sig);
            return (0, sig);
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: WindowsHelloAuthenticator.exe credential_key_name");
                Console.WriteLine("");
                Console.WriteLine("This program authenticates the current user by Windows Hello,");
                Console.WriteLine("and outputs a signature of the signed input from stdin to stdout.");
                Console.WriteLine("The input will be signed by a private key that is associated with 'credential_key_name'");
                Environment.Exit(1);
            }

            var verifyRes = VerifyUser(args[0], Console.In.ReadToEnd()).Result;
            if (verifyRes.err > 0)
            {
                Console.WriteLine(ExitCodeToMessage(verifyRes.err, args[0]));
                Environment.Exit(verifyRes.err);
            }
            var stdout = Console.OpenStandardOutput();
            stdout.Write(verifyRes.sig, 0, verifyRes.sig.Length);
        }
    }
}
