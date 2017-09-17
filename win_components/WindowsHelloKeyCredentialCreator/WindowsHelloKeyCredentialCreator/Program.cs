using System;
using System.IO;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace WindowsHelloKeyCredentialCreator
{
    class Program
    {

        public const int ERR_CREAT_FAIL = 1;
        public const int ERR_CREAT_KEY_EXISTS = 170; // Avoid reserved exit codes of UNIX

        static async Task<(int err, string pubKey)> CreatePublicKey(string key_name)
        {
            int err;
            var createRes = await KeyCredentialManager.RequestCreateAsync(key_name, KeyCredentialCreationOption.FailIfExists);
            IBuffer pubKey;
            if (createRes.Status == KeyCredentialStatus.CredentialAlreadyExists)
            {
                var existing = await KeyCredentialManager.OpenAsync(key_name);
                if (existing.Status != KeyCredentialStatus.Success)
                {
                    return (ERR_CREAT_FAIL, null);
                }
                err = ERR_CREAT_KEY_EXISTS;
                pubKey = existing.Credential.RetrievePublicKey();
            }
            else if (createRes.Status != KeyCredentialStatus.Success)
            {
                return (ERR_CREAT_FAIL, null);
            }
            else {
                err = 0;
                pubKey = createRes.Credential.RetrievePublicKey();
            }
            var pem = String.Format("-----BEGIN PUBLIC KEY-----\n{0}\n-----END PUBLIC KEY-----\n", CryptographicBuffer.EncodeToBase64String(pubKey));
            return (err, pem);
        }

        static void exit(int code, bool needPrompt)
        {
            if (needPrompt)
            {
                Console.WriteLine("Hit Enter key to terminate...");
                Console.ReadLine();
            }
            Environment.Exit(code);
        }

        static void Main(string[] args)
        {
            string key_name;
            foreach (var arg in args)
            {
                if (arg == "-h" || arg == "/?")
                {
                    Console.WriteLine("Usage: WindowsHelloKeyCredentialCreator.exe [key_name]");
                    Console.WriteLine("This program creates a KeyCredential of Windows Hello, and save it to a file named 'key_name.pem'.");
                    Console.WriteLine("If key_name is not given, the prompt to ask the name will be shown.");
                    return;
                }
            }

            bool needsPrompt = args.Length == 0;

            if (needsPrompt)
            {
                Console.WriteLine("Input the name of the new KeyCredential");
                Console.Write("Name: ");
                key_name = Console.ReadLine();
            }
            else
            {
                key_name = args[0];
            }

            var res = CreatePublicKey(key_name).Result;
            if (res.err == ERR_CREAT_KEY_EXISTS)
            {
                Console.WriteLine("Error: The key already exists. Outputting The existing public key.");
            }
            else if (res.err > 0) {
                Console.WriteLine("Error: Key creation failed due to some error");
                exit(res.err, needsPrompt);
            }

            File.WriteAllText(String.Format("{0}.pem", key_name), res.pubKey);
            Console.WriteLine(String.Format("Done. The public credential key is written in '{0}.pem'", key_name));
            exit(res.err, needsPrompt);
        }
    }
}
