using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    private readonly static string CspContainerName = "RsaContainer_Task3";

    // Генерація власної пари ключів: закритий — у контейнері CSP, відкритий — у XML-файлі
    public static void GenerateOwnKeys(string publicKeyPath)
    {
        CspParameters cspParameters = new CspParameters(1)
        {
            KeyContainerName = CspContainerName,
            Flags = CspProviderFlags.UseMachineKeyStore,
            ProviderName = "Microsoft Strong Cryptographic Provider"
        };

        using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
        {
            rsa.PersistKeyInCsp = true;
            File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
        }
    }

    // Зашифровування даних за допомогою файлу відкритого ключа отримувача та збереження у файл
    public static void EncryptData(string publicKeyPath, byte[] dataToEncrypt, string chipherTextPath)
    {
        byte[] chipherBytes;

        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;
            rsa.FromXmlString(File.ReadAllText(publicKeyPath));

            chipherBytes = rsa.Encrypt(dataToEncrypt, true);
        }

        File.WriteAllBytes(chipherTextPath, chipherBytes);
    }

    // Розшифровування зашифрованого файлу за допомогою закритого ключа з контейнера CSP
    public static byte[] DecryptData(string chipherTextPath)
    {
        byte[] chipherBytes = File.ReadAllBytes(chipherTextPath);
        byte[] plainTextBytes;

        var cspParams = new CspParameters(1)
        {
            KeyContainerName = CspContainerName,
            Flags = CspProviderFlags.UseMachineKeyStore,
            ProviderName = "Microsoft Strong Cryptographic Provider"
        };

        using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
        {
            rsa.PersistKeyInCsp = true;
            plainTextBytes = rsa.Decrypt(chipherBytes, true);
        }

        return plainTextBytes;
    }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        string publicKeyFile = "PublicKey.xml";
        string cipherFile = "encrypted_message.dat";
        const string original = "Секретне повідомлення, зашифроване через файл відкритого ключа XML!";

        GenerateOwnKeys(publicKeyFile);

        EncryptData(publicKeyFile, Encoding.UTF8.GetBytes(original), cipherFile);

        byte[] decryptedBytes = DecryptData(cipherFile);
        string decryptedText = Encoding.UTF8.GetString(decryptedBytes);

        Console.WriteLine("=== ЗАВДАННЯ 3: RSA (Відкритий ключ у XML-файлі + Закритий у CSP) ===");
        Console.WriteLine("Файл відкритого ключа : " + Path.GetFullPath(publicKeyFile));
        Console.WriteLine("Вміст XML-ключа       : " + File.ReadAllText(publicKeyFile));
        Console.WriteLine("\nOriginal Text         = " + original);
        Console.WriteLine("Encrypted File (.dat) = " + Convert.ToBase64String(File.ReadAllBytes(cipherFile)));
        Console.WriteLine("Decrypted Text        = " + decryptedText);
    }
}