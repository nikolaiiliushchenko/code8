using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    private readonly static string CspContainerName = "RsaContainer_Task2";

    // Генерація набору ключів 2048 біт та збереження в іменованому контейнері CSP
    public static void AssignNewKey()
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
        }
    }

    // Зашифровування повідомлення за допомогою ключа з контейнера
    public static byte[] EncryptData(byte[] dataToEncrypt)
    {
        byte[] cypherBytes;

        var cspParams = new CspParameters(1)
        {
            KeyContainerName = CspContainerName,
            Flags = CspProviderFlags.UseMachineKeyStore,
            ProviderName = "Microsoft Strong Cryptographic Provider"
        };

        using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
        {
            rsa.PersistKeyInCsp = true;
            cypherBytes = rsa.Encrypt(dataToEncrypt, true);
        }

        return cypherBytes;
    }

    // Розшифровування повідомлення за допомогою ключа з контейнера
    public static byte[] DecryptData(byte[] dataToDecrypt)
    {
        byte[] plainBytes;

        var cspParams = new CspParameters(1)
        {
            KeyContainerName = CspContainerName,
            Flags = CspProviderFlags.UseMachineKeyStore,
            ProviderName = "Microsoft Strong Cryptographic Provider"
        };

        using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
        {
            rsa.PersistKeyInCsp = true;
            plainBytes = rsa.Decrypt(dataToDecrypt, true);
        }

        return plainBytes;
    }

    // Видалення ключів із контейнера сховища CSP
    public static void DeleteKeyInCsp()
    {
        CspParameters cspParameters = new CspParameters(1)
        {
            KeyContainerName = CspContainerName,
            Flags = CspProviderFlags.UseMachineKeyStore,
            ProviderName = "Microsoft Strong Cryptographic Provider"
        };

        using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
        {
            rsa.PersistKeyInCsp = false;
            rsa.Clear();
        }
    }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        const string original = "Конфіденційне повідомлення RSA (ключі у контейнері CSP)";

        AssignNewKey();

        byte[] encrypted = EncryptData(Encoding.UTF8.GetBytes(original));
        byte[] decrypted = DecryptData(encrypted);
        string decryptedMessage = Encoding.UTF8.GetString(decrypted);

        Console.WriteLine("=== ЗАВДАННЯ 2: RSA (CSP Container Keys) ===");
        Console.WriteLine("Контейнер CSP  = " + CspContainerName);
        Console.WriteLine("Original Text  = " + original);
        Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted));
        Console.WriteLine("Decrypted Text = " + decryptedMessage);

        DeleteKeyInCsp();
        Console.WriteLine("Ключі успішно видалено зі сховища CSP після завершення.");
    }
}