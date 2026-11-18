using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    private static RSAParameters _publicKey, _privateKey;

    // In-Memory Keys: генерація пари ключів RSA 2048 біт у пам'яті
    public static void AssignNewKey()
    {
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;
            _publicKey = rsa.ExportParameters(false);
            _privateKey = rsa.ExportParameters(true);
        }
    }

    // Зашифровування повідомлення відкритим ключем у пам'яті
    public static byte[] EncryptData(byte[] dataToEncrypt)
    {
        byte[] cypherBytes;

        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;
            rsa.ImportParameters(_publicKey);
            cypherBytes = rsa.Encrypt(dataToEncrypt, true);
        }

        return cypherBytes;
    }

    // Розшифровування повідомлення закритим ключем у пам'яті
    public static byte[] DecryptData(byte[] dataToDecrypt)
    {
        byte[] plainBytes;

        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;
            rsa.ImportParameters(_privateKey);
            plainBytes = rsa.Decrypt(dataToDecrypt, true);
        }

        return plainBytes;
    }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        const string original = "Конфіденційне повідомлення RSA (ключі у пам'яті)";

        AssignNewKey();

        byte[] encrypted = EncryptData(Encoding.UTF8.GetBytes(original));
        byte[] decrypted = DecryptData(encrypted);
        string decryptedMessage = Encoding.UTF8.GetString(decrypted);

        Console.WriteLine("=== ЗАВДАННЯ 1: RSA (In-Memory Keys) ===");
        Console.WriteLine("Original Text  = " + original);
        Console.WriteLine("Public Key (N) = " + Convert.ToBase64String(_publicKey.Modulus!));
        Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted));
        Console.WriteLine("Decrypted Text = " + decryptedMessage);
    }
}