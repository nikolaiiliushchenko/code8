using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    private readonly static string CspContainerName = "RsaContainer_Iliushchenko";

    // 1. Генерація власного відкритого ключа RSA 2048 bit у файл Iliushchenko.xml
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

    // 2. Зашифровування вітання за допомогою XML-файлу відкритого ключа іншого студента
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

    // 3. Розшифровування отриманого від іншого студента файлу за допомогою свого контейнера CSP
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

    // Допоміжний метод створення тестового відкритого ключа одногрупника (якщо файлів з чату ще немає)
    public static void CreateSampleClassmatePublicKey(string path)
    {
        if (!File.Exists(path))
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                File.WriteAllText(path, rsa.ToXmlString(false));
            }
        }
    }

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;

        const string myPublicKeyFile = "Iliushchenko.xml";

        // КРОК 1: Генеруємо власний ключ Iliushchenko.xml (якщо він ще не створений)
        if (!File.Exists(myPublicKeyFile))
        {
            GenerateOwnKeys(myPublicKeyFile);
        }

        Console.WriteLine("=== ЗАВДАННЯ 4: Обмін зашифрованими вітаннями RSA 2048 bit ===");
        Console.WriteLine("[1] Відкритий ключ збережено у файл: " + Path.GetFullPath(myPublicKeyFile));
        Console.WriteLine("    (Цей файл Iliushchenko.xml потрібно надіслати у робочий чат)\n");

        // КРОК 2: Зашифровуємо вітання для двох наступних за списком студентів
        string student1Key = "Student1_PublicKey.xml";
        string student2Key = "Student2_PublicKey.xml";
        CreateSampleClassmatePublicKey(student1Key);
        CreateSampleClassmatePublicKey(student2Key);

        string greetingText = "Привіт від Ніколая Ільющенка (МІТ-21)! Гарного захисту лабораторної №8!";
        byte[] greetingBytes = Encoding.UTF8.GetBytes(greetingText);

        string outForStudent1 = "Greeting_From_Iliushchenko_To_Student1.dat";
        string outForStudent2 = "Greeting_From_Iliushchenko_To_Student2.dat";

        EncryptData(student1Key, greetingBytes, outForStudent1);
        EncryptData(student2Key, greetingBytes, outForStudent2);

        Console.WriteLine("[2] Зашифровано вітання для двох студентів:");
        Console.WriteLine("    Текст вітання : " + greetingText);
        Console.WriteLine("    Файл студенту 1: " + outForStudent1 + " (Base64: " + Convert.ToBase64String(File.ReadAllBytes(outForStudent1)).Substring(0, 40) + "...)");
        Console.WriteLine("    Файл студенту 2: " + outForStudent2 + " (Base64: " + Convert.ToBase64String(File.ReadAllBytes(outForStudent2)).Substring(0, 40) + "...)\n");

        // КРОК 3: Розшифровуємо отримане від іншого студента вітання (зашифроване ключем Iliushchenko.xml)
        string incomingFile = "Incoming_Greeting_For_Iliushchenko.dat";
        if (!File.Exists(incomingFile))
        {
            string incomingSample = "Вітання для Ніколая Ільющенка від одногрупника! Все працює відмінно!";
            EncryptData(myPublicKeyFile, Encoding.UTF8.GetBytes(incomingSample), incomingFile);
        }

        byte[] decryptedIncoming = DecryptData(incomingFile);
        string receivedGreeting = Encoding.UTF8.GetString(decryptedIncoming);

        Console.WriteLine("[3] Розшифровано отримане вітання (" + incomingFile + "):");
        Console.WriteLine("    >>> " + receivedGreeting);
    }
}