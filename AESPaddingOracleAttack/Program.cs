using System;
using System.Text;

namespace AESPaddingOracleAttack
{
    class Program
    { 
        static void Main(string[] args)
        {
            var aesHelper = new AesFunctionalityProvider();
            var aesAttacker = new PaddingOracleAttacker(aesHelper);

            Console.WriteLine($"Your message to be encoded (has to be longer than 16 Bytes - see information at the end):");
            var readMessage = Console.ReadLine();

            var encryptedMessage = aesHelper.GetAesEncryptedMessage(readMessage);
            Console.WriteLine("--------------------------------------------------------------");
            Console.WriteLine($"Encrypted message: {Convert.ToBase64String(encryptedMessage)}");

            var decryptedMessage = aesAttacker.DecryptCipherBlock(encryptedMessage);

            Console.WriteLine("----------------------------------------------------------------");
            Console.WriteLine($"Decrypted message: {Encoding.ASCII.GetString(decryptedMessage)}");

            Console.WriteLine("==================================================================================");
            Console.WriteLine($"First 16-Byte block is not decrypted because of unknown initialization vector IV.");
            Console.ReadKey();
        }
    }
}
