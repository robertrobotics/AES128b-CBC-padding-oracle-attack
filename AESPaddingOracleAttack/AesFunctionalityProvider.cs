using System;
using System.IO;
using System.Security.Cryptography;

namespace AESPaddingOracleAttack
{
    /// <summary>
    /// Class defining basic functionalities for AES 128b cipher.
    /// </summary>
    public class AesFunctionalityProvider 
    {
        private readonly Aes aes;

        /// <summary>
        /// Initializes <see cref="AesFunctionalityProvider"/> instance.
        /// </summary>
        public AesFunctionalityProvider()
        {
            this.aes = this.GetInitializedAes();
        }

        /// <summary>
        /// Indicates whether the decryption of data has been done correctly.
        /// This property is FALSE when <see cref="CryptographicException"/> has been thrown, because of e.g. wrong padding value.
        /// </summary>
        public bool IsDecryptionDoneCorrectly { get; private set; }

        /// <summary>
        /// Encrypts message using AES 128b encryption in CBC mode.
        /// </summary>
        /// <param name="message">Message to be encrypted.</param>
        /// <returns>Encrypted message as <see cref="byte[]"/>.</returns>
        public byte[] GetAesEncryptedMessage(string message)
        {
            var messageToBeEncrypted = message ?? string.Empty;
            var encryptor = this.GetEncryptor(this.aes);
            var memoryStream = new MemoryStream();
            byte[] encryptedValue;

            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                using (var stream = new StreamWriter(cryptoStream))
                    stream.Write(messageToBeEncrypted);
                encryptedValue = memoryStream.ToArray();
            }

            return encryptedValue;
        }

        /// <summary>
        /// Decrypts encrypted data using AES 128b algorithm.
        /// </summary>
        /// <param name="cipherData">Cipher data to be decrypted.</param>
        /// <returns>Decrypted cipher data.</returns>
        public string DecryptData(byte[] cipherData)
        {
            var plainText = string.Empty;
            var decryptor = this.GetDecryptor(this.aes);
            var memoryStream = new MemoryStream(cipherData);
            var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            var streamReader = new StreamReader(cryptoStream);

            try
            {
                plainText = streamReader?.ReadToEnd();
                this.IsDecryptionDoneCorrectly = true;
            }
            catch (CryptographicException)
            {
                this.IsDecryptionDoneCorrectly = false;
            }

            return plainText;
        }

        private ICryptoTransform GetEncryptor(Aes aes) => aes?.CreateEncryptor(aes.Key, aes.IV);
        private ICryptoTransform GetDecryptor(Aes aes) => aes?.CreateDecryptor(aes.Key, aes.IV);

        private Aes GetInitializedAes()
        {
            var aesParser = Aes.Create();
            aesParser.Mode = CipherMode.CBC;
            aesParser.BlockSize = 128;
            aesParser.KeySize = 128;
            aesParser.Padding = PaddingMode.PKCS7;
            aesParser.GenerateKey();
            aesParser.GenerateIV();

            return aesParser ?? throw new ArgumentNullException($"Aes object could not be created.");
        }
    }
}
