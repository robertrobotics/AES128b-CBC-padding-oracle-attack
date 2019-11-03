using System;
using System.Collections.Generic;

namespace AESPaddingOracleAttack
{
    /// <summary>
    /// Class used for demonstration purposes to show how an padding oracle attack 
    /// can be done on any CBC algorithm (in this case: AES 128b).
    /// </summary>
    public class PaddingOracleAttacker
    { 
        private const int BlockSize = 16;
        private readonly AesFunctionalityProvider AesFuncionalityProvider;

        /// <summary>
        /// Initializes helper for AES algorithm class for an internal algorithm purposes.
        /// </summary>
        /// <param name="aesFunctionalityProvider">Provides basic decryption / encryption operations.</param>
        public PaddingOracleAttacker(AesFunctionalityProvider aesFunctionalityProvider)
        {
            this.AesFuncionalityProvider = aesFunctionalityProvider ?? throw new ArgumentNullException($"Passed argument: {nameof(aesFunctionalityProvider)} cannot be null!");
        }

        /// <summary>
        /// Decrypts given encrypted message (cipher) without knowledge about used key and initialization vector.
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message (cipher) to be decrypted.</param>
        /// <returns></returns>
        public byte[] DecryptCipherBlock(byte[] encryptedMessage)
        {
            var dataBlocks = this.GetUncoupledDataBlock(encryptedMessage);
            var decryptedBlocks = new List<byte[]>();

            // Add first empty block - cannot be obtained because we do not know initialization vector for CBC (IV).
            decryptedBlocks.Add(new byte[BlockSize]);

            for (var blockNumber = 0; blockNumber < dataBlocks.Count - 1; blockNumber++)
            {
                var decryptedSingleBlock = this.DecryptSingleBlock(dataBlocks[blockNumber], dataBlocks[blockNumber + 1]);
                decryptedBlocks.Add(decryptedSingleBlock);
            }

            return this.ConcatenateBlocksIntoOne(decryptedBlocks);
        }

        private IList<byte[]> GetUncoupledDataBlock(byte[] data)
        {
            var dataBlocks = new List<byte[]>();

            for (var byteNumber = 0; byteNumber < data.Length; byteNumber += BlockSize)
            {
                var singleBlock = new byte[BlockSize];
                Array.Copy(data, byteNumber, singleBlock, 0, BlockSize);
                dataBlocks.Add(singleBlock);
            }

            return dataBlocks;
        }

        private byte[] ConcatenateBlocksIntoOne(List<byte[]> dataBlocks)
        {
            var totalLength = 0;
            dataBlocks.ForEach(block => totalLength += block.Length);
            var concatenatedDataBlocks = new byte[totalLength];

            for (var blockNumber = 0; blockNumber < dataBlocks.Count; blockNumber++)
            {
                var singleBlock = dataBlocks[blockNumber];
                Array.Copy(singleBlock, 0, concatenatedDataBlocks, blockNumber * BlockSize, singleBlock.Length);
            }

            return concatenatedDataBlocks;
        }

        private byte[] DecryptSingleBlock(byte[] previousBlock, byte[] blockToBeDecrypted)
        {
            var decryptedData = new byte[BlockSize];            // : Pi:            decrypted plain text (result of the attack),
            var fakeCipher = new byte[BlockSize];               // : C'i-1 :        fake previous cipher block to feed the padding oracle to obtain valid padding value,
            var concatenatedCipher = new byte[BlockSize * 2];   // : C'i-1 + Ci :   concatenation of C'i-1 and Ci [ C'i-1 | Ci ],
            var decryptedCurrentCipher = new byte[BlockSize];   // : D(Ci) :        decrypted current cipher (current cipher is encrypted plain text block E(Pi))

            for (var byteNumber = 1; byteNumber <= BlockSize; byteNumber++)
            {
                /*  Calculate last bytes of fake cipher blocks to be fitted with current padding value, padding is equal to 'byteNumber' variable's value.
                    E.g. to obtain 14th byte we know that Pi = [_ _ _ _ _ _ _ _ _ _ _ _ _ x 0x02 0x02] - for more info see PKCS#7 standard description.
                    Because of that 13th C' block will be C'_13 = [r r r r r r r r r r r r r p x y] - we have to calculate x and y for 0x02 padding value, r is random value,
                                                                                                      p is the valid padding obtained from posterior steps.
                    We can do that knowing the formula: Pi = D(Ci) ^ C_i-1 and D(Ci)[x] = P'i[x] ^ C'_i-1
                    Here, we want to complete C'_i-1 block knowing D(Ci) bytes from preceding iterations with formula: C'_i-1[k] = padding ^ D(Ci)[k].
                */
                for (var i = 1; i < byteNumber; i++)
                {
                    fakeCipher[BlockSize - i] = (byte)(byteNumber ^ decryptedCurrentCipher[BlockSize - i]);
                }

                // Create concatenation of fake cipher block and block which algorithm has to decrypt
                Array.Copy(fakeCipher, BlockSize - byteNumber + 1, concatenatedCipher, BlockSize - byteNumber + 1, byteNumber - 1);
                Array.Copy(previousBlock, 0, concatenatedCipher, 0, BlockSize - byteNumber + 1);
                Array.Copy(blockToBeDecrypted, 0, concatenatedCipher, BlockSize, BlockSize);

                // Get valid padding for which decryption is being done w/o errors
                var validPadding = this.GetValidPadding(concatenatedCipher, byteNumber);

                // Calculate cipher to be decrypted after decryption block -> D(Ci)[byteNumber]
                decryptedCurrentCipher[BlockSize - byteNumber] = (byte)(byteNumber ^ validPadding);

                // Calculate plain text value.
                decryptedData[BlockSize - byteNumber] = (byte)(decryptedCurrentCipher[BlockSize - byteNumber] ^ previousBlock[BlockSize - byteNumber]);
            }

            return decryptedData;
        }

        private byte GetValidPadding(byte[] concatenatedCipher, int byteNumber)
        {
            byte validPaddingValue = 0x00;
            for (var fakePadding = 0; fakePadding < 256; fakePadding++)
            {
                concatenatedCipher[BlockSize - byteNumber] = (byte)fakePadding;
                this.AesFuncionalityProvider.DecryptData(concatenatedCipher);

                if (this.AesFuncionalityProvider.IsDecryptionDoneCorrectly)
                {
                    validPaddingValue = concatenatedCipher[BlockSize - byteNumber];
                    break;
                }
            }
            return validPaddingValue;
        }

    }
}
