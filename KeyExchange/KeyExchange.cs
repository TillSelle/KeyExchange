using System.Security.Cryptography;
using System.Text;

namespace KeyExchange
{

    public class Message
    {
        public byte[] MessageBytes { get; set; }
        public string Content { get; set; }
    }

    public class Client
    {
        private byte[] clientPrivateKey;

        public byte[] clientPublicKey;

        private CngAlgorithm HashAlgorithm = CngAlgorithm.Sha256;

        private ECDiffieHellmanCng DiffieClient = new ECDiffieHellmanCng();

        private ECDiffieHellmanKeyDerivationFunction DerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;

        public Client()
        {
            DiffieClient.KeyDerivationFunction = DerivationFunction;
            DiffieClient.HashAlgorithm = HashAlgorithm;
            clientPublicKey = DiffieClient.PublicKey.ToByteArray();
        }



        public void SetHashAlgorithm(CngAlgorithm algorithm)
        {
            HashAlgorithm = algorithm;
        }

        public void GenerateAndSetPrivateKey(Client client2)
        {
            clientPrivateKey = DiffieClient.DeriveKeyMaterial(CngKey.Import(client2.clientPublicKey, CngKeyBlobFormat.EccPublicBlob));
        }

        public List<byte[]> Encrypt(string message)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = clientPrivateKey;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plaintext = Encoding.UTF8.GetBytes(message);
                        cs.Write(plaintext, 0, plaintext.Length);
                        cs.Close();
                        byte[] encMessage = ms.ToArray();
                        return new List<byte[]>() { encMessage, aes.IV };

                    }
                }
                
            }
        }

        public Message Decrypt(byte[] encryptedMessage, byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = clientPrivateKey;
                aes.IV = iv;
                Message Object = new Message();
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                        cs.Close();
                        string message = Encoding.Latin1.GetString(ms.ToArray());
                        Object.Content = message;
                        Object.MessageBytes = Encoding.Latin1.GetBytes(message);
                        return Object;
                    }
                }
            }
        }

    }

    
}