using System.Security.Cryptography;
using System.IO;
using System;
using Ionic.Zlib;

namespace bloonstd6crypt
{
    internal class Program
    {
        const int Magic = 1;
        const int HeaderSize = 0x24;

        const string Password = "11";
        const int Iterations = 0xa;
        const int SaltSize = 0x18;
        const ulong PasswordVersion = 0x2;

        const int CipherBlockSizeBits  = 128;
        const int CipherBlockSizeBytes = CipherBlockSizeBits / 8;

        const int ZlibBufferSize = 0x800;

        static void Usage()
        {
            Console.WriteLine("Usage: bloonstd6crypt [-e --encrypt | -d --decrypt] <input> <output>");
        }

        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Usage();
                return;
            }

            var inputStream = File.OpenRead(args[1]);
            var inputReader = new BinaryReader(inputStream);

            var outputStream = File.OpenWrite(args[2]);
            var outputWriter = new BinaryWriter(outputStream);

            if (args[0] == "-e" || args[0] == "--encrypt")
            {
                var guid = Guid.NewGuid();
                var dateTime = DateTime.Now;
                
                outputWriter.Write(Magic);
                outputWriter.Write(HeaderSize);
                outputWriter.Write(0x44); // Save index
                outputWriter.Write(guid.ToByteArray());
                outputWriter.Write(dateTime.ToBinary());
                outputWriter.Write(dateTime.ToBinary());
                outputWriter.Write(PasswordVersion);

                var salt = new byte[SaltSize];
                var rfc2898DeriveBytes = new Rfc2898DeriveBytes(Password, salt, Iterations, HashAlgorithmName.SHA1);

                outputWriter.Write(salt);

                var aes = new AesManaged();

                aes.KeySize = CipherBlockSizeBits;
                aes.BlockSize = CipherBlockSizeBits;

                aes.Mode = CipherMode.CBC;

                var bytes = rfc2898DeriveBytes.GetBytes(0x10);
                aes.IV = bytes;

                bytes = rfc2898DeriveBytes.GetBytes(0x10);
                aes.Key = bytes;

                var compressStream = new ZlibStream(inputStream, CompressionMode.Compress);
                compressStream.BufferSize = 0x800;


                var cryptoStream = new CryptoStream(compressStream, aes.CreateEncryptor(), CryptoStreamMode.Read);

                cryptoStream.CopyTo(outputWriter.BaseStream);

                outputStream.Close();
            }
            else if (args[0] == "-d" || args[0] == "--decrypt")
            {
                if (inputReader.ReadUInt32() != Magic)
                {
                    Console.WriteLine("Invalid magic");
                    return;
                }

                var headerSize = inputReader.ReadInt32();

                if (headerSize != HeaderSize)
                {
                    Console.WriteLine("Invalid header size");
                    return;
                }

                var saveIndex = inputReader.ReadInt32();

                var guid = new Guid(inputReader.ReadBytes(0x10));

                var creationTime = DateTime.FromBinary(inputReader.ReadInt64());

                var lastWriteTime = DateTime.FromBinary(inputReader.ReadInt64());

                var passwordVersion = inputReader.ReadUInt64();

                var salt = inputReader.ReadBytes(SaltSize);

                var rfc2898DeriveBytes = new Rfc2898DeriveBytes("11", salt, Iterations, HashAlgorithmName.SHA1);

                var aes = new AesManaged();

                aes.KeySize = CipherBlockSizeBits;
                aes.BlockSize = CipherBlockSizeBits;

                aes.Mode = CipherMode.CBC;

                var bytes = rfc2898DeriveBytes.GetBytes(0x10);
                aes.IV = bytes;

                bytes = rfc2898DeriveBytes.GetBytes(0x10);
                aes.Key = bytes;

                var decryptStream = new CryptoStream(inputStream, aes.CreateDecryptor(), CryptoStreamMode.Read);

                var plainText = new byte[inputStream.Length - (0x2c + 8 + SaltSize)];

                if (plainText.Length % CipherBlockSizeBytes != 0)
                {
                    throw new Exception();
                }

                var decompressStream = new ZlibStream(decryptStream, CompressionMode.Decompress);

                decompressStream.BufferSize = 0x800;

                decompressStream.CopyTo(outputStream);
            }
            else
            {
                Console.WriteLine("Invalid command");
            }
        }
    }
}