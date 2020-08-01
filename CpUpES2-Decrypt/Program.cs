using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CpUpES2_Decrypt
{
    class Program
    {
        public static byte[] Aes_128_Decrypt(byte[] message, byte[] Key, byte[] Iv)
        {
            Aes aes = new AesManaged();
            aes.Key = Key;
            aes.IV = Iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            ICryptoTransform cipher;

            cipher = aes.CreateDecryptor();

            return cipher.TransformFinalBlock(message, 0, message.Length);
        }

        static int Main(string[] args)
        {
            RsaKeyParameters Rsa_Public_Key = new RsaKeyParameters(false, new BigInteger("A7CCAE0F501188527BF3DACCA3E231C8D8701E7B91927390701DE5E7A96327DAD87167A8F01368ADDFE490E325A290533697058FBA775766698010AFD8FD7A3FFD265E0A52FE04928BCE8B4302F4C70FFAC3C9397FD24B106271E57BDA20D2D702298F6F990ECF9B0FE04FF6CCEE170B555304232012D78E6019DAB29763829E6AF5ADA802204FA551631179CBFE6164732662E8576741949BB136456C11DE355F487211D230267DC05E699A2652AD5C6D74B0568326F4F2F5B86AD956E94404D3A65928F4EA2189567CE9989911B04808517F4C76A8B25DF1D6ABBE8595C469BFD7E870C4F00A89610C2C9B79F625A42CA2B4C6B8D37E62CE9EC61A856FD32F", 16), new BigInteger("10001", 16));


            if(args.Length < 1)
            {
                Console.WriteLine("Usage: CpUpES2Decrypt.exe <UpdaterES2.CpUp File>");
                return 2;
            }
            else if(File.Exists(args[0]))
            {
                // Parse Header
                FileStream fs = File.OpenRead(args[0]);
                BinaryReader bfs = new BinaryReader(fs);

                UInt32 Magic = bfs.ReadUInt32();
                UInt32 Version = bfs.ReadUInt32();
                UInt64 Reserved = bfs.ReadUInt64();
                UInt32 Type = bfs.ReadUInt32();
                UInt32 FullSize = bfs.ReadUInt32();
                UInt32 StartAddress = bfs.ReadUInt32();
                UInt32 ExtractedSize = bfs.ReadUInt32();

                if (Magic == 0x43705570) //CpUp
                {
                    Console.WriteLine("CpUp Magic: 0x" + Magic.ToString("X"));
                    Console.WriteLine("CpUp Version: 0x" + Version.ToString("X"));
                    Console.WriteLine("CpUp Reserved Space: 0x" + Reserved.ToString("X"));
                    Console.WriteLine("CpUp Type: 0x" + Type.ToString("X"));
                    Console.WriteLine("CpUp Size: 0x" + FullSize.ToString("X"));
                    Console.WriteLine("CpUp Start Address: 0x" + StartAddress.ToString("X"));
                    Console.WriteLine("CpUp Extracted Size: 0x" + ExtractedSize.ToString("X"));
                    Console.WriteLine("\n\nRSA Decrypting Key Information...");

                    // Dervie AES Key
                    Pkcs1Encoding pkcs1Encoding = new Pkcs1Encoding(new RsaEngine());
                    pkcs1Encoding.Init(false, Rsa_Public_Key);
                    pkcs1Encoding.GetInputBlockSize();

                    fs.Seek(-0x100, SeekOrigin.End);
                    Byte[] HeaderData = new Byte[0x100];
                    fs.Read(HeaderData, 0x00, 0x100);

                    Byte[] HeaderDecrypted = pkcs1Encoding.ProcessBlock(HeaderData, 0, 0x100);

                    Byte[] Iv = new Byte[0x10];
                    Byte[] Key = new Byte[0x10];
                    Byte[] Sha1Hash = new Byte[0x14];

                    Array.ConstrainedCopy(HeaderDecrypted, 0x0, Iv, 0x0, 0x10);
                    Array.ConstrainedCopy(HeaderDecrypted, 0x10, Key, 0x0, 0x10);
                    Array.ConstrainedCopy(HeaderDecrypted, 0x20, Sha1Hash, 0x0, 0x14);

                    Console.WriteLine("CpUp Key: " + BitConverter.ToString(Key));
                    Console.WriteLine("CpUp Iv: " + BitConverter.ToString(Iv));
                    Console.WriteLine("CpUp Sha1: " + BitConverter.ToString(Sha1Hash));

                    Console.WriteLine("\n\nAES Decrytping CpUp File...");
                    // Decrypt Update
                    fs.Seek(StartAddress, SeekOrigin.Begin);
                    Byte[] UpdateData = new Byte[(FullSize - StartAddress) - 0x100];
                    fs.Read(UpdateData, 0x00, UpdateData.Length);
                    Byte[] UpdateDecrypted = Aes_128_Decrypt(UpdateData, Key, Iv);
                    fs.Close();

                    String FileName = Path.ChangeExtension(args[0], "tar.gz");
                    fs = File.OpenWrite(FileName);
                    fs.Write(UpdateDecrypted, 0x00, (Int32)ExtractedSize);
                    fs.Close();
                    Console.WriteLine("Decrypted file saved to: " + FileName);

                    ConsoleColor PrevColor = Console.ForegroundColor;
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("\n\nBlessed Be!");
                    Console.ForegroundColor = PrevColor;

                    return 0;
                }
                else
                {
                    Console.WriteLine("Invalid CPUP! (Magic = 0x" + Magic.ToString("X")+")");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine("File not Found: " + args[0]);
                return 4;
            }
        }
    }
}
