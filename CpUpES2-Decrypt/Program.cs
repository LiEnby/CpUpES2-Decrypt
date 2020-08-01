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
            RsaKeyParameters CpUp_Public_Key = new RsaKeyParameters(false, new BigInteger("A7CCAE0F501188527BF3DACCA3E231C8D8701E7B91927390701DE5E7A96327DAD87167A8F01368ADDFE490E325A290533697058FBA775766698010AFD8FD7A3FFD265E0A52FE04928BCE8B4302F4C70FFAC3C9397FD24B106271E57BDA20D2D702298F6F990ECF9B0FE04FF6CCEE170B555304232012D78E6019DAB29763829E6AF5ADA802204FA551631179CBFE6164732662E8576741949BB136456C11DE355F487211D230267DC05E699A2652AD5C6D74B0568326F4F2F5B86AD956E94404D3A65928F4EA2189567CE9989911B04808517F4C76A8B25DF1D6ABBE8595C469BFD7E870C4F00A89610C2C9B79F625A42CA2B4C6B8D37E62CE9EC61A856FD32F", 16), new BigInteger("10001", 16));
            RsaKeyParameters FsImage_Public_Key = new RsaKeyParameters(false, new BigInteger("A9697F9D9343CADE68E04F9E356E6AB6BBC7DE36A4D81B98A83BC12BE3F6DF96ED7A64389456ACA933BEBFBA4FFEF05CF45F2F886F434FBBC3A01348533070C0B7D5E9C21EFE53E95A6019DB51C12C6BAFEB94E992287963448E59606384B99F3FF3E5EB6AA08BF32A4DBA7A312520CEC2B69BB20A6D0640B117170AA2DDA1FB590AEE7ADFC4E80DFCF27FA55DDEC92C07922FDD05AB1618DCB727AA6FF70027A9410BC845E50EAFD46C0FD92FF500672DE56489C669B0AA481FFD75E99E21A8DC2F9F9E87957B46BBF63FB7DDBE8B8CA861BA349A62458E855EE78C3DD6791F92E76422144E51295B1337E15C126DF6FA0C29321BC1D7C00E3C19EEF3A3E7A5", 16), new BigInteger("10001", 16));

            if(args.Length < 1)
            {
                Console.WriteLine("Usage: CpUpES2-Decrypt.exe <UpdaterES2.CpUp File OR fsimage1.trf File>");
                return 2;
            }
            else if(File.Exists(args[0]))
            {
                
                // Parse Header
                FileStream fs = File.OpenRead(args[0]);
                BinaryReader bfs = new BinaryReader(fs);

                UInt32 Magic = bfs.ReadUInt32();
                UInt32 Version = bfs.ReadUInt32();
                UInt32 TrfSize = bfs.ReadUInt32();
                UInt32 TrfStartAddress = bfs.ReadUInt32();
                UInt32 TrfExtractedSize = bfs.ReadUInt32();
                UInt32 FullSize = bfs.ReadUInt32();
                UInt32 StartAddress = bfs.ReadUInt32();
                UInt32 ExtractedSize = bfs.ReadUInt32();


                if (Magic == 0x43705570 || Magic == 0x23642745) 
                {
                    String FileType = "CpUp";
                    if (Magic == 0x23642745)
                        FileType = "Trf";

                    UInt32 UsedStartAddress = StartAddress;
                    UInt32 UsedSize = FullSize;
                    UInt32 UsedExtractedSize = ExtractedSize;
                    Boolean IsEncrypted = true;
                    String FileName = Path.ChangeExtension(args[0], "tar.gz");
                    if (FileType == "Trf")
                    {
                        UsedStartAddress = TrfStartAddress;
                        UsedSize = TrfSize;
                        UsedExtractedSize = TrfExtractedSize;
                        FileName = Path.ChangeExtension(args[0], "img");

                        if(Version == 0x1010100) // I think?
                            IsEncrypted = false;

                    }

                    Console.WriteLine(FileType+" Magic: 0x" + Magic.ToString("X"));
                    Console.WriteLine(FileType + " Version: 0x" + Version.ToString("X"));
                    Console.WriteLine(FileType + " TSize: 0x" + TrfSize.ToString("X"));
                    Console.WriteLine(FileType + " TStart Address: 0x" + TrfStartAddress.ToString("X"));
                    Console.WriteLine(FileType + " TExtracted Size: 0x" + TrfExtractedSize.ToString("X"));

                    Console.WriteLine(FileType + " CSize: 0x" + FullSize.ToString("X"));
                    Console.WriteLine(FileType + " CStart Address: 0x" + StartAddress.ToString("X"));
                    Console.WriteLine(FileType + " CExtracted Size: 0x" + ExtractedSize.ToString("X"));
                    Console.WriteLine("\n\nRSA Decrypting Key Information...");


                    // Dervie AES Key
                    Pkcs1Encoding pkcs1Encoding = new Pkcs1Encoding(new RsaEngine());
                    if(FileType == "Trf")
                        pkcs1Encoding.Init(false, FsImage_Public_Key);
                    else if (FileType == "CpUp")
                        pkcs1Encoding.Init(false, CpUp_Public_Key);

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

                    Console.WriteLine(FileType + " Key: " + BitConverter.ToString(Key));
                    Console.WriteLine(FileType + " Iv: " + BitConverter.ToString(Iv));
                    Console.WriteLine(FileType + " Sha1: " + BitConverter.ToString(Sha1Hash));

                    Console.WriteLine("\n\nAES Decrypting "+FileType+" File...");
                    // Decrypt Update
                    
                    fs.Seek(UsedStartAddress, SeekOrigin.Begin);
                    Byte[] UpdateData = new Byte[(UsedSize - UsedStartAddress) - 0x100];
                    fs.Read(UpdateData, 0x00, UpdateData.Length);
                    if(IsEncrypted)
                        UpdateData = Aes_128_Decrypt(UpdateData, Key, Iv);
                    fs.Close();

                    
                    fs = File.OpenWrite(FileName);
                    fs.Write(UpdateData, 0x00, (Int32)UsedExtractedSize);
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
                    Console.WriteLine("Unknown Filetype! (Magic = 0x" + Magic.ToString("X")+")");
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
