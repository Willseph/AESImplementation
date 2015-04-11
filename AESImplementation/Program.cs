using System;

namespace AESImplementation.ConsoleTest
{
	class MainClass
	{
		static Random RNG;

		public static void Main (string[] args)
		{
			RNG = new Random ();
			byte[] Plaintext = new byte[200];
			for (int i = 0; i < Plaintext.Length; i++)
				Plaintext [i] = (byte)i;

			byte[] IV = new byte[16];
			RNG.NextBytes (IV);

			byte[] Key = new byte[] {
				0x2b,
				0x7e,
				0x15,
				0x16,
				0x28,
				0xae,
				0xd2,
				0xa6,
				0xab,
				0xf7,
				0x15,
				0x88,
				0x09,
				0xcf,
				0x4f,
				0x3c
			};

			byte[] Ciphertext = AESImplementation.Core.Encryption.EncryptBytes (Plaintext, Key, IV);

			byte[] Decrypted = AESImplementation.Core.Decryption.DecryptBytes (Ciphertext, Key, IV);
		}

		static byte[] RandomKey()
		{
			byte[] Key = new byte[16];
			new System.Security.Cryptography.RNGCryptoServiceProvider ().GetNonZeroBytes (Key);
			return Key;
		}
	}
}
