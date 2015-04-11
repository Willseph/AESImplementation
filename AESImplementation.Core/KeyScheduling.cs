using System;

namespace AESImplementation.Core
{
	internal static class KeyScheduling
	{
		static readonly byte[] Rcon = new byte[] {
			0x01,
			0x02,
			0x04,
			0x08,
			0x10,
			0x20,
			0x40,
			0x80,
			0x1b,
			0x36
		};

		internal static ByteMatrix[] CreateKeySchedule(byte[] Key)
		{
			if (Key.Length != 16)
				throw new AESKeyLengthException ();

			ByteMatrix[] ExpandedKeyMatrices = new ByteMatrix[11];
			ExpandedKeyMatrices[0] = new ByteMatrix (Key);

			for (int i = 0; i < 10; i++)
				ExpandedKeyMatrices [i + 1] = CreateRoundKey (ExpandedKeyMatrices [i], i);

			return ExpandedKeyMatrices;
		}

		private static ByteMatrix CreateRoundKey(ByteMatrix PreviousRoundKey, int KeyIndex)
		{
			ByteMatrix NewRoundKey = new ByteMatrix ();

			NewRoundKey.Set (0, 0, SBox.EncryptConvert (PreviousRoundKey.Get (3, 1)).Xor(Rcon[KeyIndex]));
			NewRoundKey.Set (0, 1, SBox.EncryptConvert (PreviousRoundKey.Get (3, 2)));
			NewRoundKey.Set (0, 2, SBox.EncryptConvert (PreviousRoundKey.Get (3, 3)));
			NewRoundKey.Set (0, 3, SBox.EncryptConvert (PreviousRoundKey.Get (3, 0)));

			for(int R=0; R<4; R++)
				NewRoundKey.Set (0, R, PreviousRoundKey.Get (0, R).Xor(NewRoundKey.Get(0,R)));

			for (int C = 1; C < 4; C++)
				for (int R = 0; R < 4; R++)
					NewRoundKey.Set (C, R, PreviousRoundKey.Get (C, R).Xor (NewRoundKey.Get (C - 1, R)));

			return NewRoundKey;
		}
	}
}

