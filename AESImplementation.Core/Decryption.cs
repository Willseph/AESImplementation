using System;

namespace AESImplementation.Core
{
	public static class Decryption
	{
		public static byte[] DecryptBytes(byte[] Ciphertext, byte[] Key, byte[] IV)
		{
			if (IV.LongLength != 16)
				throw new ArgumentException ("Initialization vector must be 16 bytes long.", "IV");

			if (Ciphertext.LongLength % 16 != 0)
				throw new ArgumentException ("Ciphertext invalid. Length must be a multiple of 16.");

			ByteMatrix[] ExpandedKey = KeyScheduling.CreateKeySchedule (Key);

			byte[] DecryptedBuffer = new byte[Ciphertext.LongLength];

			byte[] LastPaddingPass = IV;

			for (int i = 0; i < Ciphertext.LongLength; i+=16) {
				byte[] CryptoSlice = Ciphertext.Slice (i, 16);
				ByteMatrix DecryptedBlock = DecryptMatrix( new ByteMatrix (CryptoSlice), ExpandedKey);
				Array.Copy (DecryptedBlock.GetBytes().Xor(LastPaddingPass), 0, DecryptedBuffer, i, 16);
				LastPaddingPass = CryptoSlice;
			}

			return DecryptedBuffer;
		}

		static ByteMatrix DecryptMatrix(ByteMatrix State, ByteMatrix[] ExpandedKey)
		{
			State = ByteMatrix.Xor(State,ExpandedKey[10]);
			ShiftRowsDecrypt (State);
			SubBytesDecrypt (State);

			for (int i = 8; i >= 0; i--) {
				State = ByteMatrix.Xor(State,ExpandedKey[i+1]);
				MixColumnsDecrypt (State);
				ShiftRowsDecrypt (State);
				SubBytesDecrypt (State);
			}

			State = ByteMatrix.Xor(State,ExpandedKey[0]);

			return State;
		}

		static void SubBytesDecrypt(ByteMatrix State)
		{
			for (int C = 0; C < 4; C++)
				for (int R = 0; R < 4; R++)
					State.Set (C, R, SBox.DecryptConvert (State.Get (C, R)));
		}

		static void ShiftRowsDecrypt(ByteMatrix State)
		{
			byte T = 0;

			//Move right 1 byte
			T = State.Get(3,1);
			State.Set (3, 1, State.Get (2, 1));
			State.Set (2, 1, State.Get (1, 1));
			State.Set (1, 1, State.Get (0, 1));
			State.Set (0, 1, T);

			//Move right 2 bytes
			for (int i = 0; i < 2; i++) {
				T = State.Get(3,2);
				State.Set (3, 2, State.Get (2, 2));
				State.Set (2, 2, State.Get (1, 2));
				State.Set (1, 2, State.Get (0, 2));
				State.Set (0, 2, T);
			}

			//Move right 3 bytes
			for (int i = 0; i < 3; i++) {
				T = State.Get(3,3);
				State.Set (3, 3, State.Get (2, 3));
				State.Set (2, 3, State.Get (1, 3));
				State.Set (1, 3, State.Get (0, 3));
				State.Set (0, 3, T);
			}
		}

		static void MixColumnsDecrypt(ByteMatrix State)
		{
			for (int C = 0; C < 4; C++) {
				byte R0 = State.Get (C, 0);
				byte R1 = State.Get (C, 1);
				byte R2 = State.Get (C, 2);
				byte R3 = State.Get (C, 3);

				Galois.MixDecryptColumn (ref R0, ref R1, ref R2, ref R3);

				State.Set (C, 0, R0);
				State.Set (C, 1, R1);
				State.Set (C, 2, R2);
				State.Set (C, 3, R3);
			}
		}
	}
}

