using System;

namespace AESImplementation.Core
{
	public static class Encryption
	{
		public static byte[] EncryptBytes(byte[] Plaintext, byte[] Key, byte[] IV)
		{
			if (IV.LongLength != 16)
				throw new ArgumentException ("Initialization vector must be 16 bytes long.", "IV");

			ByteMatrix[] ExpandedKey = KeyScheduling.CreateKeySchedule (Key);

			byte[] CryptoBuffer = new byte[(long)(16 * Math.Ceiling (Plaintext.LongLength / 16.0))];
			Array.Copy (Plaintext, CryptoBuffer, Plaintext.LongLength);

			byte[] LastPaddingPass = IV;

			for (int i = 0; i < CryptoBuffer.LongLength; i+=16) {
				byte[] PlaintextSlice = CryptoBuffer.Slice (i, 16);
				ByteMatrix CypherBlock = EncryptMatrix( new ByteMatrix (LastPaddingPass.Xor(PlaintextSlice)), ExpandedKey);
				LastPaddingPass = CypherBlock.GetBytes ();
				Array.Copy (LastPaddingPass, 0, CryptoBuffer, i, 16);
			}

			return CryptoBuffer;
		}

		static ByteMatrix EncryptMatrix(ByteMatrix State, ByteMatrix[] ExpandedKey)
		{
			//First add round key
			State = ByteMatrix.Xor(State,ExpandedKey[0]);

			for (int i = 0; i < 9; i++) {
				SubBytesEncrypt (State);
				ShiftRowsEncrypt (State);
				MixColumnsEncrypt (State);
				State = ByteMatrix.Xor(State,ExpandedKey[i+1]);
			}

			//Final round
			SubBytesEncrypt (State);
			ShiftRowsEncrypt (State);
			State = ByteMatrix.Xor(State,ExpandedKey[10]);

			return State;
		}

		static void SubBytesEncrypt(ByteMatrix State)
		{
			for (int C = 0; C < 4; C++)
				for (int R = 0; R < 4; R++)
					State.Set (C, R, SBox.EncryptConvert (State.Get (C, R)));
		}

		static void ShiftRowsEncrypt(ByteMatrix State)
		{
			byte T = 0;

			//Move left 1 byte
			T = State.Get(0,1);
			State.Set (0, 1, State.Get (1, 1));
			State.Set (1, 1, State.Get (2, 1));
			State.Set (2, 1, State.Get (3, 1));
			State.Set (3, 1, T);

			//Move left 2 bytes
			for (int i = 0; i < 2; i++) {
				T = State.Get (0, 2);
				State.Set (0, 2, State.Get (1, 2));
				State.Set (1, 2, State.Get (2, 2));
				State.Set (2, 2, State.Get (3, 2));
				State.Set (3, 2, T);
			}

			//Move left 3 bytes
			for (int i = 0; i < 3; i++) {
				T = State.Get (0, 3);
				State.Set (0, 3, State.Get (1, 3));
				State.Set (1, 3, State.Get (2, 3));
				State.Set (2, 3, State.Get (3, 3));
				State.Set (3, 3, T);
			}
		}

		static void MixColumnsEncrypt(ByteMatrix State)
		{
			for (int C = 0; C < 4; C++) {
				byte R0 = State.Get (C, 0);
				byte R1 = State.Get (C, 1);
				byte R2 = State.Get (C, 2);
				byte R3 = State.Get (C, 3);

				Galois.MixEncryptColumn (ref R0, ref R1, ref R2, ref R3);

				State.Set (C, 0, R0);
				State.Set (C, 1, R1);
				State.Set (C, 2, R2);
				State.Set (C, 3, R3);
			}
		}
	}
}

