using System;
using System.Text;

namespace AESImplementation.Core
{
	internal static class Utils
	{
		internal static byte Xor(this byte B1, byte Other)
		{
			return (byte)(B1 ^ Other);
		}

		internal static byte[] Xor(this byte[] B1, byte[] Other)
		{
			if (B1.LongLength != Other.LongLength)
				throw new ArgumentException ("Arrays must be equal in length.");

			byte[] Result = new byte[B1.LongLength];
			for (long i = 0; i < B1.LongLength; i++)
				Result [i] = B1 [i].Xor (Other [i]);

			return Result;
		}

		internal static E[] Slice<E>(this E[] Array, long Start, long Length)
		{
			E[] Result = new E[Length];
			for (long i = 0; i < Length; i++)
				Result [i] = Array [i + Start];
			return Result;
		}
	}

	internal class ByteMatrix
	{
		byte[,] MatrixBytes;

		internal ByteMatrix()
			:this(new byte[16])
		{
		}

		internal ByteMatrix(byte[] Bytes)
		{
			if (Bytes.Length != 16)
				throw new ArgumentException ("Byte array must be exactly 16 bytes in length.");
			
			MatrixBytes = new byte[4, 4];

			for(int i=0; i<Bytes.Length; i++)
				Set (i/4, i%4, Bytes [i]);
		}

		internal byte Get(int Column, int Row)
		{
			return MatrixBytes [Column, Row];
		}

		internal void Set(int Column, int Row, byte Value)
		{
			MatrixBytes [Column, Row] = Value;
		}

		internal byte[] GetBytes()
		{
			byte[] Result = new byte[16];
			for (int C = 0; C < 4; C++)
				for (int R = 0; R < 4; R++)
					Result [C * 4 + R] = Get (C, R);

			return Result;
		}

		public override string ToString ()
		{
			StringBuilder SB = new StringBuilder ();
			for (int R = 0; R < 4; R++) {
				for (int C = 0; C < 4; C++)
					SB.AppendFormat("{0:x2}\t", Get (C, R));

				SB.AppendLine ();
			}
			return SB.ToString ();
		}

		public override bool Equals (object obj)
		{
			if (obj == this)
				return true;
			if (obj == null)
				return false;

			ByteMatrix Casted = obj as ByteMatrix;
			if (Casted == null)
				return false;

			return Casted.MatrixBytes.Equals (this.MatrixBytes);
		}

		internal static ByteMatrix Xor (ByteMatrix M1, ByteMatrix M2)
		{
			ByteMatrix Result = new ByteMatrix ();
			for (int C = 0; C < 4; C++)
				for (int R = 0; R < 4; R++)
					Result.Set (C, R, M1.Get (C, R).Xor (M2.Get (C, R)));
			
			return Result;
		}
	}
}

