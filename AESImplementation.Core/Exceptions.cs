using System;

namespace AESImplementation.Core
{
	public class AESKeyLengthException : Exception
	{
		public AESKeyLengthException() : base("The provided key must be exactly 16-bytes long.")
		{
		}
	}
}

