#region Related components
using System;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Servicing methods for working with captcha images
	/// </summary>
	public static partial class CaptchaService
	{
		/// <summary>
		/// Generates random code for using with captcha or other purpose
		/// </summary>
		/// <param name="useShortCode">true to use short-code</param>
		/// <param name="useHex">true to use hexa in code</param>
		/// <returns>The string that presents random code</returns>
		public static string GenerateRandomCode(bool useShortCode = true, bool useHex = false)
		{
			var code = UtilityService.GetUUID();
			var length = 9;
			if (useShortCode)
				length = 4;

			if (!useHex)
			{
				code = UtilityService.GetRandomNumber(1000).ToString() + UtilityService.GetRandomNumber(1000).ToString();
				while (code.Length < length + 5)
					code += UtilityService.GetRandomNumber(1000).ToString();
			}

			var index = UtilityService.GetRandomNumber(0, code.Length);
			if (index > code.Length - length)
				index = code.Length - length;
			code = code.Substring(index, length);

			var random1 = ((char)UtilityService.GetRandomNumber(48, 57)).ToString();
			var replacement = "O";
			while (replacement.Equals("O"))
				replacement = ((char)UtilityService.GetRandomNumber(71, 90)).ToString();
			code = code.Replace(random1, replacement);

			if (length > 4)
			{
				var random2 = random1;
				while (random2.Equals(random1))
					random2 = ((char)UtilityService.GetRandomNumber(48, 57)).ToString();
				replacement = "O";
				while (replacement.Equals("O"))
					replacement = ((char)UtilityService.GetRandomNumber(71, 90)).ToString();
				code = code.Replace(random2, replacement);

				var random3 = random1;
				while (random3.Equals(random1))
				{
					random3 = ((char)UtilityService.GetRandomNumber(48, 57)).ToString();
					if (random3.Equals(random2))
						random3 = ((char)UtilityService.GetRandomNumber(48, 57)).ToString();
				}
				replacement = "O";
				while (replacement.Equals("O"))
					replacement = ((char)UtilityService.GetRandomNumber(71, 90)).ToString();
				code = code.Replace(random3, replacement);
			}

			var hasNumber = false;
			var hasChar = false;
			for (int charIndex = 0; charIndex < code.Length; charIndex++)
			{
				if (code[charIndex] >= '0' && code[charIndex] <= '9')
					hasNumber = true;
				if (code[charIndex] >= 'A' && code[charIndex] <= 'Z')
					hasChar = true;
				if (hasNumber && hasChar)
					break;
			}

			if (!hasNumber)
				code += ((char)UtilityService.GetRandomNumber(48, 57)).ToString();

			if (!hasChar)
			{
				replacement = "O";
				while (replacement.Equals("O"))
					replacement = ((char)UtilityService.GetRandomNumber(65, 90)).ToString();
				code += replacement;
			}

			return code.Right(length);
		}

		/// <summary>
		/// Generates new code of the captcha
		/// </summary>
		/// <param name="salt">The string to use as salt</param>
		/// <returns>The encrypted string that contains code of captcha</returns>
		public static string GenerateCode(string salt = null)
		{
			return (DateTime.Now.ToUnixTimestamp().ToString() + (string.IsNullOrWhiteSpace(salt) ? "" : "-" + salt) + "-" + CaptchaService.GenerateRandomCode()).Encrypt(CaptchaService.EncryptionKey, true);
		}

		/// <summary>
		/// Validates captcha code
		/// </summary>
		/// <param name="captchaCode">The string that presents encrypted code</param>
		/// <param name="inputCode">The code that inputed by user</param>
		/// <returns>true if valid</returns>
		public static bool IsCodeValid(string captchaCode, string inputCode)
		{
			if (string.IsNullOrWhiteSpace(captchaCode) || string.IsNullOrWhiteSpace(inputCode))
				return false;

			try
			{
				var codes = captchaCode.Decrypt(CaptchaService.EncryptionKey, true).ToArray('-');

				var datetime = codes.First().CastAs<long>().FromUnixTimestamp();
				if ((DateTime.Now - datetime).TotalMinutes > 5.0)
					return false;

				return inputCode.Trim().IsEquals(codes.Last());
			}
			catch
			{
				return false;
			}
		}

		static string EncryptionKey
		{
			get
			{
				return UtilityService.GetAppSetting("Keys:Encryption", CryptoService.DEFAULT_PASS_PHRASE);
			}
		}
	}
}