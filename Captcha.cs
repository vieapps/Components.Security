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
			=> UtilityService.GetRandomCode(useShortCode, useHex);

		/// <summary>
		/// Generates new code of the captcha
		/// </summary>
		/// <param name="salt">The string to use as salt</param>
		/// <returns>The encrypted string that contains code of captcha</returns>
		public static string GenerateCode(string salt = null)
			=> $"{DateTime.Now.ToUnixTimestamp()}-{salt ?? UtilityService.NewUUID.Left(13)}-{CaptchaService.GenerateRandomCode()}".Encrypt(CaptchaService.EncryptionKey, true);

		/// <summary>
		/// Validates captcha code
		/// </summary>
		/// <param name="captchaCode">The string that presents encrypted code</param>
		/// <param name="inputCode">The code that inputed by user</param>
		/// <returns>true if valid</returns>
		public static bool IsCodeValid(string captchaCode, string inputCode)
		{
			try
			{
				if (string.IsNullOrWhiteSpace(captchaCode) || string.IsNullOrWhiteSpace(inputCode))
					return false;

				var info = captchaCode.Decrypt(CaptchaService.EncryptionKey, true).ToArray('-');
				return (DateTime.Now.ToUnixTimestamp() - info.First().CastAs<long>()) / 60 > 5
					? false
					: inputCode.Trim().IsEquals(info.Last());
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		/// Gets the encryption key for encrypting/decrypting captcha image
		/// </summary>
		public static string EncryptionKey => UtilityService.GetAppSetting("Keys:Encryption", CryptoService.DEFAULT_PASS_PHRASE);
	}
}