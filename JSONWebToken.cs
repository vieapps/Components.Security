#region Related components
using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Static servicing methods for working with JSON Web Token
	/// </summary>
	public static class JSONWebToken
	{
		/// <summary>
		/// Encodes a JSON Web Token
		/// </summary>
		/// <param name="payload">An arbitrary payload</param>
		/// <param name="key">The key used to sign</param>
		/// <param name="hashAlgorithm">The hash algorithm used to sign (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512)</param>
		/// <returns>The string that presents a JSON Web Token</returns>
		public static string Encode(JObject payload, string key, string hashAlgorithm = null)
		{
			var segments = new List<string>
			{
				new Dictionary<string, string>
				{
					{ "typ", "JWT" },
					{ "alg", (hashAlgorithm ?? "SHA256").Replace(StringComparison.OrdinalIgnoreCase, "sha", "hs") }
				}.ToJson().ToString(Formatting.None).ToBase64Url(),
				(payload ?? new JObject()).ToString(Formatting.None).ToBase64Url()
			};
			segments.Add(segments.Join(".").GetHMAC(key ?? CryptoService.DEFAULT_PASS_PHRASE, hashAlgorithm ?? "SHA256", false).ToBase64Url(true));
			return segments.Join(".");
		}

		/// <summary>
		/// Decodes a given JSON Web Token and return the string that presents the JSON payload 
		/// </summary>
		/// <param name="token">The JSON Web Token</param>
		/// <param name="key">The key that were used to sign the JSON Web Token</param>
		/// <param name="verify">Whether to verify the signature</param>
		/// <returns>A string that representing the payload</returns>
		/// <exception cref="InvalidTokenSignatureException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
		public static string Decode(string token, string key, bool verify = true)
		{
			var parts = !string.IsNullOrWhiteSpace(token)
				? token.ToArray('.', true)
				: Array.Empty<string>();

			if (parts.Length != 3)
				throw new InvalidTokenException("The token must consists from 3 delimited by dot parts");

			if (verify && !parts[2].Equals($"{parts[0]}.{parts[1]}".GetHMAC(key ?? CryptoService.DEFAULT_PASS_PHRASE, parts[0].FromBase64Url().ToExpandoObject().Get("alg", "hs256").Replace(StringComparison.OrdinalIgnoreCase, "hs", "sha"), false).ToBase64Url(true)))
				throw new InvalidTokenSignatureException();

			return parts[1].FromBase64Url();
		}

		/// <summary>
		/// Decodes a given JSON Web Token and return the JSON payload
		/// </summary>
		/// <param name="token">The JSON Web Token</param>
		/// <param name="key">The key that were used to sign the JSON Web Token</param>
		/// <param name="verify">Whether to verify the signature</param>
		/// <returns>An <see cref="JObject">JObject</see> object that representing the payload</returns>
		/// <exception cref="InvalidTokenSignatureException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
		public static JObject DecodeAsJson(string token, string key, bool verify = true)
			=> JObject.Parse(JSONWebToken.Decode(token, key, verify));
	}
}