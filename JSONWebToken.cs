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
		/// Creates a JSON Web Token
		/// </summary>
		/// <param name="payload">An arbitrary payload</param>
		/// <param name="key">The key used to sign the token</param>
		/// <param name="hashAlgorithm">The hash algorithm to use (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512) - default is SHA 256</param>
		/// <param name="headers">An arbitrary set of extra headers, will be augmented with the standard "typ" and "alg" headers</param>
		/// <returns>A JSON Web Token in Base64Url string</returns>
		public static string Encode(JObject payload, string key, string hashAlgorithm = "SHA256", IDictionary<string, string> headers = null)
		{
			var segments = new List<string>
			{
				new Dictionary<string, string>(headers ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase)
				{
					{ "typ", "JWT" },
					{ "alg", hashAlgorithm.Replace(StringComparison.OrdinalIgnoreCase, "SHA", "hs") }
				}.ToJson().ToString(Formatting.None).ToBase64Url(),
				(payload ?? new JObject()).ToString(Formatting.None).ToBase64Url()
			};
			segments.Add(string.Join(".", segments).GetHMAC(key, hashAlgorithm, false).ToBase64Url(true));
			return string.Join(".", segments);
		}

		/// <summary>
		/// Decodes a given a JSON Web Token and return the JSON payload string
		/// </summary>
		/// <param name="token">The JSON Web Token (encoded with Base64Url)</param>
		/// <param name="key">The key that were used to sign the JSON Web Token</param>
		/// <param name="verify">Whether to verify the signature (default is true)</param>
		/// <returns>A string containing the JSON payload</returns>
		/// <exception cref="InvalidTokenSignatureException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
		public static string Decode(string token, string key, bool verify = true)
		{
			var parts = !string.IsNullOrEmpty(token)
				? token.ToArray('.', true)
				: new string[] { };

			if (parts.Length != 3)
				throw new InvalidTokenException("The token must consists from 3 delimited by dot parts");

			if (verify)
			{
				var header = JObject.Parse(parts[0].FromBase64Url());
				var hashAlgorithm = ((header["alg"] as JValue).Value as string ?? "hs256").Replace(StringComparison.OrdinalIgnoreCase, "hs", "SHA");
				var signature = (parts[0] + "." + parts[1]).GetHMAC(key, hashAlgorithm, false).ToBase64Url(true);
				if (!signature.Equals(parts[2]))
					throw new InvalidTokenSignatureException($"Invalid signature, expected \"{signature}\" but got \"{parts[2]}\"");
			}

			return parts[1].FromBase64Url();
		}

		/// <summary>
		/// Decodes a given a JSON Web Token and return the JSON payload string
		/// </summary>
		/// <param name="token">The JSON Web Token (encoded with Base64Url)</param>
		/// <param name="key">The key that were used to sign the JSON Web Token</param>
		/// <param name="verify">Whether to verify the signature (default is true)</param>
		/// <returns>An <see cref="JObject">JObject</see> object representing the payload</returns>
		/// <exception cref="InvalidTokenSignatureException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
		public static JObject DecodeAsJson(string token, string key, bool verify = true)
		{
			return JObject.Parse(JSONWebToken.Decode(token, key, verify));
		}
	}
}