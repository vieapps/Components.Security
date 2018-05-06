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
	/// All available hash algorithms for working with JSON Web Token
	/// </summary>
	[Serializable]
	public enum JSONWebTokenHashAlgorithm
	{
		/// <summary>
		/// HMAC SHA256
		/// </summary>
		HS256,

		/// <summary>
		/// HMAC SHA384
		/// </summary>
		HS384,

		/// <summary>
		/// HMAC SHA512
		/// </summary>
		HS512
	}

	/// <summary>
	/// Static servicing methods for working with JSON Web Token
	/// </summary>
	public static class JSONWebToken
	{

		static Dictionary<JSONWebTokenHashAlgorithm, Func<string, string, string>> HashAlgorithms
			= new Dictionary<JSONWebTokenHashAlgorithm, Func<string, string, string>>
			{
				{ JSONWebTokenHashAlgorithm.HS256, (key, value) => value.GetHMACSHA256(key, false).ToBase64Url(true)  },
				{ JSONWebTokenHashAlgorithm.HS384, (key, value) => value.GetHMACSHA384(key, false).ToBase64Url(true)  },
				{ JSONWebTokenHashAlgorithm.HS512, (key, value) => value.GetHMACSHA512(key, false).ToBase64Url(true)  }
			};

		static JSONWebTokenHashAlgorithm GetHashAlgorithm(string algorithm)
		{
			switch (algorithm.ToLower())
			{
				case "hs256":
					return JSONWebTokenHashAlgorithm.HS256;

				case "hs384":
					return JSONWebTokenHashAlgorithm.HS384;

				case "hs512":
					return JSONWebTokenHashAlgorithm.HS512;

				default:
					throw new InvalidTokenSignatureException("The hash algorithm is not supported");
			}
		}

		/// <summary>
		/// Creates a JSON Web Token, given a header, a payload, the signing key, and the algorithm to use.
		/// </summary>
		/// <param name="headers">An arbitrary set of extra headers. Will be augmented with the standard "typ" and "alg" headers.</param>
		/// <param name="payload">An arbitrary payload.</param>
		/// <param name="key">The key used to sign the token.</param>
		/// <param name="algorithm">The hash algorithm to use.</param>
		/// <returns>The generated JSON Web Token in Base64Url string.</returns>
		public static string Encode(IDictionary<string, object> headers, JObject payload, string key, JSONWebTokenHashAlgorithm algorithm = JSONWebTokenHashAlgorithm.HS256)
		{
			var header = new Dictionary<string, object>(headers)
			{
				{ "typ", "JWT" },
				{ "alg", algorithm.ToString() }
			};

			var segments = new List<string>()
			{
				header.ToJson().ToString(Formatting.None).ToBase64Url(),
				payload.ToString(Formatting.None).ToBase64Url()
			};
			segments.Add(JSONWebToken.HashAlgorithms[algorithm](key, string.Join(".", segments)));

			return string.Join(".", segments);
		}

		/// <summary>
		/// Creates a JSON Web Token, given a payload, the signing key, and the algorithm to use.
		/// </summary>
		/// <param name="payload">An arbitrary payload.</param>
		/// <param name="key">The key used to sign the token.</param>
		/// <param name="algorithm">The hash algorithm to use.</param>
		/// <returns>The generated JWT.</returns>
		public static string Encode(JObject payload, string key, JSONWebTokenHashAlgorithm algorithm = JSONWebTokenHashAlgorithm.HS256)
		{
			return JSONWebToken.Encode(new Dictionary<string, object>(), payload, key, algorithm);
		}

		/// <summary>
		/// Given a JSON Web Token, decode it and return the JSON payload string.
		/// </summary>
		/// <param name="token">The JSON Web Token (encoded with Base64Url).</param>
		/// <param name="key">The key that were used to sign the JSON Web Token.</param>
		/// <param name="verify">Whether to verify the signature (default is true).</param>
		/// <returns>A string containing the JSON payload.</returns>
		/// <exception cref="InvalidTokenSignatureException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
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
				var algorithm = header["alg"] != null
					? JSONWebToken.GetHashAlgorithm((header["alg"] as JValue).Value as string)
					: JSONWebTokenHashAlgorithm.HS256;
				var signature = JSONWebToken.HashAlgorithms[algorithm](key, parts[0] + "." + parts[1]);
				if (!signature.Equals(parts[2]))
					throw new InvalidTokenSignatureException($"Invalid signature. Expected '{signature}' but got '{parts[2]}'.");
			}

			return parts[1].FromBase64Url();
		}

		/// <summary>
		/// Given a JSON Web Token, decode it and return the JSON payload.
		/// </summary>
		/// <param name="token">The JSON Web Token (encoded with Base64Url).</param>
		/// <param name="key">The key that were used to sign the JSON Web Token.</param>
		/// <param name="verify">Whether to verify the signature (default is true).</param>
		/// <returns>An <see cref="JObject">JObject</see> object representing the payload.</returns>
		/// <exception cref="InvalidTokenSignatureException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm.</exception>
		public static JObject DecodeAsJson(string token, string key, bool verify = true)
		{
			return JObject.Parse(JSONWebToken.Decode(token, key, verify));
		}
	}
}