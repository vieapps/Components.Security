#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.Claims;
using System.Xml.Serialization;
using System.Numerics;
using System.Dynamic;
using System.Runtime.Serialization;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Components.Security
{
	public static class UserIdentityExtentions
	{

		#region Normalize & combine privileges
		internal static bool IsEmpty(HashSet<string> roles, HashSet<string> users)
		{
			return (roles == null || roles.Count < 1) && (users == null || users.Count < 1);
		}

		internal static bool IsNotEmpty(HashSet<string> roles, HashSet<string> users)
		{
			return (roles != null && roles.Count > 0) || (users != null && users.Count > 0);
		}

		/// <summary>
		/// Normalizes the privileges (access permissions) of a business entity
		/// </summary>
		/// <param name="privileges"></param>
		/// <returns></returns>
		public static Privileges Normalize(this Privileges privileges)
		{
			if (privileges == null)
				return null;

			var permissions = new Privileges();

			if (UserIdentityExtentions.IsEmpty(privileges.DownloadableRoles, privileges.DownloadableUsers))
				permissions.DownloadableRoles = permissions.DownloadableUsers = null;
			else
			{
				permissions.DownloadableRoles = privileges.DownloadableRoles;
				permissions.DownloadableUsers = privileges.DownloadableUsers;
			}

			if (UserIdentityExtentions.IsEmpty(privileges.ViewableRoles, privileges.ViewableUsers))
				permissions.ViewableRoles = permissions.ViewableUsers = null;
			else
			{
				permissions.ViewableRoles = privileges.ViewableRoles;
				permissions.ViewableUsers = privileges.ViewableUsers;
			}

			if (UserIdentityExtentions.IsEmpty(privileges.ContributiveRoles, privileges.ContributiveUsers))
				permissions.ContributiveRoles = permissions.ContributiveUsers = null;
			else
			{
				permissions.ContributiveRoles = privileges.ContributiveRoles;
				permissions.ContributiveUsers = privileges.ContributiveUsers;
			}

			if (UserIdentityExtentions.IsEmpty(privileges.EditableRoles, privileges.EditableUsers))
				permissions.EditableRoles = permissions.EditableUsers = null;
			else
			{
				permissions.EditableRoles = privileges.EditableRoles;
				permissions.EditableUsers = privileges.EditableUsers;
			}

			if (UserIdentityExtentions.IsEmpty(privileges.ModerateRoles, privileges.ModerateUsers))
				permissions.ModerateRoles = permissions.ModerateUsers = null;
			else
			{
				permissions.ModerateRoles = privileges.ModerateRoles;
				permissions.ModerateUsers = privileges.ModerateUsers;
			}

			if (UserIdentityExtentions.IsEmpty(privileges.AdministrativeRoles, privileges.AdministrativeUsers))
				permissions.AdministrativeRoles = permissions.AdministrativeUsers = null;
			else
			{
				permissions.AdministrativeRoles = privileges.AdministrativeRoles;
				permissions.AdministrativeUsers = privileges.AdministrativeUsers;
			}

			if (UserIdentityExtentions.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
		}

		/// <summary>
		/// Combines the original permissions of a business entity with parent permissions
		/// </summary>
		/// <param name="originalPrivileges"></param>
		/// <param name="parentPrivileges"></param>
		/// <returns></returns>
		public static Privileges Combine(this Privileges originalPrivileges, Privileges parentPrivileges)
		{
			if (originalPrivileges == null && parentPrivileges == null)
				return null;

			var permissions = new Privileges();

			if (originalPrivileges != null && UserIdentityExtentions.IsNotEmpty(originalPrivileges.DownloadableRoles, originalPrivileges.DownloadableUsers))
			{
				permissions.DownloadableRoles = originalPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = originalPrivileges.DownloadableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.DownloadableRoles = parentPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = parentPrivileges.DownloadableUsers;
			}

			if (originalPrivileges != null && UserIdentityExtentions.IsNotEmpty(originalPrivileges.ViewableRoles, originalPrivileges.ViewableUsers))
			{
				permissions.ViewableRoles = originalPrivileges.ViewableRoles;
				permissions.ViewableUsers = originalPrivileges.ViewableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ViewableRoles = parentPrivileges.ViewableRoles;
				permissions.ViewableUsers = parentPrivileges.ViewableUsers;
			}

			if (originalPrivileges != null && UserIdentityExtentions.IsNotEmpty(originalPrivileges.ContributiveRoles, originalPrivileges.ContributiveUsers))
			{
				permissions.ContributiveRoles = originalPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = originalPrivileges.ContributiveUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ContributiveRoles = parentPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = parentPrivileges.ContributiveUsers;
			}

			if (originalPrivileges != null && UserIdentityExtentions.IsNotEmpty(originalPrivileges.EditableRoles, originalPrivileges.EditableUsers))
			{
				permissions.EditableRoles = originalPrivileges.EditableRoles;
				permissions.EditableUsers = originalPrivileges.EditableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.EditableRoles = parentPrivileges.EditableRoles;
				permissions.EditableUsers = parentPrivileges.EditableUsers;
			}

			if (originalPrivileges != null && UserIdentityExtentions.IsNotEmpty(originalPrivileges.ModerateRoles, originalPrivileges.ModerateUsers))
			{
				permissions.ModerateRoles = originalPrivileges.ModerateRoles;
				permissions.ModerateUsers = originalPrivileges.ModerateUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ModerateRoles = parentPrivileges.ModerateRoles;
				permissions.ModerateUsers = parentPrivileges.ModerateUsers;
			}

			if (originalPrivileges != null && UserIdentityExtentions.IsNotEmpty(originalPrivileges.AdministrativeRoles, originalPrivileges.AdministrativeUsers))
			{
				permissions.AdministrativeRoles = originalPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = originalPrivileges.AdministrativeUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.AdministrativeRoles = parentPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = parentPrivileges.AdministrativeUsers;
			}

			if (UserIdentityExtentions.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& UserIdentityExtentions.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
		}
		#endregion

		#region Working with access token
		/// <summary>
		/// Gets the access token of an user that associate with a session and return a JSON Web Token
		/// </summary>
		/// <param name="userID">The string that presents the identity of the user</param>
		/// <param name="sessionID">The string that presents the identity of the associated session</param>
		/// <param name="roles">The collection that presents the roles that the user was belong to</param>
		/// <param name="privileges">The collection that presents the access privileges that the user was got</param>
		/// <param name="key">The key used to encrypt and sign</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <param name="hashAlgorithm">The hash algorithm used to hash and sign (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512)</param>
		/// <returns>A JSON Web Token that presents the access token</returns>
		public static string GetAccessToken(string userID, string sessionID, IEnumerable<string> roles, IEnumerable<Privilege> privileges, BigInteger key, Action<JObject> onPreCompleted = null, string hashAlgorithm = "BLAKE256")
		{
			var token = new JObject
			{
				{ "uid", userID },
				{ "sid", sessionID },
				{ "rls", (roles ?? new List<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToJArray() },
				{ "pls", (privileges ?? new List<Privilege>()).ToJArray() }
			}.ToString(Formatting.None);
			var hash = token.GetHash(hashAlgorithm);
			var signature = key.Sign(hash);
			var publicKey = key.GenerateECCPublicKey();
			var payload = new JObject
			{
				{ "iat", DateTime.Now.ToUnixTimestamp() },
				{ "uid", userID },
				{ "sid", publicKey.Encrypt(sessionID, true) },
				{ "tkn", publicKey.Encrypt(token, true) },
				{ "tkh", hash.ToHex() },
				{ "sig", ECCsecp256k1.GetSignature(signature) }
			};
			onPreCompleted?.Invoke(payload);
			return JSONWebToken.Encode(payload, ECCsecp256k1.GetPublicKey(publicKey).ToHex(), hashAlgorithm);
		}

		/// <summary>
		/// Gets the access token of an user that associate with a session and return a JSON Web Token
		/// </summary>
		/// <param name="userIdentity">The user identity</param>
		/// <param name="key">The key used to encrypt and sign</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <param name="hashAlgorithm">The hash algorithm used to hash and sign (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512)</param>
		/// <returns>A JSON Web Token that presents the access token</returns>
		public static string GetAccessToken(this UserIdentity userIdentity, BigInteger key, Action<JObject> onPreCompleted = null, string hashAlgorithm = "BLAKE256")
		{
			var roles = SystemRole.All.ToString()
				+ (!userIdentity.ID.Equals("") ? "," + SystemRole.Authenticated.ToString() : "")
				+ (userIdentity.IsSystemAdministrator ? "," + SystemRole.SystemAdministrator.ToString() : "");
			return UserIdentityExtentions.GetAccessToken(userIdentity.ID, userIdentity.SessionID, (userIdentity.Roles ?? new List<string>()).Concat(roles.ToList()), userIdentity.Privileges, key, onPreCompleted, hashAlgorithm);
		}

		/// <summary>
		/// Parses the given access token and return an <see cref="UserIdentity">UserIdentity</see> object
		/// </summary>
		/// <param name="accessToken">The JSON Web Token that presents the access token</param>
		/// <param name="key">The key used to decrypt and verify</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <param name="hashAlgorithm">The hash algorithm used to hash and sign (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512)</param>
		/// <returns>The <see cref="UserIdentity">UserIdentity</see> object that presented by the access token</returns>
		public static UserIdentity ParseAccessToken(this string accessToken, BigInteger key, Action<JObject, UserIdentity> onPreCompleted = null, string hashAlgorithm = "BLAKE256")
		{
			try
			{
				// decode JSON Web Token
				var publicKey = key.GenerateECCPublicKey();
				var payload = JSONWebToken.DecodeAsJson(accessToken, ECCsecp256k1.GetPublicKey(publicKey).ToHex());

				// get values
				var token = payload.ToExpandoObject();
				var userID = token.Get<string>("uid");
				var sessionID = token.Get<string>("sid");

				// verify (1st)
				if (string.IsNullOrWhiteSpace(userID) || string.IsNullOrWhiteSpace(sessionID))
					throw new InvalidTokenException("Identity is not found");
				else
					sessionID = key.Decrypt(sessionID, true);

				// verify (2nd)
				var hash = token.Get<string>("tkh").HexToBytes();
				var signature = ECCsecp256k1.GetSignature(token.Get<string>("sig"));
				if (!publicKey.Verify(hash, signature))
					throw new InvalidTokenSignatureException();

				// decrypt & verify (3rd)
				var strToken = key.Decrypt(token.Get<string>("tkn"), true);
				if (!hash.SequenceEqual(strToken.GetHash(hashAlgorithm)))
					throw new InvalidTokenException("Digest is not matched");

				// verify (4th)
				token = strToken.ToExpandoObject();
				if (!userID.IsEquals(token.Get<string>("uid")) || !sessionID.IsEquals(token.Get<string>("sid")))
					throw new InvalidTokenException("Identity is not matched");

				// create user identity
				var roles = token.Get<List<string>>("rls");
				var privileges = token.Get<List<Privilege>>("pls");
				var userIdentity = new UserIdentity(userID, sessionID, roles, privileges);

				// callback
				onPreCompleted?.Invoke(payload, userIdentity);

				// return user identity
				return userIdentity;
			}
			catch (InvalidTokenSignatureException)
			{
				throw;
			}
			catch (InvalidTokenException)
			{
				throw;
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Invalid access token", ex);
			}
		}
		#endregion

		#region Working with authenticate token
		/// <summary>
		/// Gets the authenticate token of an user that associate with a session and return a JSON Web Token
		/// </summary>
		/// <param name="userID">The string that presents identity of an user</param>
		/// <param name="sessionID">The string that presents identity of working session that associated with user</param>
		/// <param name="encryptionKey">The passphrase that used to encrypt data using AES</param>
		/// <param name="signKey">The passphrase that used to sign the token</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <returns>A JSON Web Token that presents the authenticate token</returns>
		public static string GetAuthenticateToken(string userID, string sessionID, string encryptionKey, string signKey, Action<JObject> onPreCompleted = null)
		{
			var payload = new JObject
			{
				{ "iat", DateTime.Now.ToUnixTimestamp() },
				{ "uid", userID },
				{ "sid", sessionID.Encrypt(encryptionKey, true) },
				{ "sig", $"{sessionID}@{userID}".GetHMACBLAKE256(encryptionKey) }
			};
			onPreCompleted?.Invoke(payload);
			return JSONWebToken.Encode(payload, signKey);
		}

		/// <summary>
		/// Gets the authenticate token of an user and return a JSON Web Token
		/// </summary>
		/// <param name="user">The identity of an user</param>
		/// <param name="encryptionKey">The passphrase that used to encrypt data using AES</param>
		/// <param name="signKey">The passphrase that used to sign the token</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <returns>A JSON Web Token that presents the authenticate token</returns>
		public static string GetAuthenticateToken(this UserIdentity user, string encryptionKey, string signKey, Action<JObject> onPreCompleted = null)
			=> UserIdentityExtentions.GetAuthenticateToken(user.ID, user.SessionID, encryptionKey, signKey, onPreCompleted);

		/// <summary>
		/// Parses the given authenticate token and return an <see cref="UserIdentity">UserIdentity</see> object
		/// </summary>
		/// <param name="authenticateToken">The JSON Web Token that presents the authenticate token</param>
		/// <param name="encryptionKey">The passphrase that used to generate the encryption key for decrypting data using AES</param>
		/// <param name="shareKey">The passphrase that presents shared key for verify the token</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <returns>The <see cref="UserIdentity">UserIdentity</see> object that presented by the authenticate token</returns>
		public static UserIdentity ParseAuthenticateToken(this string authenticateToken, string encryptionKey, string shareKey, Action<JObject, UserIdentity> onPreCompleted = null)
		{
			try
			{
				// decode JSON Web Token
				var payload = JSONWebToken.DecodeAsJson(authenticateToken, shareKey);

				// get values
				var token = payload.ToExpandoObject();
				var issuedAt = token.Get<long>("iat");
				var userID = token.Get<string>("uid");
				var sessionID = token.Get<string>("sid");
				var signature = token.Get<string>("sig");

				// verify
				if (DateTime.Now.ToUnixTimestamp() - issuedAt > 30)
					throw new TokenExpiredException();

				if (userID == null || string.IsNullOrWhiteSpace(sessionID))
					throw new InvalidTokenException("Identity is invalid");

				sessionID = sessionID.Decrypt(encryptionKey, true);
				if (string.IsNullOrWhiteSpace(signature) || !signature.Equals($"{sessionID}@{userID}".GetHMACBLAKE256(encryptionKey)))
					throw new InvalidTokenSignatureException();

				// create user identity
				var userIdentity = new UserIdentity(userID, sessionID);

				// callback
				onPreCompleted?.Invoke(payload, userIdentity);

				// return user identity
				return userIdentity;
			}
			catch (InvalidTokenSignatureException)
			{
				throw;
			}
			catch (TokenExpiredException)
			{
				throw;
			}
			catch (InvalidTokenException)
			{
				throw;
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Invalid authenticate token", ex);
			}
		}
		#endregion

	}
}