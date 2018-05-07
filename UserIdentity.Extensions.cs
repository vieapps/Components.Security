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
		/// Gets the access token
		/// </summary>
		/// <param name="userID">The string that presents the identity of the user</param>
		/// <param name="sessionID">The string that presents the identity of the associated session</param>
		/// <param name="roles">The collection that presents the roles that the user was belong to</param>
		/// <param name="privileges">The collection that presents the access privileges that the user was got</param>
		/// <param name="eccKey">The key for encrypting and signing using ECCsecp256k1</param>
		/// <returns>The string that presennts the encrypted access token</returns>
		public static string GetAccessToken(string userID, string sessionID, IEnumerable<string> roles, IEnumerable<Privilege> privileges, BigInteger eccKey)
		{
			var token = new JObject
			{
				{ "UserID", userID },
				{ "SessionID", sessionID },
				{ "Roles", (roles ?? new List<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToJArray() },
				{ "Privileges", (privileges ?? new List<Privilege>()).ToJArray() }
			};

			var data = token.ToString(Formatting.None).ToBytes();
			var hash = data.GetHash("BLAKE256");

			token = new JObject
			{
				{ "Token", ECCsecp256k1.Encrypt(eccKey.GenerateECCPublicKey(), data).ToBase64() },
				{ "Hash", hash.ToHex() },
				{ "Signature", ECCsecp256k1.SignAsHex(eccKey, hash) }
			};

			return token.ToString(Formatting.None).ToBase64();
		}

		/// <summary>
		/// Gets the access token
		/// </summary>
		/// <param name="userIdentity">The user identity</param>
		/// <param name="eccKey">The key for verifying and decrypting using ECCsecp256k1</param>
		/// <returns>The string that presennts the encrypted access token</returns>
		public static string GetAccessToken(this UserIdentity userIdentity, BigInteger eccKey)
		{
			var roles = SystemRole.All.ToString()
				+ (!userIdentity.ID.Equals("") ? "," + SystemRole.Authenticated.ToString() : "")
				+ (userIdentity.IsSystemAdministrator ? "," + SystemRole.SystemAdministrator.ToString() : "");
			return UserIdentityExtentions.GetAccessToken(userIdentity.ID, userIdentity.SessionID, (userIdentity.Roles ?? new List<string>()).Concat(roles.ToList()), userIdentity.Privileges, eccKey);
		}

		/// <summary>
		/// Parses the access token to get <see cref="UserIdentity">UserIdentity</see> object
		/// </summary>
		/// <param name="accessToken">The string that presennts the encrypted access token</param>
		/// <param name="eccKey">The key for verifying and decrypting using ECCsecp256k1</param>
		/// <param name="getUserName">The function to get name of user</param>
		/// <returns>The <see cref="UserIdentity">UserIdentity</see> object that presented by the access token</returns>
		public static UserIdentity ParseAccessToken(this string accessToken, BigInteger eccKey, Func<string, string> getUserName = null)
		{
			// decrypt & parse
			string token = null, hash = null, signature = null;
			try
			{
				var info = accessToken.FromBase64().ToExpandoObject();
				token = info.Get<string>("Token");
				hash = info.Get<string>("Hash");
				signature = info.Get<string>("Signature");
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException(ex);
			}

			// verify
			if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(hash) || string.IsNullOrWhiteSpace(signature))
				throw new InvalidTokenException();

			try
			{
				if (!ECCsecp256k1.Verify(eccKey.GenerateECCPublicKey(), hash.HexToBytes(), signature))
					throw new InvalidTokenException();
			}
			catch (Exception ex)
			{
				if (ex is InvalidTokenException)
					throw ex;
				else
					throw new InvalidTokenException(ex);
			}

			// deserialize
			try
			{
				var info = ECCsecp256k1.Decrypt(eccKey, token.Base64ToBytes()).GetString().ToExpandoObject();
				var userID = info.Get<string>("UserID");
				var userName = getUserName?.Invoke(userID);
				var sessionID = info.Get<string>("SessionID");
				var roles = info.Get<List<string>>("Roles");
				var privileges = info.Get<List<Privilege>>("Privileges");
				return new UserIdentity(userID, userName, sessionID, roles, privileges);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot deserialize the access token", ex);
			}
		}
		#endregion

		#region Working with JSON Web Token
		/// <summary>
		/// Gets the JSON Web Token
		/// </summary>
		/// <param name="userID">The string that presents identity of an user</param>
		/// <param name="sessionID">The string that presents identity of working session that associated with user</param>
		/// <param name="encryptionKey">The passphrase that used to generate the encryption key for encrypting data using AES</param>
		/// <param name="shareKey">The passphrase that presents shared key for signing the token</param>
		/// <param name="onPreCompleted">The action to run before the parsing process is compeleted</param>
		/// <returns>The string that presents a JSON Web Token</returns>
		public static string GetJSONWebToken(string userID, string sessionID, string encryptionKey, string shareKey, Action<JObject> onPreCompleted = null)
		{
			var payload = new JObject
			{
				{ "iat", DateTime.Now.ToUnixTimestamp() },
				{ "uid", userID },
				{ "jti", sessionID.Encrypt(encryptionKey, true) },
				{ "jts", sessionID.GetHMACBLAKE256(userID) }
			};

			onPreCompleted?.Invoke(payload);
			return JSONWebToken.Encode(payload, shareKey);
		}

		/// <summary>
		/// Parses the JSON Web Token (return a tuple value with first element is user identity, second is session identity)
		/// </summary>
		/// <param name="jwtoken">The string that presents a JSON Web Token</param>
		/// <param name="encryptionKey">The passphrase that used to generate the encryption key for decrypting data using AES</param>
		/// <param name="shareKey">The passphrase that presents shared key for verify the token</param>
		/// <param name="onPreCompleted">The action to run before the parsing process is compeleted</param>
		/// <returns>The tuple with first element is user identity, second is session identity</returns>
		public static Tuple<string, string> ParseJSONWebToken(this string jwtoken, string encryptionKey, string shareKey, Action<ExpandoObject> onPreCompleted = null)
		{
			// parse JSON Web Token
			ExpandoObject token = null;
			try
			{
				token = JSONWebToken.Decode(jwtoken, shareKey).ToExpandoObject();
			}
			catch (InvalidTokenSignatureException)
			{
				throw;
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException(ex);
			}

			// check issued time
			var issuedAt = DateTime.Now.AddMinutes(-60).ToUnixTimestamp();
			try
			{
				issuedAt = token.Get<long>("iat");
			}
			catch { }
			if (DateTime.Now.ToUnixTimestamp() - issuedAt > 30)
				throw new TokenExpiredException();

			// get user identity
			var userID = token.Get<string>("uid");
			if (userID == null)
				throw new InvalidTokenException("Token is invalid (Identity is invalid)");

			// get session identity
			var sessionID = token.Get<string>("jti");
			if (string.IsNullOrWhiteSpace(sessionID))
				throw new InvalidTokenException("Token is invalid (Identity is invalid)");

			try
			{
				sessionID = sessionID.Decrypt(encryptionKey, true);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Token is invalid (Identity is invalid)", ex);
			}

			var signature = token.Get<string>("jts");
			if (string.IsNullOrWhiteSpace(signature) || !signature.Equals(sessionID.GetHMACBLAKE256(userID)))
				throw new InvalidTokenSignatureException("Token is invalid (Signature is invalid)");

			// return
			onPreCompleted?.Invoke(token);
			return new Tuple<string, string>(userID, sessionID);
		}
		#endregion

		#region Working with passport token
		/// <summary>
		/// Gets the passport token
		/// </summary>
		/// <param name="userIdentity">The user identity</param>
		/// <param name="deviceID">The string that presents identity of working device that associated with user</param>
		/// <param name="encryptionKey">The passphrase that used to generate the encryption key for encrypting data using AES</param>
		/// <param name="shareKey">The passphrase that presents shared key for signing the token</param>
		/// <param name="eccKey">The key for encrypting and signing using ECCsecp256k1</param>
		/// <returns>The string that presents a JSON Web Token</returns>
		public static string GetPassportToken(this UserIdentity userIdentity, string deviceID, string encryptionKey, string shareKey, BigInteger eccKey)
		{
			var accessToken = UserIdentityExtentions.GetAccessToken(userIdentity, eccKey);
			return UserIdentityExtentions.GetJSONWebToken(userIdentity.ID, userIdentity.SessionID, encryptionKey, shareKey, (token) =>
			{
				token["jtk"] = accessToken;
				token["did"] = deviceID;
			});
		}

		/// <summary>
		/// Parses the passport token (return a tuple value with first element is user identity, second element is is device identity)
		/// </summary>
		/// <param name="jwtoken">The string that presents a JSON Web Token</param>
		/// <param name="encryptionKey">The passphrase that used to generate the encryption key for decrypting data using AES</param>
		/// <param name="shareKey">The passphrase that presents shared key for verify the token</param>
		/// <param name="eccKey">The key for verifying and decrypting using ECCsecp256k1</param>
		/// <param name="getUserName">The function to get name of user</param>
		/// <returns>A tuple value with first element is user identity, second element is session identity, third element is access token, and last element is device identity</returns>
		public static Tuple<UserIdentity, string> ParsePassportToken(this string jwtoken, string encryptionKey, string shareKey, BigInteger eccKey, Func<string, string> getUserName = null)
		{
			var accessToken = "";
			var deviceID = "";
			var info = UserIdentityExtentions.ParseJSONWebToken(jwtoken, encryptionKey, shareKey, (token) =>
			{
				accessToken = token.Get<string>("jtk");
				deviceID = token.Get<string>("did");
			});

			if (string.IsNullOrWhiteSpace(accessToken) || string.IsNullOrWhiteSpace(deviceID))
				throw new InvalidTokenException();

			var userIdentity = UserIdentityExtentions.ParseAccessToken(accessToken, eccKey, getUserName);
			return !info.Item1.Equals(userIdentity.ID) || !info.Item2.Equals(userIdentity.SessionID)
				? throw new InvalidTokenException()
				: new Tuple<UserIdentity, string>(userIdentity, deviceID);
		}
		#endregion

	}

	/// <summary>
	/// Presents the identity of an user (backward compatible - need update to UserIdentity)
	/// </summary>
	[Serializable]
	public class User : UserIdentity, ISerializable
	{
		/// <summary>
		/// Initializes an identity of an user (backward compatible - need update to UserIdentity)
		/// </summary>
		public User() : base() { }
		public User(SerializationInfo serializationInfo, StreamingContext context) : base(serializationInfo, context) { }
	}
}