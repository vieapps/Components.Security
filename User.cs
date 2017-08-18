#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Web.Security;
using System.Xml.Serialization;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Converters;

using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Presents an user
	/// </summary>
	[Serializable]
	public class User
	{
		public User()
		{
			this.ID = "";
			this.Name = "";
			this.Role = SystemRole.All;
			this.Roles = new List<string>();
			this.Privileges = new List<Privilege>();
		}

		#region Properties
		/// <summary>
		/// Gets or sets the identity
		/// </summary>
		public string ID { get; set; }

		/// <summary>
		/// Gets or sets the name
		/// </summary>
		public string Name { get; set; }

		/// <summary>
		/// Gets or sets the system role
		/// </summary>
		[JsonConverter(typeof(StringEnumConverter))]
		public SystemRole Role { get; set; }

		/// <summary>
		/// Gets or sets the working roles (means working roles of business services)
		/// </summary>
		public List<string> Roles { get; set; }

		/// <summary>
		/// Gets or sets the working privileges (means scopes/working privileges of services/services' objects)
		/// </summary>
		public List<Privilege> Privileges { get; set; }
		#endregion

		#region Authentication
		[JsonIgnore, XmlIgnore]
		public string AuthenticationType { get { return "API"; } }

		[JsonIgnore, XmlIgnore]
		public bool IsAuthenticated
		{
			get
			{
				return !string.IsNullOrWhiteSpace(this.ID);
			}
		}
		#endregion

		#region Authorization
		/// <summary>
		/// Determines an user can manage (means the user can act like an administrator)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanManage(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			if (!this.IsAuthenticated)
				return false;

			var can = originalPrivileges != null && originalPrivileges.AdministrativeUsers != null && originalPrivileges.AdministrativeUsers.Contains(this.ID.ToLower());
			if (!can && this.Roles != null && originalPrivileges != null && originalPrivileges.AdministrativeRoles != null)
				can = originalPrivileges.AdministrativeRoles.Intersect(this.Roles).Count() > 0;

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.AdministrativeUsers != null && parentPrivileges.AdministrativeUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && parentPrivileges.AdministrativeRoles != null)
					can = parentPrivileges.AdministrativeRoles.Intersect(this.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can moderate (means the user can act like a moderator)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanModerate(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			if (!this.IsAuthenticated)
				return false;

			var can = this.CanManage(originalPrivileges, parentPrivileges);

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.ModerateUsers != null && originalPrivileges.ModerateUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && originalPrivileges != null && originalPrivileges.ModerateRoles != null)
					can = originalPrivileges.ModerateRoles.Intersect(this.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.ModerateUsers != null && parentPrivileges.ModerateUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && parentPrivileges.ModerateRoles != null)
					can = parentPrivileges.ModerateRoles.Intersect(this.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can edit (means the user can act like an editor)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanEdit(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			if (!this.IsAuthenticated)
				return false;

			var can = this.CanModerate(originalPrivileges, parentPrivileges);

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.EditableUsers != null && originalPrivileges.EditableUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && originalPrivileges != null && originalPrivileges.EditableRoles != null)
					can = originalPrivileges.EditableRoles.Intersect(this.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.EditableUsers != null && parentPrivileges.EditableUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && parentPrivileges.EditableRoles != null)
					can = parentPrivileges.EditableRoles.Intersect(this.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can contribute (means the user can act like a contributor)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanContribute(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			var can = this.CanEdit(originalPrivileges, parentPrivileges);

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.ContributiveUsers != null && !string.IsNullOrWhiteSpace(this.ID) && originalPrivileges.ContributiveUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && originalPrivileges != null && originalPrivileges.ContributiveRoles != null)
					can = originalPrivileges.ContributiveRoles.Intersect(this.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.ContributiveUsers != null && !string.IsNullOrWhiteSpace(this.ID) && parentPrivileges.ContributiveUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && parentPrivileges.ContributiveRoles != null)
					can = parentPrivileges.ContributiveRoles.Intersect(this.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can view (means the user can act like a viewer)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanView(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			var can = this.CanContribute(originalPrivileges, parentPrivileges);

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.ViewableUsers != null && !string.IsNullOrWhiteSpace(this.ID) && originalPrivileges.ViewableUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && originalPrivileges != null && originalPrivileges.ViewableRoles != null)
					can = originalPrivileges.ViewableRoles.Intersect(this.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.ViewableUsers != null && !string.IsNullOrWhiteSpace(this.ID) && parentPrivileges.ViewableUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && parentPrivileges.ViewableRoles != null)
					can = parentPrivileges.ViewableRoles.Intersect(this.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can download (means the user can act like a downloader/viewer)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanDownload(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			var can = (originalPrivileges == null || User.IsEmpty(originalPrivileges.DownloadableUsers, originalPrivileges.DownloadableRoles))
				&& (parentPrivileges == null || User.IsEmpty(parentPrivileges.DownloadableUsers, parentPrivileges.DownloadableRoles))
				? this.CanView(originalPrivileges, parentPrivileges)
				: false;

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.DownloadableUsers != null && !string.IsNullOrWhiteSpace(this.ID) && originalPrivileges.DownloadableUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && originalPrivileges != null && originalPrivileges.DownloadableRoles != null)
					can = originalPrivileges.DownloadableRoles.Intersect(this.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.DownloadableUsers != null && !string.IsNullOrWhiteSpace(this.ID) && parentPrivileges.DownloadableUsers.Contains(this.ID.ToLower());
				if (!can && this.Roles != null && parentPrivileges.DownloadableRoles != null)
					can = parentPrivileges.DownloadableRoles.Intersect(this.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Gets the state that determines the user can perform the action or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="action">The action to perform on the object of this service</param>
		/// <param name="privileges">The working privileges of the object (entity)</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public bool IsAuthorized(string serviceName, string objectName, Action action, Privileges privileges = null, Func<User, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
		{
			// check
			if (this.Role.Equals(SystemRole.SystemAdministrator))
				return true;

			// prepare privileges
			var workingPrivileges = this.Privileges != null && this.Privileges.Count > 0
				? this.Privileges
				: null;

			if (workingPrivileges == null)
			{
				if (getPrivileges != null)
					workingPrivileges = getPrivileges.Invoke(this, privileges);
				else
				{
					workingPrivileges = new List<Privilege>();
					if (this.CanManage(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, PrivilegeRole.Administrator.ToString()));
					else if (this.CanModerate(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, PrivilegeRole.Moderator.ToString()));
					else if (this.CanEdit(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, PrivilegeRole.Editor.ToString()));
					else if (this.CanContribute(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, PrivilegeRole.Contributor.ToString()));
					else if (this.CanView(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, PrivilegeRole.Viewer.ToString()));
				}
			}

			// prepare actions
			workingPrivileges.ForEach(privilege =>
			{
				if (privilege.Actions == null || privilege.Actions.Count < 1)
				{
					if (getActions != null)
						privilege.Actions = getActions.Invoke(privilege.Role.ToEnum<PrivilegeRole>());
				}
				else
				{
					var actions = new List<Action>();
					if (privilege.Role.Equals(PrivilegeRole.Administrator.ToString()))
						actions.Add(Action.Full);
					else if (privilege.Role.Equals(PrivilegeRole.Moderator.ToString()))
						actions = new List<Action>()
						{
							Action.CheckIn,
							Action.CheckOut,
							Action.Comment,
							Action.Vote,
							Action.Approve,
							Action.Restore,
							Action.Rollback,
							Action.Delete,
							Action.Update,
							Action.Create,
							Action.View,
							Action.Download,
						};
					else if (privilege.Role.Equals(PrivilegeRole.Editor.ToString()))
						actions = new List<Action>()
						{
							Action.CheckIn,
							Action.CheckOut,
							Action.Comment,
							Action.Vote,
							Action.Restore,
							Action.Rollback,
							Action.Delete,
							Action.Update,
							Action.Create,
							Action.View,
							Action.Download,
						};
					else if (privilege.Role.Equals(PrivilegeRole.Contributor.ToString()))
						actions = new List<Action>()
						{
							Action.CheckIn,
							Action.CheckOut,
							Action.Comment,
							Action.Vote,
							Action.Create,
							Action.View,
							Action.Download,
						};
					else
						actions = new List<Action>()
						{
							Action.View,
							Action.Download,
						};

					privilege.Actions = actions.Select(a => a.ToString()).ToList();
				}
			});

			// check permission
			var workingPrivilege = workingPrivileges.FirstOrDefault(p => serviceName.Equals(p.ServiceName) && objectName.Equals(p.ObjectName));
			return workingPrivilege != null
				? workingPrivilege.Actions.FirstOrDefault(a => a.Equals(Action.Full.ToString()) || a.Equals(action.ToString())) != null
				: false;
		}
		#endregion

		#region Helper: normalize & combine
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
		public static Privileges NormalizePrivileges(Privileges privileges)
		{
			if (privileges == null)
				return null;

			var permissions = new Privileges();

			if (User.IsEmpty(privileges.DownloadableRoles, privileges.DownloadableUsers))
				permissions.DownloadableRoles = permissions.DownloadableUsers = null;
			else
			{
				permissions.DownloadableRoles = privileges.DownloadableRoles;
				permissions.DownloadableUsers = privileges.DownloadableUsers;
			}

			if (User.IsEmpty(privileges.ViewableRoles, privileges.ViewableUsers))
				permissions.ViewableRoles = permissions.ViewableUsers = null;
			else
			{
				permissions.ViewableRoles = privileges.ViewableRoles;
				permissions.ViewableUsers = privileges.ViewableUsers;
			}

			if (User.IsEmpty(privileges.ContributiveRoles, privileges.ContributiveUsers))
				permissions.ContributiveRoles = permissions.ContributiveUsers = null;
			else
			{
				permissions.ContributiveRoles = privileges.ContributiveRoles;
				permissions.ContributiveUsers = privileges.ContributiveUsers;
			}

			if (User.IsEmpty(privileges.EditableRoles, privileges.EditableUsers))
				permissions.EditableRoles = permissions.EditableUsers = null;
			else
			{
				permissions.EditableRoles = privileges.EditableRoles;
				permissions.EditableUsers = privileges.EditableUsers;
			}

			if (User.IsEmpty(privileges.ModerateRoles, privileges.ModerateUsers))
				permissions.ModerateRoles = permissions.ModerateUsers = null;
			else
			{
				permissions.ModerateRoles = privileges.ModerateRoles;
				permissions.ModerateUsers = privileges.ModerateUsers;
			}

			if (User.IsEmpty(privileges.AdministrativeRoles, privileges.AdministrativeUsers))
				permissions.AdministrativeRoles = permissions.AdministrativeUsers = null;
			else
			{
				permissions.AdministrativeRoles = privileges.AdministrativeRoles;
				permissions.AdministrativeUsers = privileges.AdministrativeUsers;
			}

			if (User.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& User.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& User.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& User.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& User.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& User.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
		}

		/// <summary>
		/// Combines the original permissions of a business entity with parent permissions
		/// </summary>
		/// <param name="originalPrivileges"></param>
		/// <param name="parentPrivileges"></param>
		/// <returns></returns>
		public static Privileges CombinePrivileges(Privileges originalPrivileges, Privileges parentPrivileges)
		{
			if (originalPrivileges == null && parentPrivileges == null)
				return null;

			var permissions = new Privileges();

			if (originalPrivileges != null && User.IsNotEmpty(originalPrivileges.DownloadableRoles, originalPrivileges.DownloadableUsers))
			{
				permissions.DownloadableRoles = originalPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = originalPrivileges.DownloadableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.DownloadableRoles = parentPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = parentPrivileges.DownloadableUsers;
			}

			if (originalPrivileges != null && User.IsNotEmpty(originalPrivileges.ViewableRoles, originalPrivileges.ViewableUsers))
			{
				permissions.ViewableRoles = originalPrivileges.ViewableRoles;
				permissions.ViewableUsers = originalPrivileges.ViewableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ViewableRoles = parentPrivileges.ViewableRoles;
				permissions.ViewableUsers = parentPrivileges.ViewableUsers;
			}

			if (originalPrivileges != null && User.IsNotEmpty(originalPrivileges.ContributiveRoles, originalPrivileges.ContributiveUsers))
			{
				permissions.ContributiveRoles = originalPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = originalPrivileges.ContributiveUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ContributiveRoles = parentPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = parentPrivileges.ContributiveUsers;
			}

			if (originalPrivileges != null && User.IsNotEmpty(originalPrivileges.EditableRoles, originalPrivileges.EditableUsers))
			{
				permissions.EditableRoles = originalPrivileges.EditableRoles;
				permissions.EditableUsers = originalPrivileges.EditableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.EditableRoles = parentPrivileges.EditableRoles;
				permissions.EditableUsers = parentPrivileges.EditableUsers;
			}

			if (originalPrivileges != null && User.IsNotEmpty(originalPrivileges.ModerateRoles, originalPrivileges.ModerateUsers))
			{
				permissions.ModerateRoles = originalPrivileges.ModerateRoles;
				permissions.ModerateUsers = originalPrivileges.ModerateUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ModerateRoles = parentPrivileges.ModerateRoles;
				permissions.ModerateUsers = parentPrivileges.ModerateUsers;
			}

			if (originalPrivileges != null && User.IsNotEmpty(originalPrivileges.AdministrativeRoles, originalPrivileges.AdministrativeUsers))
			{
				permissions.AdministrativeRoles = originalPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = originalPrivileges.AdministrativeUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.AdministrativeRoles = parentPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = parentPrivileges.AdministrativeUsers;
			}

			if (User.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& User.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& User.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& User.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& User.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& User.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
		}
		#endregion

		#region Helper: access token
		/// <summary>
		/// Gets the access token
		/// </summary>
		/// <param name="userID"></param>
		/// <param name="userRole"></param>
		/// <param name="userRoles"></param>
		/// <param name="privileges"></param>
		/// <param name="rsaCrypto"></param>
		/// <param name="aesKey"></param>
		/// <returns></returns>
		public static string GetAccessToken(string userID, SystemRole userRole, List<string> userRoles, List<Privilege> privileges, RSACryptoServiceProvider rsaCrypto, string aesKey)
		{
			var token = new JObject()
			{
				{ "ID", userID },
				{ "Role", userRole.ToString() }
			};

			if (userRoles != null && userRoles.Count > 0)
				token.Add(new JProperty("Roles", userRoles));

			if (privileges != null && privileges.Count > 0)
				token.Add(new JProperty("Privileges", privileges));

			var key = UtilityService.GetUUID();
			token = new JObject()
			{
				{ "Key", CryptoService.RSAEncrypt(rsaCrypto, key) },
				{ "Data", token.ToString(Formatting.None).Encrypt(key) }
			};

			return token.ToString(Formatting.None).Encrypt(aesKey);
		}

		/// <summary>
		/// Gets the access token
		/// </summary>
		/// <param name="user"></param>
		/// <param name="rsaCrypto"></param>
		/// <param name="aesKey"></param>
		/// <returns></returns>
		public static string GetAccessToken(User user, RSACryptoServiceProvider rsaCrypto, string aesKey)
		{
			return User.GetAccessToken(user.ID, user.Role, user.Roles, user.Privileges, rsaCrypto, aesKey);
		}

		/// <summary>
		/// Parses the access token
		/// </summary>
		/// <param name="accessToken"></param>
		/// <param name="rsaCrypto"></param>
		/// <param name="aesKey"></param>
		/// <returns></returns>
		public static User ParseAccessToken(string accessToken, RSACryptoServiceProvider rsaCrypto, string aesKey)
		{
			// decrypt
			string decrypted = "";
			try
			{
				decrypted = accessToken.Decrypt(aesKey);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot decrypt the access token", ex);
			}

			// parse JSON
			JObject token = null;
			try
			{
				token = JObject.Parse(decrypted);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot parse the JSON", ex);
			}

			// check
			if (token["Key"] == null || token["Data"] == null)
				throw new InvalidTokenException();

			// decrypt key
			try
			{
				decrypted = CryptoService.RSADecrypt(rsaCrypto, (token["Key"] as JValue).Value.ToString());
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot decrypt the access token", ex);
			}

			// decrypt JSON
			try
			{
				decrypted = (token["Data"] as JValue).Value.ToString().Decrypt(decrypted);
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot decrypt the access token", ex);
			}

			// serialize from JSON
			try
			{
				return decrypted.FromJson<User>();
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Cannot parse the JSON", ex);
			}
		}
		#endregion

		#region Helper: JSON Web Token
		static string GetSignature(string sessionID, string accessToken, string aesKey, string algorithm = "HS512")
		{
			var data = accessToken + "@" + sessionID;
			algorithm = algorithm ?? "HS512";
			switch (algorithm.ToLower())
			{
				case "hs1":
					return data.GetHMACSHA1(aesKey, false);

				case "hs256":
					return data.GetHMACSHA256(aesKey, false);

				case "hs384":
					return data.GetHMACSHA384(aesKey, false);

				default:
					return data.GetHMACSHA512(aesKey, false);
			}
		}

		/// <summary>
		/// Gets the JSON Web Token
		/// </summary>
		/// <param name="sessionID"></param>
		/// <param name="userID"></param>
		/// <param name="accessToken"></param>
		/// <param name="aesKey"></param>
		/// <param name="signKey"></param>
		/// <param name="additional"></param>
		/// <returns></returns>
		public static string GetJSONWebToken(string sessionID, string userID, string accessToken, string aesKey, string signKey, Action<JObject> additional = null)
		{
			var payload = new JObject()
			{
				{ "iat", DateTime.Now.ToUnixTimestamp() },
				{ "jti", sessionID.Encrypt(aesKey.Reverse()) },
				{ "uid", userID },
				{ "jtk", accessToken },
				{ "jts", User.GetSignature(sessionID, accessToken, aesKey) }
			};
			additional?.Invoke(payload);
			return JSONWebToken.Encode(payload, signKey);
		}

		/// <summary>
		/// Parses the JSON Web Token (return a tuple value with first element is session identity, second element is user identity, third element is access token)
		/// </summary>
		/// <param name="jwt"></param>
		/// <param name="aesKey"></param>
		/// <param name="signKey"></param>
		/// <param name="additional"></param>
		/// <returns>The tuple with first element is session identity, second element is user identity, third element is access token</returns>
		public static Tuple<string, string, string> ParseJSONWebToken(string jwt, string aesKey, string signKey, Action<JObject> additional = null)
		{
			// parse JSON Web Token
			JObject payload = null;
			try
			{
				payload = JSONWebToken.DecodeAsJObject(jwt, signKey);
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
			var issuedAt = payload["iat"] != null
				? (payload["iat"] as JValue).Value.CastAs<long>()
				: DateTime.Now.AddMinutes(-30).ToUnixTimestamp();
			if (DateTime.Now.ToUnixTimestamp() - issuedAt > 30)
				throw new TokenExpiredException();

			// get session identity
			var sessionID = payload["jti"] != null
				? (payload["jti"] as JValue).Value as string
				: null;
			if (string.IsNullOrWhiteSpace(sessionID))
				throw new InvalidTokenException("Token is invalid (Identity is invalid)");

			try
			{
				sessionID = sessionID.Decrypt(aesKey.Reverse());
			}
			catch (Exception ex)
			{
				throw new InvalidTokenException("Token is invalid (Identity is invalid)", ex);
			}

			// get user identity
			var userID = (payload["uid"] as JValue).Value as string;
			if (userID == null)
				throw new InvalidTokenException("Token is invalid (User identity is invalid)");

			// get access token
			var accessToken = payload["jtk"] != null
				? (payload["jtk"] as JValue).Value as string
				: null;
			if (string.IsNullOrWhiteSpace(accessToken))
				throw new InvalidTokenException("Token is invalid (Access token is invalid)");

			var signature = payload["jts"] != null
				? (payload["jts"] as JValue).Value as string
				: null;
			if (string.IsNullOrWhiteSpace(signature) || !signature.Equals(User.GetSignature(sessionID, accessToken, aesKey)))
				throw new InvalidTokenSignatureException("Token is invalid (Signature is invalid)");

			// additional process
			additional?.Invoke(payload);

			// return information
			return new Tuple<string, string, string>(sessionID, userID, accessToken);
		}
		#endregion

		#region Helper: authentiate ticket
		/// <summary>
		/// Gets the authenticate ticket
		/// </summary>
		/// <param name="userID"></param>
		/// <param name="sessonID"></param>
		/// <param name="deviceID"></param>
		/// <param name="accessToken"></param>
		/// <param name="expiration"></param>
		/// <param name="persistent"></param>
		/// <returns></returns>
		public static string GetAuthenticateTicket(string userID, string sessonID, string deviceID, string accessToken, int expiration = 30, bool persistent = false)
		{
			var data = new JObject()
			{
				{ "SessionID", sessonID },
				{ "DeviceID", deviceID },
				{ "AccessToken", accessToken }
			};
			var ticket = new FormsAuthenticationTicket(1, userID, DateTime.Now, DateTime.Now.AddMinutes(expiration > 0 ? expiration : 30), persistent, data.ToString(Formatting.None));
			return FormsAuthentication.Encrypt(ticket);
		}

		/// <summary>
		/// Parses the authenticate ticket (return a tuple value with first element is user, second element is session identity, third element is device identity)
		/// </summary>
		/// <param name="ticket"></param>
		/// <param name="rsaCrypto"></param>
		/// <param name="aesKey"></param>
		/// <returns></returns>
		public static Tuple<User, string, string> ParseAuthenticateTicket(string ticket, RSACryptoServiceProvider rsaCrypto, string aesKey)
		{
			try
			{
				var authTicket = FormsAuthentication.Decrypt(ticket);
				var data = JObject.Parse(authTicket.UserData);
				var user = User.ParseAccessToken((data["AccessToken"] as JValue).Value as string, rsaCrypto, aesKey);
				if (!user.ID.Equals(authTicket.Name))
					user = new User();
				return new Tuple<User, string, string>(user, (data["SessionID"] as JValue).Value as string, (data["DeviceID"] as JValue).Value as string);
			}
			catch
			{
				return new Tuple<User, string, string>(new User(), "", "");
			}
		}
		#endregion

	}

	// -----------------------------------------------------

	/// <summary>
	/// Presents the identity of an user
	/// </summary>
	public class UserIdentity : User, IIdentity
	{
		/// <summary>
		/// Initializes an user identity
		/// </summary>
		/// <param name="user"></param>
		public UserIdentity(User user = null) : base()
		{
			if (user != null)
			{
				this.ID = user.ID;
				this.Role = user.Role;
				this.Roles = user.Roles;
				this.Privileges = user.Privileges;
			}
		}
	}

	// -----------------------------------------------------

	/// <summary>
	/// Presents a principal of an user
	/// </summary>
	public class UserPrincipal : IPrincipal
	{
		/// <summary>
		/// Initializes an user principal
		/// </summary>
		/// <param name="user"></param>
		public UserPrincipal(User user = null) : base()
		{
			this.Identity = new UserIdentity(user);
		}

		#region Properties
		/// <summary>
		/// Gets the identity of the current principal
		/// </summary>
		public IIdentity Identity { get; internal set; }

		/// <summary>
		/// Gets a value that indicates whether the user (of the current identity) has been authenticated
		/// </summary>
		public bool IsAuthenticated
		{
			get
			{
				return this.Identity != null && (this.Identity as UserIdentity).IsAuthenticated;
			}
		}
		#endregion

		#region Methods of role-based authorization
		/// <summary>
		/// Determines whether the current principal belongs to the specified role
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
		public bool IsInRole(string role)
		{
			return !string.IsNullOrWhiteSpace(role) && this.Identity != null && (this.Identity as UserIdentity).Roles.FirstOrDefault(r => r.IsEquals(role)) != null;
		}

		/// <summary>
		/// Determines an user can manage (means the user can act like an administrator)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanManage(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			return this.Identity != null && (this.Identity as UserIdentity).CanManage(originalPrivileges, parentPrivileges);
		}

		/// <summary>
		/// Determines an user can moderate (means the user can act like a moderator)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanModerate(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			return this.Identity != null && (this.Identity as UserIdentity).CanModerate(originalPrivileges, parentPrivileges);
		}

		/// <summary>
		/// Determines an user can edit (means the user can act like an editor)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanEdit(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			return this.Identity != null && (this.Identity as UserIdentity).CanEdit(originalPrivileges, parentPrivileges);
		}

		/// <summary>
		/// Determines an user can contribute (means the user can act like a contributor)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanContribute(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			return this.Identity != null && (this.Identity as UserIdentity).CanContribute(originalPrivileges, parentPrivileges);
		}

		/// <summary>
		/// Determines an user can view (means the user can act like a viewer)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanView(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			return this.Identity != null && (this.Identity as UserIdentity).CanView(originalPrivileges, parentPrivileges);
		}

		/// <summary>
		/// Determines an user can download (means the user can act like a downloader/viewer)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanDownload(Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			return this.Identity != null && (this.Identity as UserIdentity).CanDownload(originalPrivileges, parentPrivileges);
		}
		#endregion

		#region Methods of action-based authorization
		/// <summary>
		/// Gets the state that determines the user can perform the action or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="action">The action to perform on the object of this service</param>
		/// <param name="privileges">The working privileges of the object (entity)</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public bool IsAuthorized(string serviceName, string objectName, Action action, Privileges privileges = null, Func<User, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
		{
			return this.Identity != null && (this.Identity as UserIdentity).IsAuthorized(serviceName, objectName, action, privileges, getPrivileges, getActions);
		}
		#endregion

	}

}