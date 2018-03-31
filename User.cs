#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Xml.Serialization;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;

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
		/// <summary>
		/// Initializes the new instance of an user
		/// </summary>
		public User()
		{
			this.ID = "";
			this.Roles = new List<string>();
			this.Privileges = new List<Privilege>();
		}

		#region Properties
		/// <summary>
		/// Gets or sets the identity
		/// </summary>
		public string ID { get; set; }

		/// <summary>
		/// Gets or sets the working roles (means working roles of business services and special system roles)
		/// </summary>
		public List<string> Roles { get; set; }

		/// <summary>
		/// Gets or sets the working privileges (means scopes/working privileges of services/services' objects)
		/// </summary>
		public List<Privilege> Privileges { get; set; }
		#endregion

		#region Authentication
		/// <summary>
		/// Gets the authentication type
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public string AuthenticationType { get { return "API"; } }

		/// <summary>
		/// Gets the state that determines the user is authenticated or not
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public bool IsAuthenticated
		{
			get
			{
				return !string.IsNullOrWhiteSpace(this.ID);
			}
		}

		static string _SystemAccountID = null;

		/// <summary>
		/// Gets the identity of the system account
		/// </summary>
		internal static string SystemAccountID
		{
			get
			{
				if (string.IsNullOrWhiteSpace(User._SystemAccountID))
					User._SystemAccountID = UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account");
				return User._SystemAccountID;
			}
		}

		/// <summary>
		/// Gets the state that determines the user is system account
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public bool IsSystemAccount
		{
			get
			{
				return this.IsAuthenticated
					? this.ID.IsEquals(User.SystemAccountID)
					: false;
			}
		}

		/// <summary>
		/// Gets the state that determines the user is system administrator
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public bool IsSystemAdministrator
		{
			get
			{
				return this.IsSystemAccount || (this.IsAuthenticated && User.SystemAdministrators.Contains(this.ID.ToLower()));
			}
		}

		static HashSet<string> _SystemAdministrators = null;

		/// <summary>
		/// Gets the collection of the system administrators
		/// </summary>
		public static HashSet<string> SystemAdministrators
		{
			get
			{
				return User._SystemAdministrators ?? (User._SystemAdministrators = UtilityService.GetAppSetting("Users:SystemAdministrators", "").ToLower().ToHashSet());
			}
		}
		#endregion

		#region Authorization
		/// <summary>
		/// Determines whether this user belongs to the specified role or not
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
		public bool IsInRole(string role)
		{
			return !string.IsNullOrWhiteSpace(role) && this.Roles != null && this.Roles.FirstOrDefault(r => r.IsEquals(role)) != null;
		}

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
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="action">The action to perform on the object of this service</param>
		/// <param name="privileges">The working privileges of the object (entity)</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public bool IsAuthorized(string serviceName, string objectName, string objectIdentity, Action action, Privileges privileges = null, Func<User, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
		{
			// prepare privileges
			var workingPrivileges = this.Privileges != null && this.Privileges.Count > 0 && this.Privileges.FirstOrDefault(p => p.ServiceName.IsEquals(serviceName) && p.ObjectName.IsEquals(objectName) && p.ObjectIdentity.IsEquals(objectIdentity)) != null
				? this.Privileges
				: null;
			if (workingPrivileges == null)
			{
				workingPrivileges = getPrivileges?.Invoke(this, privileges);
				if (getPrivileges == null)
				{
					workingPrivileges = new List<Privilege>();
					if (this.CanManage(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, objectIdentity, PrivilegeRole.Administrator.ToString()));
					else if (this.CanModerate(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, objectIdentity, PrivilegeRole.Moderator.ToString()));
					else if (this.CanEdit(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, objectIdentity, PrivilegeRole.Editor.ToString()));
					else if (this.CanContribute(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, objectIdentity, PrivilegeRole.Contributor.ToString()));
					else if (this.CanView(privileges))
						workingPrivileges.Add(new Privilege(serviceName, objectName, objectIdentity, PrivilegeRole.Viewer.ToString()));
				}
			}

			// prepare actions
			workingPrivileges.Where(privilege => privilege.Actions == null || privilege.Actions.Count < 1).ForEach(p =>
			{
				if (getActions != null)
					try
					{
						if (!Enum.TryParse(p.Role, out PrivilegeRole role))
							role = PrivilegeRole.Viewer;
						p.Actions = getActions(role);
					}
					catch { }

				if (p.Actions == null || p.Actions.Count < 1)
				{
					var actions = new List<Action>();
					if (p.Role.Equals(PrivilegeRole.Administrator.ToString()))
						actions.Add(Action.Full);

					else if (p.Role.Equals(PrivilegeRole.Moderator.ToString()))
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

					else if (p.Role.Equals(PrivilegeRole.Editor.ToString()))
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

					else if (p.Role.Equals(PrivilegeRole.Contributor.ToString()))
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

					p.Actions = actions.Select(a => a.ToString()).ToList();
				}
			});

			// get the first matched privilege
			var workingPrivilege = workingPrivileges.FirstOrDefault(p =>
			{
				return p.ServiceName.IsEquals(serviceName)
					&& p.ObjectName.IsEquals(string.IsNullOrWhiteSpace(objectName) ? "" : objectName)
					&& p.ObjectIdentity.IsEquals(string.IsNullOrWhiteSpace(objectIdentity) ? "" : objectIdentity);
			});

			// return the state that determine user has action or not
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
		/// <param name="id">The string that presents the identity of the user</param>
		/// <param name="roles">The collection that presents the roles that the user was belong to</param>
		/// <param name="privileges">The collection that presents the access privileges that the user was got</param>
		/// <param name="rsaCrypto"></param>
		/// <param name="aesKey"></param>
		/// <returns></returns>
		public static string GetAccessToken(string id, IEnumerable<string> roles, IEnumerable<Privilege> privileges, RSACryptoServiceProvider rsaCrypto, string aesKey)
		{
			var token = new JObject()
			{
				{ "ID", id },
				{ "Roles", (roles ?? new List<string>()).Distinct().ToJArray() },
				{ "Privileges", (privileges ?? new List<Privilege>()).ToJArray() }
			};

			var key = UtilityService.NewUUID;
			token = new JObject()
			{
				{ "Key", rsaCrypto.Encrypt(key) },
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
			var roles = SystemRole.All.ToString()
				+ (!user.ID.Equals("") ? "," + SystemRole.Authenticated.ToString() : "")
				+ (user.IsSystemAdministrator ? "," + SystemRole.SystemAdministrator.ToString() : "");
			return User.GetAccessToken(user.ID, (user.Roles ?? new List<string>()).Concat(roles.ToList()), user.Privileges, rsaCrypto, aesKey);
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
				decrypted = rsaCrypto.Decrypt((token["Key"] as JValue).Value.ToString());
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
		/// <param name="userID"></param>
		/// <param name="accessToken"></param>
		/// <param name="sessionID"></param>
		/// <param name="aesKey"></param>
		/// <param name="jwtKey"></param>
		/// <param name="onPreCompleted"></param>
		/// <returns></returns>
		public static string GetJSONWebToken(string userID, string accessToken, string sessionID, string aesKey, string jwtKey, Action<JObject> onPreCompleted = null)
		{
			var payload = new JObject()
			{
				{ "iat", DateTime.Now.ToUnixTimestamp() },
				{ "jti", sessionID.Encrypt(aesKey.Reverse()) },
				{ "uid", userID },
				{ "jtk", accessToken },
				{ "jts", User.GetSignature(sessionID, accessToken, aesKey) }
			};

			onPreCompleted?.Invoke(payload);
			return JSONWebToken.Encode(payload, jwtKey);
		}

		/// <summary>
		/// Parses the JSON Web Token (return a tuple value with first element is user identity, second element is access token, and last element is session identity)
		/// </summary>
		/// <param name="token"></param>
		/// <param name="aesKey"></param>
		/// <param name="jwtKey"></param>
		/// <param name="onPreCompleted"></param>
		/// <returns>The tuple with first element is session identity, second element is user identity, third element is access token</returns>
		public static Tuple<string, string, string> ParseJSONWebToken(string token, string aesKey, string jwtKey, Action<JObject> onPreCompleted = null)
		{
			// parse JSON Web Token
			JObject payload = null;
			try
			{
				payload = JSONWebToken.DecodeAsJObject(token, jwtKey);
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

			// return
			onPreCompleted?.Invoke(payload);
			return new Tuple<string, string, string>(userID, accessToken, sessionID);
		}
		#endregion

		#region Helper: passport token
		/// <summary>
		/// Gets the passport token
		/// </summary>
		/// <param name="userID"></param>
		/// <param name="authenticateTicket"></param>
		/// <param name="sessionID"></param>
		/// <param name="deviceID"></param>
		/// <param name="aesKey"></param>
		/// <param name="jwtKey"></param>
		/// <returns></returns>
		public static string GetPassportToken(string userID, string authenticateTicket, string sessionID, string deviceID, string aesKey, string jwtKey)
		{
			return User.GetJSONWebToken(userID, authenticateTicket, sessionID, aesKey, jwtKey, payload => payload.Add(new JProperty("did", deviceID)));
		}

		/// <summary>
		/// Parses the passport token (return a tuple value with first element is user identity, second element is authenticate ticket/access token, third element is session identity, and last element is device identity)
		/// </summary>
		/// <param name="token"></param>
		/// <param name="aesKey"></param>
		/// <param name="jwtKey"></param>
		/// <returns></returns>
		public static Tuple<string, string, string, string> ParsePassportToken(string token, string aesKey, string jwtKey)
		{
			var deviceID = "";
			var info = User.ParseJSONWebToken(token, aesKey, jwtKey, payload => deviceID = payload["did"] != null ? (payload["did"] as JValue).Value as string : null);
			var userID = info.Item1;
			var accessToken = info.Item2;
			var sessionID = info.Item3;
			return new Tuple<string, string, string, string>(userID, accessToken, sessionID, deviceID);
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
				this.Roles = user.Roles;
				this.Privileges = user.Privileges;
			}
		}

		public string Name { get { return this.ID; } }
	}

	// -----------------------------------------------------

	/// <summary>
	/// Presents a principal of an user
	/// </summary>
	public class UserPrincipal : IPrincipal
	{
		/// <summary>
		/// Initializes the new instance of an user principal
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

		/// <summary>
		/// Determines whether the current principal is system administrator or not
		/// </summary>
		public bool IsSystemAdministrator
		{
			get
			{
				return this.Identity != null && (this.Identity as UserIdentity).IsSystemAdministrator;
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
			return this.Identity != null && (this.Identity as UserIdentity).IsInRole(role);
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
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="action">The action to perform on the object of this service</param>
		/// <param name="privileges">The working privileges of the object (entity)</param>
		/// <param name="getPrivileges">The function to prepare the collection of privileges</param>
		/// <param name="getActions">The function to prepare the actions of each privilege</param>
		/// <returns></returns>
		public bool IsAuthorized(string serviceName, string objectName, string objectIdentity, Action action, Privileges privileges = null, Func<User, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
		{
			return this.Identity != null && (this.Identity as UserIdentity).IsAuthorized(serviceName, objectName, objectIdentity, action, privileges, getPrivileges, getActions);
		}
		#endregion

	}

}