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
	/// <summary>
	/// Presents the identity of an user
	/// </summary>
	[Serializable]
	public class UserIdentity : ClaimsIdentity, ISerializable
	{
		/// <summary>
		/// Initializes a new instance of the UserIdentity class with the specified authentication type
		/// </summary>
		public UserIdentity() : base() { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="name">The name (for displaying) of user</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public UserIdentity(string name, string authenticationType = null) : this(null, name, authenticationType) { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="id">The identity of user</param>
		/// <param name="name">The name (for displaying) of user</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public UserIdentity(string id, string name, string authenticationType = null) : this(id, name, null, authenticationType) { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="id">The identity of user</param>
		/// <param name="name">The name (for displaying) of user</param>
		/// <param name="sessionID">The identity of working session</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public UserIdentity(string id, string name, string sessionID, string authenticationType = null) : this(id, name, sessionID, null, null, authenticationType) { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="id">The identity of user</param>
		/// <param name="name">The name (for displaying) of user</param>
		/// <param name="sessionID">The identity of working session</param>
		/// <param name="roles">The working roles</param>
		/// <param name="privileges">The working privileges</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public UserIdentity(string id, string name, string sessionID, List<string> roles, List<Privilege> privileges, string authenticationType = null) : base(authenticationType ?? "API")
		{
			this.ID = id;
			this.Name = name;
			this.SessionID = sessionID;
			this.AuthenticationType = authenticationType ?? "API";
			this.Roles = roles ?? new List<string>();
			this.Privileges = privileges ?? new List<Privilege>();
			this.BuildClaims();
			this.BuildClaimsOfRolesAndPrivileges();
		}

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with an associated principal
		/// </summary>
		/// <param name="principal">The user principal</param>
		public UserIdentity(ClaimsPrincipal principal) : this(principal?.Claims) { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with an associated identity
		/// </summary>
		/// <param name="identity">The user identity</param>
		public UserIdentity(ClaimsIdentity identity) : this(identity?.Claims) { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with preset claims
		/// </summary>
		/// <param name="claims">The claims of user</param>
		public UserIdentity(IEnumerable<Claim> claims)
		{
			this.BuildClaims(claims);

			this.ID = this.FindFirst(ClaimTypes.NameIdentifier)?.Value;
			this.Name = this.FindFirst(ClaimTypes.Name)?.Value;
			this.SessionID = this.FindFirst(ClaimTypes.Sid)?.Value;
			this.AuthenticationType = this.FindFirst(ClaimTypes.AuthenticationMethod)?.Value;

			this.SetAuthorizationInfo(claims?.FirstOrDefault(claim => claim.Type.Equals(ClaimTypes.UserData))?.Value);
			this.BuildClaimsOfRolesAndPrivileges();
		}

		#region Properties
		/// <summary>
		/// Gets or sets identity of user
		/// </summary>
		public string ID { get; set; }

		/// <summary>
		/// Gets or sets name of user
		/// </summary>
		public override string Name { get; }

		/// <summary>
		/// Gets or sets identity of working session
		/// </summary>
		public string SessionID { get; set; }

		/// <summary>
		/// Gets or sets the working roles (means working roles of business services and special system roles)
		/// </summary>
		public List<string> Roles { get; set; } = new List<string>();

		/// <summary>
		/// Gets or sets the working privileges (means scopes/working privileges of services/services' objects)
		/// </summary>
		public List<Privilege> Privileges { get; set; } = new List<Privilege>();
		#endregion

		#region Authentication
		/// <summary>
		/// Gets the authentication type
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public override string AuthenticationType { get; }

		/// <summary>
		/// Gets the state that determines the user is authenticated or not
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public override bool IsAuthenticated
		{
			get
			{
				return !string.IsNullOrWhiteSpace(this.ID) && this.ID.IsValidUUID();
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
				if (string.IsNullOrWhiteSpace(UserIdentity._SystemAccountID))
					UserIdentity._SystemAccountID = UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account");
				return UserIdentity._SystemAccountID;
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
					? this.ID.IsEquals(UserIdentity.SystemAccountID)
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
				return this.IsSystemAccount || (this.IsAuthenticated && UserIdentity.SystemAdministrators.Contains(this.ID.ToLower()));
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
				return UserIdentity._SystemAdministrators ?? (UserIdentity._SystemAdministrators = UtilityService.GetAppSetting("Users:SystemAdministrators", "").ToLower().ToHashSet());
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
			var can = (originalPrivileges == null || UserIdentityExtentions.IsEmpty(originalPrivileges.DownloadableUsers, originalPrivileges.DownloadableRoles))
				&& (parentPrivileges == null || UserIdentityExtentions.IsEmpty(parentPrivileges.DownloadableUsers, parentPrivileges.DownloadableRoles))
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
		public bool IsAuthorized(string serviceName, string objectName, string objectIdentity, Action action, Privileges privileges = null, Func<UserIdentity, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
		{
			// prepare privileges
			var workingPrivileges = this.Privileges != null && this.Privileges.Count > 0 && this.Privileges.FirstOrDefault(p => p.ServiceName.IsEquals(serviceName) && p.ObjectName.IsEquals(objectName) && p.ObjectIdentity.IsEquals(objectIdentity)) != null
				? this.Privileges
				: null;
			if (workingPrivileges == null)
			{
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
				else
					workingPrivileges = getPrivileges(this, privileges);
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

		#region Working with claims
		/// <summary>
		/// Builds the collection of claims (except roles and privileges)
		/// </summary>
		/// <param name="claims"></param>
		public void BuildClaims(IEnumerable<Claim> claims = null)
		{
			if (this.FindFirst(ClaimTypes.NameIdentifier) == null)
			{
				var preset = claims?.FirstOrDefault(claim => claim.Type.Equals(ClaimTypes.NameIdentifier));
				var value = preset?.Value ?? this.ID;
				if (!string.IsNullOrWhiteSpace(value))
					this.AddClaim(new Claim(ClaimTypes.NameIdentifier, value));
			}

			if (this.FindFirst(ClaimTypes.Name) == null)
			{
				var preset = claims?.FirstOrDefault(claim => claim.Type.Equals(ClaimTypes.Name));
				var value = preset?.Value ?? this.Name;
				if (!string.IsNullOrWhiteSpace(value))
					this.AddClaim(new Claim(ClaimTypes.Name, value));
			}

			if (this.FindFirst(ClaimTypes.AuthenticationMethod) == null)
			{
				var preset = claims?.FirstOrDefault(claim => claim.Type.Equals(ClaimTypes.AuthenticationMethod));
				var value = preset?.Value ?? this.AuthenticationType;
				if (!string.IsNullOrWhiteSpace(value))
					this.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, value));
			}

			if (this.FindFirst(ClaimTypes.Sid) == null)
			{
				var preset = claims?.FirstOrDefault(claim => claim.Type.Equals(ClaimTypes.Sid));
				var value = preset?.Value ?? this.SessionID;
				if (!string.IsNullOrWhiteSpace(value))
					this.AddClaim(new Claim(ClaimTypes.Sid, value));
			}
		}

		/// <summary>
		/// Builds the claim of roles and privileges (UserData)
		/// </summary>
		public void BuildClaimsOfRolesAndPrivileges()
		{
			var claim = this.FindFirst(ClaimTypes.UserData);
			if (claim != null)
				this.RemoveClaim(claim);
			this.AddClaim(new Claim(ClaimTypes.UserData, this.GetAuthorizationInfo()));
		}

		/// <summary>
		/// Rebuilds all claims
		/// </summary>
		public void RebuildClaims()
		{
			this.Claims.ToList().ForEach(claim => this.RemoveClaim(claim));
			this.BuildClaims();
			this.BuildClaimsOfRolesAndPrivileges();
		}
		#endregion

		#region Serialization
		void SetAuthorizationInfo(string data)
		{
			if (!string.IsNullOrWhiteSpace(data))
				try
				{
					var info = data.ToExpandoObject();
					this.Roles = info.Get<List<string>>("Roles");
					this.Privileges = info.Get<List<Privilege>>("Privileges");
				}
				catch { }
		}

		string GetAuthorizationInfo()
		{
			return new JObject
			{
				{ "Roles", this.Roles.ToJson() },
				{ "Privileges", this.Privileges.ToJson() }
			}.ToString(Formatting.None);
		}

		public new void GetObjectData(SerializationInfo serializationInfo, StreamingContext context)
		{
			base.GetObjectData(serializationInfo, context);
			serializationInfo.AddValue("ID", this.ID);
			serializationInfo.AddValue("Name", this.Name);
			serializationInfo.AddValue("SessionID", this.SessionID);
			serializationInfo.AddValue("AuthorizationInfo", this.GetAuthorizationInfo());
			serializationInfo.AddValue("Label", this.Label);
			serializationInfo.AddValue("AuthenticationType", this.AuthenticationType);
		}

		public UserIdentity(SerializationInfo serializationInfo, StreamingContext context) : base(serializationInfo, context)
		{
			this.ID = (string)serializationInfo.GetValue("ID", typeof(string));
			this.Name = (string)serializationInfo.GetValue("Name", typeof(string));
			this.SessionID = (string)serializationInfo.GetValue("SessionID", typeof(string));
			this.SetAuthorizationInfo((string)serializationInfo.GetValue("AuthorizationInfo", typeof(string)));
			this.Label = (string)serializationInfo.GetValue("Label", typeof(string));
			this.AuthenticationType = (string)serializationInfo.GetValue("AuthenticationType", typeof(string));
			this.BuildClaims();
			this.BuildClaimsOfRolesAndPrivileges();
		}
		#endregion

		#region Helper: normalize & combine privileges
		/// <summary>
		/// Normalizes the privileges (access permissions) of a business entity
		/// </summary>
		/// <param name="privileges"></param>
		/// <returns></returns>
		public static Privileges Normalize(Privileges privileges)
		{
			return privileges?.Normalize();
		}

		/// <summary>
		/// Normalizes the privileges (access permissions) of a business entity
		/// </summary>
		/// <param name="privileges"></param>
		/// <returns></returns>
		public static Privileges NormalizePrivileges(Privileges privileges)
		{
			return privileges?.Normalize();
		}

		/// <summary>
		/// Combines the original permissions of a business entity with parent permissions
		/// </summary>
		/// <param name="originalPrivileges"></param>
		/// <param name="parentPrivileges"></param>
		/// <returns></returns>
		public static Privileges Combine(Privileges originalPrivileges, Privileges parentPrivileges)
		{
			return originalPrivileges?.Combine(parentPrivileges);
		}

		/// <summary>
		/// Combines the original permissions of a business entity with parent permissions
		/// </summary>
		/// <param name="originalPrivileges"></param>
		/// <param name="parentPrivileges"></param>
		/// <returns></returns>
		public static Privileges CombinePrivileges(Privileges originalPrivileges, Privileges parentPrivileges)
		{
			return originalPrivileges?.Combine(parentPrivileges);
		}
		#endregion

		#region Helper: working with access token
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
			return UserIdentityExtentions.GetAccessToken(userID, sessionID, roles, privileges, eccKey);
		}

		/// <summary>
		/// Gets the access token
		/// </summary>
		/// <param name="userIdentity">The user identity</param>
		/// <param name="eccKey">The key for verifying and decrypting using ECCsecp256k1</param>
		/// <returns>The string that presennts the encrypted access token</returns>
		public static string GetAccessToken(UserIdentity userIdentity, BigInteger eccKey)
		{
			return userIdentity.GetAccessToken(eccKey);
		}

		/// <summary>
		/// Parses the access token to get <see cref="UserIdentity">UserIdentity</see> object
		/// </summary>
		/// <param name="accessToken">The string that presennts the encrypted access token</param>
		/// <param name="eccKey">The key for verifying and decrypting using ECCsecp256k1</param>
		/// <param name="getUserName">The function to get name of user</param>
		/// <returns>The <see cref="UserIdentity">UserIdentity</see> object that presented by the access token</returns>
		public static UserIdentity ParseAccessToken(string accessToken, BigInteger eccKey, Func<string, string> getUserName = null)
		{
			return accessToken.ParseAccessToken(eccKey, getUserName);
		}
		#endregion

		#region Helper: working with JSON Web Token
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
			return UserIdentityExtentions.GetJSONWebToken(userID, sessionID, encryptionKey, shareKey, onPreCompleted);
		}

		/// <summary>
		/// Parses the JSON Web Token (return a tuple value with first element is user identity, second is session identity)
		/// </summary>
		/// <param name="jwtoken">The string that presents a JSON Web Token</param>
		/// <param name="encryptionKey">The passphrase that used to generate the encryption key for decrypting data using AES</param>
		/// <param name="shareKey">The passphrase that presents shared key for verify the token</param>
		/// <param name="onPreCompleted">The action to run before the parsing process is compeleted</param>
		/// <returns>The tuple with first element is user identity, second is session identity</returns>
		public static Tuple<string, string> ParseJSONWebToken(string jwtoken, string encryptionKey, string shareKey, Action<ExpandoObject> onPreCompleted = null)
		{
			return jwtoken.ParseJSONWebToken(encryptionKey, shareKey, onPreCompleted);
		}
		#endregion

		#region Helper: working with passport token
		/// <summary>
		/// Gets the passport token
		/// </summary>
		/// <param name="userIdentity">The user identity</param>
		/// <param name="deviceID">The string that presents identity of working device that associated with user</param>
		/// <param name="encryptionKey">The passphrase that used to generate the encryption key for encrypting data using AES</param>
		/// <param name="shareKey">The passphrase that presents shared key for signing the token</param>
		/// <param name="eccKey">The key for encrypting and signing using ECCsecp256k1</param>
		/// <returns>The string that presents a JSON Web Token</returns>
		public static string GetPassportToken(UserIdentity userIdentity, string deviceID, string encryptionKey, string shareKey, BigInteger eccKey)
		{
			return userIdentity.GetPassportToken(deviceID, encryptionKey, shareKey, eccKey);
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
		public static Tuple<UserIdentity, string> ParsePassportToken(string jwtoken, string encryptionKey, string shareKey, BigInteger eccKey, Func<string, string> getUserName = null)
		{
			return jwtoken.ParsePassportToken(encryptionKey, shareKey, eccKey, getUserName);
		}
		#endregion

	}
}