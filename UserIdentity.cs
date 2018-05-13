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
		/// <param name="userID">The identity of user</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public UserIdentity(string userID, string authenticationType = null) : this(userID, null, authenticationType) { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="userID">The identity of user</param>
		/// <param name="sessionID">The identity of working session</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public UserIdentity(string userID, string sessionID, string authenticationType = null) : this(userID, sessionID, null, null, authenticationType) { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="userID">The identity of user</param>
		/// <param name="sessionID">The identity of working session</param>
		/// <param name="roles">The working roles</param>
		/// <param name="privileges">The working privileges</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public UserIdentity(string userID, string sessionID, List<string> roles, List<Privilege> privileges, string authenticationType = null) : base(authenticationType ?? "API")
		{
			this.ID = userID;
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
			this.SessionID = this.FindFirst(ClaimTypes.Sid)?.Value;
			this.AuthenticationType = this.FindFirst(ClaimTypes.AuthenticationMethod)?.Value;

			this.SetUserData(claims?.FirstOrDefault(claim => claim.Type.Equals(ClaimTypes.UserData))?.Value);
			this.BuildClaimsOfRolesAndPrivileges();
		}

		#region Properties
		/// <summary>
		/// Gets or sets identity of user
		/// </summary>
		public string ID { get; set; }

		/// <summary>
		/// Gets or name (identity) of user
		/// </summary>
		public override string Name => this.ID;

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
		public override bool IsAuthenticated => !string.IsNullOrWhiteSpace(this.ID) && this.ID.IsValidUUID();

		static string _SystemAccountID = null;

		/// <summary>
		/// Gets the identity of the system account
		/// </summary>
		internal static string SystemAccountID => UserIdentity._SystemAccountID ?? (UserIdentity._SystemAccountID = UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account"));

		/// <summary>
		/// Gets the state that determines the user is system account
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public bool IsSystemAccount => this.IsAuthenticated ? this.ID.IsEquals(UserIdentity.SystemAccountID) : false;

		/// <summary>
		/// Gets the state that determines the user is system administrator
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public bool IsSystemAdministrator => this.IsSystemAccount || (this.IsAuthenticated && UserIdentity.SystemAdministrators.Contains(this.ID.ToLower()));

		static HashSet<string> _SystemAdministrators = null;

		/// <summary>
		/// Gets the collection of the system administrators
		/// </summary>
		public static HashSet<string> SystemAdministrators => UserIdentity._SystemAdministrators ?? (UserIdentity._SystemAdministrators = UtilityService.GetAppSetting("Users:SystemAdministrators", "").ToLower().ToHashSet());
		#endregion

		#region Authorization
		/// <summary>
		/// Determines whether this user belongs to the specified role or not
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
		public bool IsInRole(string role) => !string.IsNullOrWhiteSpace(role) && this.Roles != null && this.Roles.FirstOrDefault(r => r.IsEquals(role)) != null;

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
				var value = preset?.Value ?? this.ID;
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
			this.AddClaim(new Claim(ClaimTypes.UserData, this.GetUserData()));
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

		#region Get & Set user data
		/// <summary>
		/// Gets or sets the action to fire when system calls to get user data
		/// </summary>
		public Action<JObject, UserIdentity> OnGetUserData { get; set; }

		string GetUserData()
		{
			var userData = new JObject
			{
				{ "Roles", this.Roles.ToJArray() },
				{ "Privileges", this.Privileges.ToJArray() }
			};
			this.OnGetUserData?.Invoke(userData, this);
			return userData.ToString(Formatting.None);
		}

		/// <summary>
		/// Gets or sets the action to fire when system calls to set user data
		/// </summary>
		public Action<JObject, UserIdentity> OnSetUserData { get; set; }

		void SetUserData(string data)
		{
			try
			{
				var json = data.ToJson();
				var info = json.ToExpandoObject();
				this.Roles = info.Get<List<string>>("Roles");
				this.Privileges = info.Get<List<Privilege>>("Privileges");
				this.OnSetUserData?.Invoke(json as JObject, this);
			}
			catch { }
		}

		/// <summary>
		/// Gets the JSON
		/// </summary>
		/// <returns></returns>
		public JToken ToJson(Action<JObject> onPreCompleted = null)
		{
			var json = new JObject
			{
				{ "ID", this.ID },
				{ "SessionID", this.SessionID },
				{ "Roles", this.Roles.ToJArray() },
				{ "Privileges", this.Privileges.ToJArray() }
			};
			onPreCompleted?.Invoke(json);
			return json;
		}
		#endregion

		#region Serialization
		/// <summary>
		/// Gets or sets the action to fire when system serializes the object (creates serialization information)
		/// </summary>
		public Action<SerializationInfo, UserIdentity> OnSerialize { get; set; }

		public new void GetObjectData(SerializationInfo serializationInfo, StreamingContext context)
		{
			serializationInfo.AddValue("ID", this.ID);
			serializationInfo.AddValue("SessionID", this.SessionID);
			serializationInfo.AddValue("Label", this.Label);
			serializationInfo.AddValue("AuthenticationType", this.AuthenticationType);
			serializationInfo.AddValue("UserData", this.GetUserData());
			this.OnSerialize?.Invoke(serializationInfo, this);
		}

		/// <summary>
		/// Gets or sets the action to fire when system deserializes the object (creates new instance from serialization information)
		/// </summary>
		public Action<SerializationInfo, UserIdentity> OnDeserialize { get; set; }

		public UserIdentity(SerializationInfo serializationInfo, StreamingContext context)
		{
			this.ID = (string)serializationInfo.GetValue("ID", typeof(string));
			this.SessionID = (string)serializationInfo.GetValue("SessionID", typeof(string));
			this.Label = (string)serializationInfo.GetValue("Label", typeof(string));
			this.AuthenticationType = (string)serializationInfo.GetValue("AuthenticationType", typeof(string));
			this.SetUserData((string)serializationInfo.GetValue("UserData", typeof(string)));
			this.BuildClaims();
			this.BuildClaimsOfRolesAndPrivileges();
			this.OnDeserialize?.Invoke(serializationInfo, this);
		}
		#endregion

		#region Static helpers
		/// <summary>
		/// Normalizes the privileges (access permissions) of a business entity
		/// </summary>
		/// <param name="privileges"></param>
		/// <returns></returns>
		public static Privileges Normalize(Privileges privileges) => privileges?.Normalize();

		/// <summary>
		/// Normalizes the privileges (access permissions) of a business entity
		/// </summary>
		/// <param name="privileges"></param>
		/// <returns></returns>
		public static Privileges NormalizePrivileges(Privileges privileges) => privileges?.Normalize();

		/// <summary>
		/// Combines the original permissions of a business entity with parent permissions
		/// </summary>
		/// <param name="originalPrivileges"></param>
		/// <param name="parentPrivileges"></param>
		/// <returns></returns>
		public static Privileges Combine(Privileges originalPrivileges, Privileges parentPrivileges) => originalPrivileges?.Combine(parentPrivileges);

		/// <summary>
		/// Combines the original permissions of a business entity with parent permissions
		/// </summary>
		/// <param name="originalPrivileges"></param>
		/// <param name="parentPrivileges"></param>
		/// <returns></returns>
		public static Privileges CombinePrivileges(Privileges originalPrivileges, Privileges parentPrivileges) => originalPrivileges?.Combine(parentPrivileges);

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
			=> UserIdentityExtentions.GetAccessToken(userID, sessionID, roles, privileges, key, onPreCompleted, hashAlgorithm);

		/// <summary>
		/// Gets the access token of an user that associate with a session and return a JSON Web Token
		/// </summary>
		/// <param name="userIdentity">The user identity</param>
		/// <param name="key">The key used to encrypt and sign</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <param name="hashAlgorithm">The hash algorithm used to hash and sign (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512)</param>
		/// <returns>A JSON Web Token that presents the access token</returns>
		public static string GetAccessToken(UserIdentity userIdentity, BigInteger key, Action<JObject> onPreCompleted = null, string hashAlgorithm = "BLAKE256")
			=> userIdentity.GetAccessToken(key, onPreCompleted, hashAlgorithm);

		/// <summary>
		/// Parses the given access token and return an <see cref="UserIdentity">UserIdentity</see> object
		/// </summary>
		/// <param name="accessToken">The JSON Web Token that presents the access token</param>
		/// <param name="key">The key used to decrypt and verify</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <param name="hashAlgorithm">The hash algorithm used to hash and sign (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512)</param>
		/// <returns>The <see cref="UserIdentity">UserIdentity</see> object that presented by the access token</returns>
		public static UserIdentity ParseAccessToken(string accessToken, BigInteger key, Action<JObject, UserIdentity> onPreCompleted = null, string hashAlgorithm = "BLAKE256")
			=> accessToken.ParseAccessToken(key, onPreCompleted, hashAlgorithm);

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
			=> UserIdentityExtentions.GetAuthenticateToken(userID, sessionID, encryptionKey, signKey, onPreCompleted);

		/// <summary>
		/// Gets the authenticate token of an user and return a JSON Web Token
		/// </summary>
		/// <param name="user">The identity of an user</param>
		/// <param name="encryptionKey">The passphrase that used to encrypt data using AES</param>
		/// <param name="signKey">The passphrase that used to sign the token</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <returns>A JSON Web Token that presents the authenticate token</returns>
		public static string GetAuthenticateToken(UserIdentity user, string encryptionKey, string signKey, Action<JObject> onPreCompleted = null)
			=> user.GetAuthenticateToken(encryptionKey, signKey, onPreCompleted);

		/// <summary>
		/// Parses the given authenticate token and return an <see cref="UserIdentity">UserIdentity</see> object
		/// </summary>
		/// <param name="authenticateToken">The JSON Web Token that presents the authenticate token</param>
		/// <param name="encryptionKey">The passphrase that used to generate the encryption key for decrypting data using AES</param>
		/// <param name="shareKey">The passphrase that presents shared key for verify the token</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <returns>The <see cref="UserIdentity">UserIdentity</see> object that presented by the authenticate token</returns>
		public static UserIdentity ParseAuthenticateToken(string authenticateToken, string encryptionKey, string shareKey, Action<JObject, UserIdentity> onPreCompleted = null)
			=> authenticateToken.ParseAuthenticateToken(encryptionKey, shareKey, onPreCompleted);
		#endregion

	}
}