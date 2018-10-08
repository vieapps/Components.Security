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
	public interface IUser
	{

		#region Properties
		/// <summary>
		/// Gets or sets identity of user
		/// </summary>
		string ID { get; set; }

		/// <summary>
		/// Gets or sets identity of working session
		/// </summary>
		string SessionID { get; set; }

		/// <summary>
		/// Gets or sets the working roles (means working roles of business services and special system roles)
		/// </summary>
		List<string> Roles { get; set; }

		/// <summary>
		/// Gets or sets the working privileges (means scopes/working privileges of services/services' objects)
		/// </summary>
		List<Privilege> Privileges { get; set; }

		/// <summary>
		/// Gets the authentication type
		/// </summary>
		string AuthenticationType { get; }
		#endregion

		#region Authentication
		/// <summary>
		/// Gets the state that determines the user is authenticated or not
		/// </summary>
		bool IsAuthenticated { get; }

		/// <summary>
		/// Gets the state that determines the user is system account
		/// </summary>
		bool IsSystemAccount { get; }

		/// <summary>
		/// Gets the state that determines the user is system administrator
		/// </summary>
		bool IsSystemAdministrator { get; }
		#endregion

		#region Authorization
		/// <summary>
		/// Determines whether this user belongs to the specified role or not
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
		bool IsInRole(string role);

		/// <summary>
		/// Determines an user can manage (means the user can act like an administrator)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		bool CanManage(Privileges originalPrivileges, Privileges parentPrivileges = null);

		/// <summary>
		/// Determines an user can moderate (means the user can act like a moderator)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		bool CanModerate(Privileges originalPrivileges, Privileges parentPrivileges = null);

		/// <summary>
		/// Determines an user can edit (means the user can act like an editor)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		bool CanEdit(Privileges originalPrivileges, Privileges parentPrivileges = null);

		/// <summary>
		/// Determines an user can contribute (means the user can act like a contributor)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		bool CanContribute(Privileges originalPrivileges, Privileges parentPrivileges = null);

		/// <summary>
		/// Determines an user can view (means the user can act like a viewer)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		bool CanView(Privileges originalPrivileges, Privileges parentPrivileges = null);

		/// <summary>
		/// Determines an user can download (means the user can act like a downloader/viewer)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		bool CanDownload(Privileges originalPrivileges, Privileges parentPrivileges = null);

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
		bool IsAuthorized(string serviceName, string objectName, string objectIdentity, Action action, Privileges privileges = null, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null);
		#endregion

	}

	/// <summary>
	/// Presents an user
	/// </summary>
	[Serializable]
	public class User : IUser
	{
		/// <summary>
		/// Initializes a new instance of the User class
		/// </summary>
		public User() { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="user">The identity of user</param>
		public User(IUser user) : this(user?.ID, user?.SessionID, user?.Roles, user?.Privileges, user?.AuthenticationType) { }

		/// <summary>
		/// Initializes a new instance of the User class
		/// </summary>
		/// <param name="userID">The identity of user</param>
		/// <param name="sessionID">The identity of working session</param>
		/// <param name="roles">The working roles</param>
		/// <param name="privileges">The working privileges</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public User(string userID, string sessionID, List<string> roles, List<Privilege> privileges, string authenticationType = null)
		{
			this.ID = userID;
			this.SessionID = sessionID;
			this.Roles = roles ?? new List<string>();
			this.Privileges = privileges ?? new List<Privilege>();
			this.AuthenticationType = authenticationType ?? "APIs";
		}

		#region Properties
		/// <summary>
		/// Gets or sets identity of user
		/// </summary>
		public string ID { get; set; }

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
		public string AuthenticationType { get; set; } = "API";

		/// <summary>
		/// Gets the state that determines the user is authenticated or not
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public bool IsAuthenticated => !string.IsNullOrWhiteSpace(this.ID) && this.ID.IsValidUUID();

		static string _SystemAccountID = null;

		/// <summary>
		/// Gets the identity of the system account
		/// </summary>
		internal static string SystemAccountID => User._SystemAccountID ?? (User._SystemAccountID = UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account"));

		/// <summary>
		/// Gets the state that determines the user is system account
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public bool IsSystemAccount => this.IsAuthenticated ? this.ID.IsEquals(User.SystemAccountID) : false;

		/// <summary>
		/// Gets the state that determines the user is system administrator
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public bool IsSystemAdministrator => this.IsSystemAccount || (this.IsAuthenticated && User.SystemAdministrators.Contains(this.ID.ToLower()));

		static HashSet<string> _SystemAdministrators = null;

		/// <summary>
		/// Gets the collection of the system administrators
		/// </summary>
		public static HashSet<string> SystemAdministrators => User._SystemAdministrators ?? (User._SystemAdministrators = UtilityService.GetAppSetting("Users:SystemAdministrators", "").ToLower().ToHashSet());
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
			var can = (originalPrivileges == null || UserExtentions.IsEmpty(originalPrivileges.DownloadableUsers, originalPrivileges.DownloadableRoles))
				&& (parentPrivileges == null || UserExtentions.IsEmpty(parentPrivileges.DownloadableUsers, parentPrivileges.DownloadableRoles))
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
		public bool IsAuthorized(string serviceName, string objectName, string objectIdentity, Action action, Privileges privileges = null, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
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

	}

	public static class UserExtentions
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

			if (UserExtentions.IsEmpty(privileges.DownloadableRoles, privileges.DownloadableUsers))
				permissions.DownloadableRoles = permissions.DownloadableUsers = null;
			else
			{
				permissions.DownloadableRoles = privileges.DownloadableRoles;
				permissions.DownloadableUsers = privileges.DownloadableUsers;
			}

			if (UserExtentions.IsEmpty(privileges.ViewableRoles, privileges.ViewableUsers))
				permissions.ViewableRoles = permissions.ViewableUsers = null;
			else
			{
				permissions.ViewableRoles = privileges.ViewableRoles;
				permissions.ViewableUsers = privileges.ViewableUsers;
			}

			if (UserExtentions.IsEmpty(privileges.ContributiveRoles, privileges.ContributiveUsers))
				permissions.ContributiveRoles = permissions.ContributiveUsers = null;
			else
			{
				permissions.ContributiveRoles = privileges.ContributiveRoles;
				permissions.ContributiveUsers = privileges.ContributiveUsers;
			}

			if (UserExtentions.IsEmpty(privileges.EditableRoles, privileges.EditableUsers))
				permissions.EditableRoles = permissions.EditableUsers = null;
			else
			{
				permissions.EditableRoles = privileges.EditableRoles;
				permissions.EditableUsers = privileges.EditableUsers;
			}

			if (UserExtentions.IsEmpty(privileges.ModerateRoles, privileges.ModerateUsers))
				permissions.ModerateRoles = permissions.ModerateUsers = null;
			else
			{
				permissions.ModerateRoles = privileges.ModerateRoles;
				permissions.ModerateUsers = privileges.ModerateUsers;
			}

			if (UserExtentions.IsEmpty(privileges.AdministrativeRoles, privileges.AdministrativeUsers))
				permissions.AdministrativeRoles = permissions.AdministrativeUsers = null;
			else
			{
				permissions.AdministrativeRoles = privileges.AdministrativeRoles;
				permissions.AdministrativeUsers = privileges.AdministrativeUsers;
			}

			if (UserExtentions.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& UserExtentions.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& UserExtentions.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& UserExtentions.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& UserExtentions.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& UserExtentions.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
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

			if (originalPrivileges != null && UserExtentions.IsNotEmpty(originalPrivileges.DownloadableRoles, originalPrivileges.DownloadableUsers))
			{
				permissions.DownloadableRoles = originalPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = originalPrivileges.DownloadableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.DownloadableRoles = parentPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = parentPrivileges.DownloadableUsers;
			}

			if (originalPrivileges != null && UserExtentions.IsNotEmpty(originalPrivileges.ViewableRoles, originalPrivileges.ViewableUsers))
			{
				permissions.ViewableRoles = originalPrivileges.ViewableRoles;
				permissions.ViewableUsers = originalPrivileges.ViewableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ViewableRoles = parentPrivileges.ViewableRoles;
				permissions.ViewableUsers = parentPrivileges.ViewableUsers;
			}

			if (originalPrivileges != null && UserExtentions.IsNotEmpty(originalPrivileges.ContributiveRoles, originalPrivileges.ContributiveUsers))
			{
				permissions.ContributiveRoles = originalPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = originalPrivileges.ContributiveUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ContributiveRoles = parentPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = parentPrivileges.ContributiveUsers;
			}

			if (originalPrivileges != null && UserExtentions.IsNotEmpty(originalPrivileges.EditableRoles, originalPrivileges.EditableUsers))
			{
				permissions.EditableRoles = originalPrivileges.EditableRoles;
				permissions.EditableUsers = originalPrivileges.EditableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.EditableRoles = parentPrivileges.EditableRoles;
				permissions.EditableUsers = parentPrivileges.EditableUsers;
			}

			if (originalPrivileges != null && UserExtentions.IsNotEmpty(originalPrivileges.ModerateRoles, originalPrivileges.ModerateUsers))
			{
				permissions.ModerateRoles = originalPrivileges.ModerateRoles;
				permissions.ModerateUsers = originalPrivileges.ModerateUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ModerateRoles = parentPrivileges.ModerateRoles;
				permissions.ModerateUsers = parentPrivileges.ModerateUsers;
			}

			if (originalPrivileges != null && UserExtentions.IsNotEmpty(originalPrivileges.AdministrativeRoles, originalPrivileges.AdministrativeUsers))
			{
				permissions.AdministrativeRoles = originalPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = originalPrivileges.AdministrativeUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.AdministrativeRoles = parentPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = parentPrivileges.AdministrativeUsers;
			}

			if (UserExtentions.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& UserExtentions.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& UserExtentions.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& UserExtentions.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& UserExtentions.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& UserExtentions.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
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
				{ "jti", $"{userID}@{sessionID}".GetHMACBLAKE256(encryptionKey) },
				{ "sid", sessionID.HexToBytes().Encrypt(encryptionKey.GenerateHashKey(256), encryptionKey.GenerateHashKey(128)).ToHex() },
				{ "aud", (string.IsNullOrWhiteSpace(userID) ? UtilityService.BlankUUID : userID).GetHMACBLAKE128(signKey) },
				{ "uid", userID }
			};
			onPreCompleted?.Invoke(payload);
			return JSONWebToken.Encode(payload, signKey);
		}

		/// <summary>
		/// Gets the authenticate token of an user and return a JSON Web Token
		/// </summary>
		/// <param name="user">The identity of an user</param>
		/// <param name="encryptionKey">The passphrase that used to encrypt data using AES</param>
		/// <param name="signKey">The passphrase that used to sign and verify the token</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <returns>A JSON Web Token that presents the authenticate token</returns>
		public static string GetAuthenticateToken(this User user, string encryptionKey, string signKey, Action<JObject> onPreCompleted = null)
			=> UserExtentions.GetAuthenticateToken(user.ID, user.SessionID, encryptionKey, signKey, onPreCompleted);

		/// <summary>
		/// Parses the given authenticate token and return an <see cref="User">UserIdentity</see> object
		/// </summary>
		/// <param name="authenticateToken">The JSON Web Token that presents the authenticate token</param>
		/// <param name="encryptionKey">The passphrase that used to generate the encryption key for decrypting data using AES</param>
		/// <param name="signKey">The passphrase that used to sign and verify the token</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <returns>The <see cref="User">UserIdentity</see> object that presented by the authenticate token</returns>
		public static User ParseAuthenticateToken(this string authenticateToken, string encryptionKey, string signKey, Action<JObject, User> onPreCompleted = null)
		{
			try
			{
				// decode JSON Web Token
				var payload = JSONWebToken.DecodeAsJson(authenticateToken, signKey);
				var token = payload.ToExpandoObject();

				// issued at (expired after 60 seconds)
				var issuedAt = token.Get<long>("iat");
				if (DateTime.Now.ToUnixTimestamp() - issuedAt > 60)
					throw new TokenExpiredException();

				// identities
				var tokenID = token.Get<string>("jti");
				var userID = token.Get<string>("uid");
				var audienceID = token.Get<string>("aud");
				var sessionID = token.Get<string>("sid");

				if (string.IsNullOrWhiteSpace(tokenID) || string.IsNullOrWhiteSpace(sessionID) || string.IsNullOrWhiteSpace(audienceID) || userID == null)
					throw new InvalidTokenException("Invalid identity");

				sessionID = sessionID.HexToBytes().Decrypt(encryptionKey.GenerateHashKey(256), encryptionKey.GenerateHashKey(128)).ToHex();
				if (!tokenID.Equals($"{userID}@{sessionID}".GetHMACBLAKE256(encryptionKey)))
					throw new InvalidTokenException("Invalid identity");

				if (userID.Equals("") && !audienceID.Equals(UtilityService.BlankUUID.GetHMACBLAKE128(signKey)))
					throw new InvalidTokenException("Invalid identity");
				else if (!userID.Equals("") && !audienceID.Equals(userID.GetHMACBLAKE128(signKey)))
					throw new InvalidTokenException("Invalid identity");

				// create user identity
				var user = new User(userID, sessionID, null, null);

				// callback
				onPreCompleted?.Invoke(payload, user);

				// return user identity
				return user;
			}
			catch (TokenExpiredException)
			{
				throw;
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
				throw new InvalidTokenException("Invalid authenticate token", ex);
			}
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
				{ "jti", sessionID },
				{ "uid", userID },
				{ "rls", (roles ?? new List<string>()).Distinct(StringComparer.OrdinalIgnoreCase).ToJArray() },
				{ "pls", (privileges ?? new List<Privilege>()).ToJArray() }
			}.ToString(Formatting.None);
			var hash = token.GetHash(hashAlgorithm);
			var signature = key.Sign(hash);
			var publicKey = key.GenerateECCPublicKey();
			var payload = new JObject
			{
				{ "iat", DateTime.Now.ToUnixTimestamp() },
				{ "exp", DateTime.Now.AddDays(90).ToUnixTimestamp() },
				{ "nbf", DateTime.Now.AddDays(-60).ToUnixTimestamp() },
				{ "jti", publicKey.Encrypt(sessionID.HexToBytes()).ToHex() },
				{ "uid", userID },
				{ "atk", publicKey.Encrypt(token, true) },
				{ "ath", hash.ToHex() },
				{ "sig", ECCsecp256k1.GetSignature(signature) }
			};
			onPreCompleted?.Invoke(payload);
			return JSONWebToken.Encode(payload, ECCsecp256k1.GetPublicKey(publicKey).ToHex(), hashAlgorithm);
		}

		/// <summary>
		/// Gets the access token of an user that associate with a session and return a JSON Web Token
		/// </summary>
		/// <param name="user">The user identity</param>
		/// <param name="key">The key used to encrypt and sign</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <param name="hashAlgorithm">The hash algorithm used to hash and sign (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512)</param>
		/// <returns>A JSON Web Token that presents the access token</returns>
		public static string GetAccessToken(this User user, BigInteger key, Action<JObject> onPreCompleted = null, string hashAlgorithm = "BLAKE256")
		{
			var roles = SystemRole.All.ToString()
				+ (!user.ID.Equals("") ? "," + SystemRole.Authenticated.ToString() : "")
				+ (user.IsSystemAdministrator ? "," + SystemRole.SystemAdministrator.ToString() : "");
			return UserExtentions.GetAccessToken(user.ID, user.SessionID, (user.Roles ?? new List<string>()).Concat(roles.ToList()), user.Privileges, key, onPreCompleted, hashAlgorithm);
		}

		/// <summary>
		/// Parses the given access token and return an <see cref="User">UserIdentity</see> object
		/// </summary>
		/// <param name="accessToken">The JSON Web Token that presents the access token</param>
		/// <param name="key">The key used to decrypt and verify</param>
		/// <param name="onPreCompleted">The action to run before the processing is completed</param>
		/// <param name="hashAlgorithm">The hash algorithm used to hash and sign (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512)</param>
		/// <returns>The <see cref="User">UserIdentity</see> object that presented by the access token</returns>
		public static User ParseAccessToken(this string accessToken, BigInteger key, Action<JObject, User> onPreCompleted = null, string hashAlgorithm = "BLAKE256")
		{
			try
			{
				// decode JSON Web Token
				var publicKey = key.GenerateECCPublicKey();
				var payload = JSONWebToken.DecodeAsJson(accessToken, ECCsecp256k1.GetPublicKey(publicKey).ToHex());
				var token = payload.ToExpandoObject();

				// times
				var issuedAt = token.Get<long>("iat").FromUnixTimestamp();
				var expiresAt = token.Get<long>("exp").FromUnixTimestamp();
				var notBefore = token.Get<long>("nbf").FromUnixTimestamp();
				if (DateTime.Now > expiresAt || DateTime.Now < notBefore || issuedAt > expiresAt || issuedAt < notBefore)
					throw new TokenExpiredException();

				// identities
				var tokenID = token.Get<string>("jti");
				var userID = token.Get<string>("uid");
				if (string.IsNullOrWhiteSpace(tokenID) || string.IsNullOrWhiteSpace(userID))
					throw new InvalidTokenException("Invalid identity");
				else
					tokenID = key.Decrypt(tokenID.HexToBytes()).ToHex();

				// signature
				var hash = token.Get<string>("ath").HexToBytes();
				var signature = ECCsecp256k1.GetSignature(token.Get<string>("sig"));
				if (!publicKey.Verify(hash, signature))
					throw new InvalidTokenSignatureException();

				accessToken = key.Decrypt(token.Get<string>("atk"), true);
				if (!hash.SequenceEqual(accessToken.GetHash(hashAlgorithm)))
					throw new InvalidTokenException("Not matched");

				// info of access token
				token = accessToken.ToExpandoObject();
				if (!userID.IsEquals(token.Get<string>("uid")) || !tokenID.IsEquals(token.Get<string>("jti")))
					throw new InvalidTokenException("Invalid identity");

				var roles = token.Get<List<string>>("rls");
				var privileges = token.Get<List<Privilege>>("pls");

				// create new user identity
				var user = new User(userID, tokenID, roles, privileges);

				// callback
				onPreCompleted?.Invoke(payload, user);

				// return user identity
				return user;
			}
			catch (TokenExpiredException)
			{
				throw;
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

	}
}