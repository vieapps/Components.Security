#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.Claims;
using System.Xml.Serialization;
using System.Numerics;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
#endregion

#if !SIGN
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("VIEApps.Components.XUnitTests")]
#endif

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Presents information of an user in the VIEApps NGX
	/// </summary>
	public interface IUser
	{
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

		/// <summary>
		/// Determines the user is authenticated or not
		/// </summary>
		bool IsAuthenticated { get; }

		/// <summary>
		/// Determines the user is system account
		/// </summary>
		bool IsSystemAccount { get; }

		/// <summary>
		/// Determines the user is system administrator
		/// </summary>
		bool IsSystemAdministrator { get; }

		/// <summary>
		/// Determines whether this user belongs to the specified role or not
		/// </summary>
		/// <param name="role">The role need to check</param>
		/// <returns></returns>
		bool IsInRole(string role);
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
		public User()
			: this(null, null, null, null) { }

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="user">The identity of user</param>
		public User(IUser user)
			: this(user?.ID, user?.SessionID, user?.Roles, user?.Privileges, user?.AuthenticationType) { }

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

		#region Statics
		static string _SystemAccountID = null;
		static HashSet<string> _SystemAdministrators = null;

		/// <summary>
		/// Gets the identity of the system account
		/// </summary>
		internal static string SystemAccountID => User._SystemAccountID ?? (User._SystemAccountID = UtilityService.GetAppSetting("Users:SystemAccountID", "VIEAppsNGX-MMXVII-System-Account"));

		/// <summary>
		/// Gets the collection of the system administrators
		/// </summary>
		public static HashSet<string> SystemAdministrators => User._SystemAdministrators ?? (User._SystemAdministrators = UtilityService.GetAppSetting("Users:SystemAdministrators", "").ToLower().ToHashSet());

		/// <summary>
		/// Gets the default instance of an anonymous user
		/// </summary>
		/// <param name="sessionID"></param>
		/// <returns></returns>
		public static User GetDefault(string sessionID = null)
			=> new User("", sessionID ?? "", new List<string> { SystemRole.All.ToString() }, new List<Privilege>(), "APIs");
		#endregion

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

		/// <summary>
		/// Gets the authentication type
		/// </summary>
		public string AuthenticationType { get; set; } = "APIs";
		#endregion

		#region Authentication & Authorization
		/// <summary>
		/// Gets the state that determines the user is authenticated or not
		/// </summary>
		[JsonIgnore, XmlIgnore]
		public bool IsAuthenticated => !string.IsNullOrWhiteSpace(this.ID) && this.ID.IsValidUUID();

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

		/// <summary>
		/// Determines whether this user belongs to the specified role or not
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
		public bool IsInRole(string role)
			=> !string.IsNullOrWhiteSpace(role) && this.Roles != null && this.Roles.FirstOrDefault(r => r.IsEquals(role)) != null;
		#endregion

	}

	public static class UserExtentions
	{

		#region Role-based authorizations of a specified service & object
		static bool IsOn(this IUser user, string serviceName, string objectName, PrivilegeRole role)
		{
			serviceName = serviceName ?? "";
			objectName = objectName ?? "";

			var privilege = user.Privileges?.FirstOrDefault(p => p.ServiceName.IsEquals(serviceName) && p.ObjectName.IsEquals(objectName) && p.ObjectIdentity.IsEquals(""));
			if (privilege == null && !objectName.Equals(""))
				privilege = user.Privileges?.FirstOrDefault(p => p.ServiceName.IsEquals(serviceName) && p.ObjectName.IsEquals("") && p.ObjectIdentity.IsEquals(""));

			return privilege != null
				? privilege.Role.ToEnum<PrivilegeRole>().Equals(role)
				: false;
		}

		/// <summary>
		/// Determines the user is administrator or not (can manage or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <returns></returns>
		public static bool IsAdministrator(this IUser user, string serviceName, string objectName)
			=> user != null && user.IsOn(serviceName, objectName, PrivilegeRole.Administrator);

		/// <summary>
		/// Determines the user is moderator or not (can moderate or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <returns></returns>
		public static bool IsModerator(this IUser user, string serviceName, string objectName)
			=> user != null && (user.IsAdministrator(serviceName, objectName) || user.IsOn(serviceName, objectName, PrivilegeRole.Moderator));

		/// <summary>
		/// Determines the user is editor or not (can edit or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <returns></returns>
		public static bool IsEditor(this IUser user, string serviceName, string objectName)
			=> user != null && (user.IsModerator(serviceName, objectName) || user.IsOn(serviceName, objectName, PrivilegeRole.Editor));

		/// <summary>
		/// Determines the user is contributor or not (can contribute or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <returns></returns>
		public static bool IsContributor(this IUser user, string serviceName, string objectName)
			=> user != null && (user.IsEditor(serviceName, objectName) || user.IsOn(serviceName, objectName, PrivilegeRole.Contributor));

		/// <summary>
		/// Determines the user is viewer or not (can view or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <returns></returns>
		public static bool IsViewer(this IUser user, string serviceName, string objectName)
			=> user != null && (user.IsContributor(serviceName, objectName) || user.IsOn(serviceName, objectName, PrivilegeRole.Viewer));

		/// <summary>
		/// Determines the user is downloader or not (can download or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <returns></returns>
		public static bool IsDownloader(this IUser user, string serviceName, string objectName)
			=> user != null && (user.IsViewer(serviceName, objectName) || user.IsOn(serviceName, objectName, PrivilegeRole.Downloader));
		#endregion

		#region Role-based authorizations of a specified privileges
		static bool IsIn(this IUser user, HashSet<string> roles, HashSet<string> users)
			=> string.IsNullOrWhiteSpace(user.ID)
				? user.Roles == null || user.Roles.Count < 1 ? false : (roles == null || roles.Count < 1 ? false : roles.Intersect(user.Roles).Count() > 0)
				: (users == null || users.Count < 1 ? false : users.Contains(user.ID)) || (user.Roles == null || user.Roles.Count < 1 ? false : (roles == null || roles.Count < 1 ? false : roles.Intersect(user.Roles).Count() > 0));

		/// <summary>
		/// Determines the user is administrator or not (can manage or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="privileges">The privileges of the object</param>
		/// <param name="parentPrivileges">The privileges of the parent object</param>
		/// <returns></returns>
		public static bool IsAdministrator(this IUser user, Privileges privileges, Privileges parentPrivileges = null)
			=> user != null && user.IsIn(privileges?.AdministrativeRoles, privileges?.AdministrativeUsers) || user.IsIn(parentPrivileges?.AdministrativeRoles, parentPrivileges?.AdministrativeUsers);

		/// <summary>
		/// Determines the user is moderator or not (can moderate or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="privileges">The privileges of the object</param>
		/// <param name="parentPrivileges">The privileges of the parent object</param>
		/// <returns></returns>
		public static bool IsModerator(this IUser user, Privileges privileges, Privileges parentPrivileges = null)
			=> user != null && user.IsAdministrator(privileges, parentPrivileges) || user.IsIn(privileges?.ModerateRoles, privileges?.ModerateUsers) || user.IsIn(parentPrivileges?.ModerateRoles, parentPrivileges?.ModerateUsers);

		/// <summary>
		/// Determines the user is editor or not (can edit or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="privileges">The privileges of the object</param>
		/// <param name="parentPrivileges">The privileges of the parent object</param>
		/// <returns></returns>
		public static bool IsEditor(this IUser user, Privileges privileges, Privileges parentPrivileges = null)
			=> user != null && user.IsModerator(privileges, parentPrivileges) || user.IsIn(privileges?.EditableRoles, privileges?.EditableUsers) || user.IsIn(parentPrivileges?.EditableRoles, parentPrivileges?.EditableUsers);

		/// <summary>
		/// Determines the user is contributor or not (can contribute or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="privileges">The privileges of the object</param>
		/// <param name="parentPrivileges">The privileges of the parent object</param>
		/// <returns></returns>
		public static bool IsContributor(this IUser user, Privileges privileges, Privileges parentPrivileges = null)
			=> user != null && (user.IsEditor(privileges, parentPrivileges) || user.IsIn(privileges?.ContributiveRoles, privileges?.ContributiveUsers) || user.IsIn(parentPrivileges?.ContributiveRoles, parentPrivileges?.ContributiveUsers));

		/// <summary>
		/// Determines the user is viewer or not (can view or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="privileges">The privileges of the object</param>
		/// <param name="parentPrivileges">The privileges of the parent object</param>
		/// <returns></returns>
		public static bool IsViewer(this IUser user, Privileges privileges, Privileges parentPrivileges = null)
			=> user != null && (user.IsContributor(privileges, parentPrivileges) || user.IsIn(privileges?.ViewableRoles, privileges?.ViewableUsers) || user.IsIn(parentPrivileges?.ViewableRoles, parentPrivileges?.ViewableUsers));

		/// <summary>
		/// Determines the user is downloader or not (can download or not)
		/// </summary>
		/// <param name="user"></param>
		/// <param name="privileges">The privileges of the object</param>
		/// <param name="parentPrivileges">The privileges of the parent object</param>
		/// <returns></returns>
		public static bool IsDownloader(this IUser user, Privileges privileges, Privileges parentPrivileges = null)
			=> user != null
				? (privileges?.DownloadableRoles != null && privileges.DownloadableRoles.Count > 0) || (privileges?.DownloadableUsers != null && privileges.DownloadableUsers.Count > 0)
				|| (parentPrivileges?.DownloadableRoles != null && parentPrivileges.DownloadableRoles.Count > 0) || (parentPrivileges?.DownloadableUsers != null && parentPrivileges.DownloadableUsers.Count > 0)
					? user.IsIn(privileges?.DownloadableRoles, privileges?.DownloadableUsers) || user.IsIn(parentPrivileges?.DownloadableRoles, parentPrivileges?.DownloadableUsers)
					: user.IsViewer(privileges, parentPrivileges)
				: false;
		#endregion

		#region Action-based authorizations of a specified service, object & privileges
		/// <summary>
		/// Gets the highest privilege role that presents by the privileges
		/// </summary>
		/// <param name="user"></param>
		/// <param name="privileges">The working privileges</param>
		/// <returns></returns>
		public static PrivilegeRole GetPrivilegeRole(this IUser user, Privileges privileges)
		{
			if (user != null)
			{
				if (user.IsAdministrator(privileges))
					return PrivilegeRole.Administrator;

				if (user.IsModerator(privileges))
					return PrivilegeRole.Moderator;

				if (user.IsEditor(privileges))
					return PrivilegeRole.Editor;

				if (user.IsContributor(privileges))
					return PrivilegeRole.Contributor;

				if (user.IsViewer(privileges))
					return PrivilegeRole.Viewer;

				if (user.IsDownloader(privileges))
					return PrivilegeRole.Downloader;
			}
			return PrivilegeRole.None;
		}

		/// <summary>
		/// Gets the default actions of the privilege role
		/// </summary>
		/// <param name="role">The privilege role</param>
		/// <returns></returns>
		public static List<Action> GetActions(this PrivilegeRole role)
			=> role.Equals(PrivilegeRole.Administrator)
				? new List<Action>
				{
					Action.Full
				}
				: role.Equals(PrivilegeRole.Moderator)
					? new List<Action>
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
						Action.Download
					}
					: role.Equals(PrivilegeRole.Editor)
						? new List<Action>
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
							Action.Download
						}
						: role.Equals(PrivilegeRole.Contributor)
							? new List<Action>
							{
								Action.CheckIn,
								Action.CheckOut,
								Action.Comment,
								Action.Vote,
								Action.Create,
								Action.View,
								Action.Download
							}
							: role.Equals(PrivilegeRole.Viewer)
								? new List<Action>
								{
									Action.View,
									Action.Download
								}
								: role.Equals(PrivilegeRole.Downloader)
									? new List<Action>
									{
										Action.Download
									}
									: new List<Action>();

		/// <summary>
		/// Determines the user can perform the action or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="action">The action to perform on the service's object</param>
		/// <param name="getPrivileges">The function to prepare the privileges when the user got empty/null privilege</param>
		/// <param name="getActions">The function to prepare the actions when the matched privilege got empty/null action</param>
		/// <returns></returns>
		public static bool IsAuthorized(this IUser user, string serviceName, string objectName, string objectIdentity, Action action, Func<IUser, string, string, List<Privilege>> getPrivileges, Func<PrivilegeRole, List<Action>> getActions)
		{
			if (user == null)
				return false;

			serviceName = serviceName ?? "";
			objectName = objectName ?? "";
			objectIdentity = objectIdentity ?? "";

			var privileges = user.Privileges?.Where(p => p.ServiceName.IsEquals(serviceName)).ToList();
			if (privileges == null || privileges.Count < 1)
				privileges = getPrivileges?.Invoke(user, serviceName, objectName) ?? new List<Privilege>();

			var privilege = privileges.FirstOrDefault(p => p.ServiceName.IsEquals(serviceName) && p.ObjectName.IsEquals(objectName) && p.ObjectIdentity.IsEquals(objectIdentity));
			if (privilege == null && !objectName.Equals("") && objectIdentity.Equals(""))
				privilege = privileges.FirstOrDefault(p => p.ServiceName.IsEquals(serviceName) && p.ObjectName.IsEquals("") && p.ObjectIdentity.IsEquals(""));
			if (privilege == null)
				return false;

			var actions = privilege.Actions != null && privilege.Actions.Count > 0
				? privilege.Actions.Select(a => a.ToEnum<Action>()).ToList()
				: null;
			if (actions == null || actions.Count < 1)
			{
				var role = privilege.Role.ToEnum<PrivilegeRole>();
				actions = getActions?.Invoke(role) ?? role.GetActions();
			}

			var full = Action.Full.ToString();
			var act = action.ToString();
			return actions.Select(a => a.ToString()).FirstOrDefault(a => a.Equals(full) || a.Equals(act)) != null;
		}

		/// <summary>
		/// Determines the user can perform the action or not
		/// </summary>
		/// <param name="action">The action to perform on the service's object</param>
		/// <param name="privileges">The working privileges of the service's object</param>
		/// <param name="getActions">The function to prepare the actions when the matched privilege got empty/null action</param>
		/// <returns></returns>
		public static bool IsAuthorized(this IUser user, Action action, Privileges privileges, Func<PrivilegeRole, List<Action>> getActions)
		{
			if (user != null)
			{
				var role = user.GetPrivilegeRole(privileges);
				var actions = getActions?.Invoke(role) ?? role.GetActions();
				if (action.Equals(Action.Download) && !user.IsDownloader(privileges))
					actions = actions.Where(a => !a.Equals(Action.Download)).ToList();

				var full = Action.Full.ToString();
				var act = action.ToString();
				return actions.Select(a => a.ToString()).FirstOrDefault(a => a.Equals(full) || a.Equals(act)) != null;
			}
			return false;
		}

		/// <summary>
		/// Determines the user can perform the action or not
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="action">The action to perform on the service's object</param>
		/// <param name="privileges">The working privileges of the service's object</param>
		/// <param name="getPrivileges">The function to prepare the privileges when the user got empty/null privilege</param>
		/// <param name="getActions">The function to prepare the actions when the matched privilege got empty/null action</param>
		/// <returns></returns>
		public static bool IsAuthorized(this IUser user, string serviceName, string objectName, string objectIdentity, Action action, Privileges privileges, Func<IUser, string, string, List<Privilege>> getPrivileges, Func<PrivilegeRole, List<Action>> getActions)
			=> user != null && (user.IsAuthorized(serviceName, objectName, objectIdentity, action, getPrivileges, getActions) || user.IsAuthorized(action, privileges, getActions));
		#endregion

		#region Privileges
		static bool IsEmpty(HashSet<string> roles, HashSet<string> users)
			=> (roles == null || roles.Count < 1) && (users == null || users.Count < 1);

		static bool IsNotEmpty(HashSet<string> roles, HashSet<string> users)
			=> (roles != null && roles.Count > 0) || (users != null && users.Count > 0);

		/// <summary>
		/// Checks to see the privileges (access permissions) of a business entity is inherit from parent or not
		/// </summary>
		/// <param name="privileges"></param>
		/// <returns></returns>
		public static bool IsInheritFromParent(this Privileges privileges)
			=> privileges == null
				|| (IsEmpty(privileges.DownloadableRoles, privileges.DownloadableUsers)
				&& IsEmpty(privileges.ViewableRoles, privileges.ViewableUsers)
				&& IsEmpty(privileges.ContributiveRoles, privileges.ContributiveUsers)
				&& IsEmpty(privileges.EditableRoles, privileges.EditableUsers)
				&& IsEmpty(privileges.ModerateRoles, privileges.ModerateUsers)
				&& IsEmpty(privileges.AdministrativeRoles, privileges.AdministrativeUsers));

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

			if (IsEmpty(privileges.DownloadableRoles, privileges.DownloadableUsers))
				permissions.DownloadableRoles = permissions.DownloadableUsers = null;
			else
			{
				permissions.DownloadableRoles = privileges.DownloadableRoles;
				permissions.DownloadableUsers = privileges.DownloadableUsers;
			}

			if (IsEmpty(privileges.ViewableRoles, privileges.ViewableUsers))
				permissions.ViewableRoles = permissions.ViewableUsers = null;
			else
			{
				permissions.ViewableRoles = privileges.ViewableRoles;
				permissions.ViewableUsers = privileges.ViewableUsers;
			}

			if (IsEmpty(privileges.ContributiveRoles, privileges.ContributiveUsers))
				permissions.ContributiveRoles = permissions.ContributiveUsers = null;
			else
			{
				permissions.ContributiveRoles = privileges.ContributiveRoles;
				permissions.ContributiveUsers = privileges.ContributiveUsers;
			}

			if (IsEmpty(privileges.EditableRoles, privileges.EditableUsers))
				permissions.EditableRoles = permissions.EditableUsers = null;
			else
			{
				permissions.EditableRoles = privileges.EditableRoles;
				permissions.EditableUsers = privileges.EditableUsers;
			}

			if (IsEmpty(privileges.ModerateRoles, privileges.ModerateUsers))
				permissions.ModerateRoles = permissions.ModerateUsers = null;
			else
			{
				permissions.ModerateRoles = privileges.ModerateRoles;
				permissions.ModerateUsers = privileges.ModerateUsers;
			}

			if (IsEmpty(privileges.AdministrativeRoles, privileges.AdministrativeUsers))
				permissions.AdministrativeRoles = permissions.AdministrativeUsers = null;
			else
			{
				permissions.AdministrativeRoles = privileges.AdministrativeRoles;
				permissions.AdministrativeUsers = privileges.AdministrativeUsers;
			}

			if (IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
		}

		/// <summary>
		/// Combines the original permissions with parent permissions
		/// </summary>
		/// <param name="originalPrivileges"></param>
		/// <param name="parentPrivileges"></param>
		/// <returns></returns>
		public static Privileges Combine(this Privileges originalPrivileges, Privileges parentPrivileges)
		{
			if (originalPrivileges == null && parentPrivileges == null)
				return null;

			var permissions = new Privileges();

			if (originalPrivileges != null && IsNotEmpty(originalPrivileges.DownloadableRoles, originalPrivileges.DownloadableUsers))
			{
				permissions.DownloadableRoles = originalPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = originalPrivileges.DownloadableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.DownloadableRoles = parentPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = parentPrivileges.DownloadableUsers;
			}

			if (originalPrivileges != null && IsNotEmpty(originalPrivileges.ViewableRoles, originalPrivileges.ViewableUsers))
			{
				permissions.ViewableRoles = originalPrivileges.ViewableRoles;
				permissions.ViewableUsers = originalPrivileges.ViewableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ViewableRoles = parentPrivileges.ViewableRoles;
				permissions.ViewableUsers = parentPrivileges.ViewableUsers;
			}

			if (originalPrivileges != null && IsNotEmpty(originalPrivileges.ContributiveRoles, originalPrivileges.ContributiveUsers))
			{
				permissions.ContributiveRoles = originalPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = originalPrivileges.ContributiveUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ContributiveRoles = parentPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = parentPrivileges.ContributiveUsers;
			}

			if (originalPrivileges != null && IsNotEmpty(originalPrivileges.EditableRoles, originalPrivileges.EditableUsers))
			{
				permissions.EditableRoles = originalPrivileges.EditableRoles;
				permissions.EditableUsers = originalPrivileges.EditableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.EditableRoles = parentPrivileges.EditableRoles;
				permissions.EditableUsers = parentPrivileges.EditableUsers;
			}

			if (originalPrivileges != null && IsNotEmpty(originalPrivileges.ModerateRoles, originalPrivileges.ModerateUsers))
			{
				permissions.ModerateRoles = originalPrivileges.ModerateRoles;
				permissions.ModerateUsers = originalPrivileges.ModerateUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ModerateRoles = parentPrivileges.ModerateRoles;
				permissions.ModerateUsers = parentPrivileges.ModerateUsers;
			}

			if (originalPrivileges != null && IsNotEmpty(originalPrivileges.AdministrativeRoles, originalPrivileges.AdministrativeUsers))
			{
				permissions.AdministrativeRoles = originalPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = originalPrivileges.AdministrativeUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.AdministrativeRoles = parentPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = parentPrivileges.AdministrativeUsers;
			}

			if (IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
		}
		#endregion

		#region Authenticate token
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
			catch (Exception ex)
			{
				if (ex is TokenExpiredException || ex is InvalidTokenSignatureException || ex is InvalidTokenException)
					throw ex;
				else
					throw new InvalidTokenException("Invalid authenticate token", ex);
			}
		}
		#endregion

		#region Access token
		/// <summary>
		/// Gets the access token of an user that associate with a session and return a JSON Web Token
		/// </summary>
		/// <param name="userID">The string that presents the identity of the user</param>
		/// <param name="sessionID">The string that presents the identity of the associated session</param>
		/// <param name="roles">The collection that presents the roles that the user was belong to</param>
		/// <param name="privileges">The collection that presents the access privileges that the user was got</param>
		/// <param name="key">The key used to encrypt and sign</param>
		/// <param name="onPreCompleted">The action to run to modify playload (if needed) before the processing is completed</param>
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
		/// Parses the given access token and return an <see cref="User">User</see> object
		/// </summary>
		/// <param name="accessToken">The JSON Web Token that presents the access token</param>
		/// <param name="key">The key used to decrypt and verify</param>
		/// <param name="onPreCompleted">The action to run to update user information (if needed) before the processing is completed</param>
		/// <param name="hashAlgorithm">The hash algorithm used to hash and sign (md5, sha1, sha256, sha384, sha512, ripemd/ripemd160, blake128, blake/blake256, blake384, blake512)</param>
		/// <returns>The <see cref="User">User</see> object that presented by the access token</returns>
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
			catch (Exception ex)
			{
				if (ex is TokenExpiredException || ex is InvalidTokenSignatureException || ex is InvalidTokenException)
					throw ex;
				else
					throw new InvalidTokenException("Invalid access token", ex);
			}
		}
		#endregion

	}
}