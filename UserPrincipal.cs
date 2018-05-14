#region Related components
using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.Claims;
#endregion

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Presents a principal of an user
	/// </summary>
	public class UserPrincipal : ClaimsPrincipal
	{
		/// <summary>
		/// Initializes the new instance of an user principal from the specified identity
		/// </summary>
		public UserPrincipal() : this(new UserIdentity()) { }

		/// <summary>
		/// Initializes the new instance of an user principal from the specified identity
		/// </summary>
		/// <param name="user">The identity from which to initialize the new principal</param>
		public UserPrincipal(IUser user) : this(new UserIdentity(user)) { }

		/// <summary>
		/// Initializes the new instance of an user principal from the specified identity
		/// </summary>
		/// <param name="identity">The identity from which to initialize the new principal</param>
		public UserPrincipal(UserIdentity identity) : base(identity)
		{
			this.Identity = identity ?? new UserIdentity();
		}

		/// <summary>
		/// Initializes the new instance of an user principal
		/// </summary>
		/// <param name="principal">The principal from which to initialize the new principal</param>
		public UserPrincipal(ClaimsPrincipal principal) : base(principal)
		{
			this.Identity = new UserIdentity(principal);
		}

		/// <summary>
		/// Gets the current principal
		/// </summary>
		public static new UserPrincipal Current => new UserPrincipal(ClaimsPrincipal.Current);

		#region Properties
		/// <summary>
		/// Gets the identity that associated with this principal
		/// </summary>
		public override IIdentity Identity { get; }

		/// <summary>
		/// Gets a value that indicates whether the user (of the current identity) has been authenticated
		/// </summary>
		public bool IsAuthenticated => this.Identity != null && (this.Identity as UserIdentity).IsAuthenticated;

		/// <summary>
		/// Determines whether the current principal is system administrator or not
		/// </summary>
		public bool IsSystemAdministrator => this.Identity != null && (this.Identity as UserIdentity).IsSystemAdministrator;
		#endregion

		#region Methods of role-based authorization
		/// <summary>
		/// Determines whether the current principal belongs to the specified role
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
		public override bool IsInRole(string role)
			=> this.Identity != null && (this.Identity as UserIdentity).IsInRole(role);

		/// <summary>
		/// Determines an user can manage (means the user can act like an administrator)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanManage(Privileges originalPrivileges, Privileges parentPrivileges = null)
			=> this.Identity != null && (this.Identity as UserIdentity).CanManage(originalPrivileges, parentPrivileges);

		/// <summary>
		/// Determines an user can moderate (means the user can act like a moderator)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanModerate(Privileges originalPrivileges, Privileges parentPrivileges = null)
			=> this.Identity != null && (this.Identity as UserIdentity).CanModerate(originalPrivileges, parentPrivileges);

		/// <summary>
		/// Determines an user can edit (means the user can act like an editor)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanEdit(Privileges originalPrivileges, Privileges parentPrivileges = null)
			=> this.Identity != null && (this.Identity as UserIdentity).CanEdit(originalPrivileges, parentPrivileges);

		/// <summary>
		/// Determines an user can contribute (means the user can act like a contributor)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanContribute(Privileges originalPrivileges, Privileges parentPrivileges = null)
			=> this.Identity != null && (this.Identity as UserIdentity).CanContribute(originalPrivileges, parentPrivileges);

		/// <summary>
		/// Determines an user can view (means the user can act like a viewer)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanView(Privileges originalPrivileges, Privileges parentPrivileges = null)
			=> this.Identity != null && (this.Identity as UserIdentity).CanView(originalPrivileges, parentPrivileges);

		/// <summary>
		/// Determines an user can download (means the user can act like a downloader/viewer)
		/// </summary>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public bool CanDownload(Privileges originalPrivileges, Privileges parentPrivileges = null)
			=> this.Identity != null && (this.Identity as UserIdentity).CanDownload(originalPrivileges, parentPrivileges);
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
		public bool IsAuthorized(string serviceName, string objectName, string objectIdentity, Action action, Privileges privileges = null, Func<IUser, Privileges, List<Privilege>> getPrivileges = null, Func<PrivilegeRole, List<string>> getActions = null)
			=> this.Identity != null && (this.Identity as UserIdentity).IsAuthorized(serviceName, objectName, objectIdentity, action, privileges, getPrivileges, getActions);
		#endregion

	}
}