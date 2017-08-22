#region Related components
using System;
using System.Collections.Generic;
#endregion

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Presents a privilege (acess permission) to perform an action on a specified object of a specified service
	/// </summary>
	[Serializable]
	public class Privilege
	{
		/// <summary>
		/// Initializes the privilege
		/// </summary>
		/// <param name="serviceName"></param>
		/// <param name="objectName"></param>
		/// <param name="role"></param>
		public Privilege(string serviceName = null, string objectName = null, string role = null)
		{
			this.ServiceName = serviceName;
			this.ObjectName = objectName;
			this.Role = role;
			this.Actions = new List<string>();
		}

		#region Properties
		/// <summary>
		/// Gets or sets the name of service
		/// </summary>
		public string ServiceName { get; set; }

		/// <summary>
		/// Gets or sets the name of service's object
		/// </summary>
		public string ObjectName { get; set; }

		/// <summary>
		/// Gets or sets the working role (must matched with <see cref="PrivilegeRole">PrivilegeRole</see>, if no role was provided then the actions are use to considering the privilege)
		/// </summary>
		public string Role { get; set; }

		/// <summary>
		/// Gets or sets the working actions can perform
		/// </summary>
		public List<string> Actions { get; set; }
		#endregion

	}

	//  --------------------------------------------------------------------------------------------

	/// <summary>
	/// Presents the privileges (access permissions) of a specified service or service's object (means access permissions of a run-time entity)
	/// </summary>
	[Serializable]
	public class Privileges
	{
		/// <summary>
		/// Initializes the privileges
		/// </summary>
		/// <param name="anonymousCanView">true to allow anonymous can view by default</param>
		public Privileges(bool anonymousCanView = false)
		{
			this.DownloadableRoles = new HashSet<string>();
			this.DownloadableUsers = new HashSet<string>();
			this.ViewableRoles = new HashSet<string>();
			this.ViewableUsers = new HashSet<string>();
			this.ContributiveRoles = new HashSet<string>();
			this.ContributiveUsers = new HashSet<string>();
			this.EditableRoles = new HashSet<string>();
			this.EditableUsers = new HashSet<string>();
			this.ModerateRoles = new HashSet<string>();
			this.ModerateUsers = new HashSet<string>();
			this.AdministrativeRoles = new HashSet<string>();
			this.AdministrativeUsers = new HashSet<string>();

			if (anonymousCanView)
				this.ViewableRoles.Add(SystemRole.All.ToString());
		}

		#region Properties
		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to download files/attachments of the published resources
		/// </summary>
		public HashSet<string> DownloadableRoles { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of users that able to download files/attachments of the published resources
		/// </summary>
		public HashSet<string> DownloadableUsers { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to view the details (means read-only on published resources)
		/// </summary>
		public HashSet<string> ViewableRoles { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of users that able to view the details (means read-only on published resources)
		/// </summary>
		public HashSet<string> ViewableUsers { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to contribute (means create new and view the published/their own resources)
		/// </summary>
		public HashSet<string> ContributiveRoles { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of users that able to contribute (means create new and view the published/their own resources)
		/// </summary>
		public HashSet<string> ContributiveUsers { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to edit (means create new and re-update the published resources)
		/// </summary>
		public HashSet<string> EditableRoles { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of users that able to edit (means create new and re-update the published resources)
		/// </summary>
		public HashSet<string> EditableUsers { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to moderate (means moderate all kinds of resources)
		/// </summary>
		public HashSet<string> ModerateRoles { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of users that able to moderate (means moderate all kinds of resources)
		/// </summary>
		public HashSet<string> ModerateUsers { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to manage (means full access)
		/// </summary>
		public HashSet<string> AdministrativeRoles { get; set; }

		/// <summary>
		/// Gets or sets the collection of identity of users that able to manage (means full access)
		/// </summary>
		public HashSet<string> AdministrativeUsers { get; set; }
		#endregion

	}

}