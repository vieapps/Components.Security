using System;
using System.Collections.Generic;

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Access permissions of a resource (means working permissions of a run-time entity)
	/// </summary>
	[Serializable]
	public class AccessPermissions
	{

		public AccessPermissions()
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

		#region Helper methods
		internal static bool IsEmpty(HashSet<string> roles, HashSet<string> users)
		{
			return (roles == null || roles.Count < 1) && (users == null || users.Count < 1);
		}

		internal static bool IsNotEmpty(HashSet<string> roles, HashSet<string> users)
		{
			return (roles != null && roles.Count > 0) || (users != null && users.Count > 0);
		}
		#endregion

	}
}