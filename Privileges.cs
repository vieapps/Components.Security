#region Related components
using System;
using System.Linq;
using System.Dynamic;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Presents a privilege to perform an action on a specified object of a specified service
	/// </summary>
	[Serializable]
	public class Privilege
	{
		/// <summary>
		/// Initializes the privilege
		/// </summary>
		public Privilege()
			: this(null, null, null) { }

		/// <summary>
		/// Initializes the privilege
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="role">The privilege role (must matched with <see cref="PrivilegeRole">PrivilegeRole</see> enum)</param>
		public Privilege(string serviceName, string objectName, string role)
			: this(serviceName, objectName, null, role) { }

		/// <summary>
		/// Initializes the privilege
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="role">The privilege role (must matched with <see cref="PrivilegeRole">PrivilegeRole</see> enum)</param>
		public Privilege(string serviceName, string objectName, string objectIdentity, string role)
			: this(serviceName, objectName, objectIdentity, PrivilegeRole.Viewer)
			=> this.Role = Enum.TryParse(role, out PrivilegeRole privilegeRole)
				? privilegeRole.ToString()
				: PrivilegeRole.Viewer.ToString();

		/// <summary>
		/// Initializes the privilege
		/// </summary>
		/// <param name="serviceName">The name of the service</param>
		/// <param name="objectName">The name of the service's object</param>
		/// <param name="objectIdentity">The identity of the service's object</param>
		/// <param name="role">The privilege role</param>
		public Privilege(string serviceName, string objectName, string objectIdentity, PrivilegeRole role)
		{
			this.ServiceName = serviceName ?? "";
			this.ObjectName = objectName ?? "";
			this.ObjectIdentity = objectIdentity ?? "";
			this.Role = role.ToString();
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
		/// Gets or sets the identity of service's object
		/// </summary>
		public string ObjectIdentity { get; set; }

		/// <summary>
		/// Gets or sets the working role (must matched with <see cref="PrivilegeRole">PrivilegeRole</see>, if no role was provided then the actions are use to considering the privilege)
		/// </summary>
		public string Role { get; set; }

		/// <summary>
		/// Gets or sets the working actions can perform
		/// </summary>
		public List<string> Actions { get; set; }
		#endregion

		/// <summary>
		/// Gets the JSON of this privilege object
		/// </summary>
		/// <returns></returns>
		public JObject ToJson()
			=> new JObject
			{
				{ "ServiceName", (this.ServiceName ?? "").Trim().ToLower() },
				{ "ObjectName", (this.ObjectName ?? "").Trim().ToLower() },
				{ "ObjectIdentity", (this.ObjectIdentity ?? "").Trim().ToLower() },
				{ "Role", (this.Role ?? "").Trim() },
				{ "Actions", (this.Actions ?? new List<string>()).ToJArray() }
			};
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
		public Privileges()
			: this(false) { }

		/// <summary>
		/// Initializes the privileges
		/// </summary>
		/// <param name="anonymousCanView">true to allow anonymous can view by default</param>
		public Privileges(bool anonymousCanView)
		{
			if (anonymousCanView)
				this.ViewableRoles.Add(SystemRole.All.ToString());
		}

		/// <summary>
		/// Initializes the privileges
		/// </summary>
		/// <param name="privileges">The object that contains the privileges</param>
		public Privileges(JObject privileges)
		{
			if (privileges != null)
				new[] { "Administrative", "Moderate", "Editable", "Contributive", "Viewable", "Downloadable" }.ForEach(name =>
				{
					var values = privileges.Get<JArray>($"{name}Roles");
					if (values != null)
						this.SetAttributeValue($"{name}Roles", new HashSet<string>(values.Select(value => value is JValue ? (value as JValue).Value as string : null).Where(value => value != null)));
					values = privileges.Get<JArray>($"{name}Users");
					if (values != null)
						this.SetAttributeValue($"{name}Users", new HashSet<string>(values.Select(value => value is JValue ? (value as JValue).Value as string : null).Where(value => value != null)));
				});
		}

		/// <summary>
		/// Initializes the privileges
		/// </summary>
		/// <param name="privileges">The object that contains the privileges</param>
		public Privileges(ExpandoObject privileges)
		{
			if (privileges != null)
				new[] { "Administrative", "Moderate", "Editable", "Contributive", "Viewable", "Downloadable" }.ForEach(name =>
				{
					var values = privileges.Get<List<string>>($"{name}Roles");
					if (values != null)
						this.SetAttributeValue($"{name}Roles", new HashSet<string>(values.Where(value => !string.IsNullOrWhiteSpace(value))));
					values = privileges.Get<List<string>>($"{name}Users");
					if (values != null)
						this.SetAttributeValue($"{name}Users", new HashSet<string>(values.Where(value => !string.IsNullOrWhiteSpace(value))));
				});
		}

		#region Properties
		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to manage (means full access)
		/// </summary>
		public HashSet<string> AdministrativeRoles { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of users that able to manage (means full access)
		/// </summary>
		public HashSet<string> AdministrativeUsers { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to moderate (means moderate all kinds of resources)
		/// </summary>
		public HashSet<string> ModerateRoles { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of users that able to moderate (means moderate all kinds of resources)
		/// </summary>
		public HashSet<string> ModerateUsers { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to edit (means create new and re-update the published resources)
		/// </summary>
		public HashSet<string> EditableRoles { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of users that able to edit (means create new and re-update the published resources)
		/// </summary>
		public HashSet<string> EditableUsers { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to contribute (means create new and view the published/their own resources)
		/// </summary>
		public HashSet<string> ContributiveRoles { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of users that able to contribute (means create new and view the published/their own resources)
		/// </summary>
		public HashSet<string> ContributiveUsers { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to view the details (means read-only on published resources)
		/// </summary>
		public HashSet<string> ViewableRoles { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of users that able to view the details (means read-only on published resources)
		/// </summary>
		public HashSet<string> ViewableUsers { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of working roles that able to download files/attachments of the published resources
		/// </summary>
		public HashSet<string> DownloadableRoles { get; set; } = new HashSet<string>();

		/// <summary>
		/// Gets or sets the collection of identity of users that able to download files/attachments of the published resources
		/// </summary>
		public HashSet<string> DownloadableUsers { get; set; } = new HashSet<string>();
		#endregion

	}

}