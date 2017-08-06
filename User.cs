#region Related components
using System;
using System.Collections.Generic;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Converters;
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

	}

}