#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.Claims;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Presents the identity of an user
	/// </summary>
	public class UserIdentity : ClaimsIdentity, IUser
	{
		/// <summary>
		/// Initializes a new instance of the UserIdentity class with the specified authentication type
		/// </summary>
		public UserIdentity()
			: base()
			=> this.SetUser();

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="userID">The identity of user</param>
		/// <param name="sessionID">The identity of working session</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public UserIdentity(string userID, string sessionID, string authenticationType = null)
			: this(userID, sessionID, null, null, authenticationType)
			=> this.SetUser();

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity, name and the specified authentication type
		/// </summary>
		/// <param name="userID">The identity of user</param>
		/// <param name="sessionID">The identity of working session</param>
		/// <param name="roles">The working roles</param>
		/// <param name="privileges">The working privileges</param>
		/// <param name="authenticationType">The type of authentication used</param>
		public UserIdentity(string userID, string sessionID, List<string> roles, List<Privilege> privileges, string authenticationType = null)
		{
			this.ID = userID;
			this.SessionID = sessionID;
			this.AuthenticationType = authenticationType ?? "APIs";
			this.Roles = roles ?? new List<string>();
			this.Privileges = privileges ?? new List<Privilege>();
			this.BuildClaims();
			this.BuildClaimsOfRolesAndPrivileges();
			this.SetUser();
		}

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with an associated principal
		/// </summary>
		/// <param name="principal">The user principal</param>
		public UserIdentity(ClaimsPrincipal principal)
			: this(principal?.Claims)
			=> this.SetUser();

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with an associated identity
		/// </summary>
		/// <param name="identity">The user identity</param>
		public UserIdentity(ClaimsIdentity identity)
			: this(identity?.Claims)
			=> this.SetUser();

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

			var userData = claims?.FirstOrDefault(claim => claim.Type.Equals(ClaimTypes.UserData))?.Value;
			if (!string.IsNullOrWhiteSpace(userData))
				try
				{
					var info = userData.ToExpandoObject();
					this.Roles = info.Get<List<string>>("Roles");
					this.Privileges = info.Get<List<Privilege>>("Privileges");
				}
				catch { }

			this.BuildClaimsOfRolesAndPrivileges();
			this.SetUser();
		}

		/// <summary>
		/// Initializes a new instance of the UserIdentity class with identity
		/// </summary>
		/// <param name="user">The identity of user</param>
		public UserIdentity(IUser user)
		{
			this.ID = user?.ID;
			this.SessionID = user?.SessionID;
			this.AuthenticationType = user?.AuthenticationType ?? "APIs";
			this.Roles = user?.Roles ?? new List<string>();
			this.Privileges = user?.Privileges ?? new List<Privilege>();
			this.BuildClaims();
			this.BuildClaimsOfRolesAndPrivileges();
			this.SetUser();
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

		/// <summary>
		/// Gets the authentication type
		/// </summary>
		public override string AuthenticationType { get; }

		/// <summary>
		/// Gets or name (identity) of user
		/// </summary>
		public override string Name => this.ID;
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
			this.AddClaim(new Claim(ClaimTypes.UserData, new Newtonsoft.Json.Linq.JObject
			{
				{ "Roles", this.Roles.ToJArray() },
				{ "Privileges", this.Privileges.ToJArray() }
			}.ToString(Newtonsoft.Json.Formatting.None)));
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

		/// <summary>
		/// Gets the user object that related to this identity
		/// </summary>
		public User User { get; private set; }

		void SetUser()
			=> this.User = new User(this.ID, this.SessionID, this.Roles, this.Privileges, this.AuthenticationType);

		/// <summary>
		/// Gets the state that determines the user is authenticated or not
		/// </summary>
		public override bool IsAuthenticated
			=> this.User.IsAuthenticated;

		/// <summary>
		/// Gets the state that determines the user is system account
		/// </summary>
		public bool IsSystemAccount
			=> this.User.IsSystemAccount;

		/// <summary>
		/// Gets the state that determines the user is system administrator
		/// </summary>
		public bool IsSystemAdministrator
=> this.User.IsSystemAdministrator;

		/// <summary>
		/// Gets the collection of the system administrators
		/// </summary>
		public static HashSet<string> SystemAdministrators
			=> User.SystemAdministrators;

		/// <summary>
		/// Determines whether this user belongs to the specified role or not
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
		public bool IsInRole(string role)
			=> this.User.IsInRole(role);
	}
}