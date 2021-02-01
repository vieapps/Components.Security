#region Related components
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
		public UserPrincipal()
			: this(new UserIdentity()) { }

		/// <summary>
		/// Initializes the new instance of an user principal from the specified identity
		/// </summary>
		/// <param name="user">The identity from which to initialize the new principal</param>
		public UserPrincipal(IUser user)
			: this(new UserIdentity(user)) { }

		/// <summary>
		/// Initializes the new instance of an user principal from the specified identity
		/// </summary>
		/// <param name="identity">The identity from which to initialize the new principal</param>
		public UserPrincipal(UserIdentity identity)
			: base(identity)
			=> this.Identity = identity ?? new UserIdentity();

		/// <summary>
		/// Initializes the new instance of an user principal
		/// </summary>
		/// <param name="principal">The principal from which to initialize the new principal</param>
		public UserPrincipal(ClaimsPrincipal principal)
			: base(principal)
			=> this.Identity = new UserIdentity(principal);

		/// <summary>
		/// Gets the current principal
		/// </summary>
		public static new UserPrincipal Current
			=> new UserPrincipal(ClaimsPrincipal.Current);

		/// <summary>
		/// Gets the identity that associated with this principal
		/// </summary>
		public override IIdentity Identity { get; }

		/// <summary>
		/// Gets a value that indicates whether the user (of the current identity) has been authenticated
		/// </summary>
		public bool IsAuthenticated
			=> this.Identity != null && (this.Identity as UserIdentity).IsAuthenticated;

		/// <summary>
		/// Determines whether the current principal is system administrator or not
		/// </summary>
		public bool IsSystemAdministrator
			=> this.Identity != null && (this.Identity as UserIdentity).IsSystemAdministrator;

		/// <summary>
		/// Determines whether the current principal belongs to the specified role
		/// </summary>
		/// <param name="role"></param>
		/// <returns></returns>
		public override bool IsInRole(string role)
			=> this.Identity != null && (this.Identity as UserIdentity).IsInRole(role);
	}
}