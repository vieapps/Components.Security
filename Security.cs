using System;
using System.Linq;
using System.Collections.Generic;

namespace net.vieapps.Components.Security
{
	public static class SecurityHelper
	{
		/// <summary>
		/// Normalizes the access permissions of an business entity
		/// </summary>
		/// <param name="object"></param>
		/// <returns></returns>
		public static AccessPermissions Normalize(this AccessPermissions @object)
		{
			if (@object == null)
				return null;

			var permissions = new AccessPermissions();

			if (AccessPermissions.IsEmpty(@object.DownloadableRoles, @object.DownloadableUsers))
				permissions.DownloadableRoles = permissions.DownloadableUsers = null;
			else
			{
				permissions.DownloadableRoles = @object.DownloadableRoles;
				permissions.DownloadableUsers = @object.DownloadableUsers;
			}

			if (AccessPermissions.IsEmpty(@object.ViewableRoles, @object.ViewableUsers))
				permissions.ViewableRoles = permissions.ViewableUsers = null;
			else
			{
				permissions.ViewableRoles = @object.ViewableRoles;
				permissions.ViewableUsers = @object.ViewableUsers;
			}

			if (AccessPermissions.IsEmpty(@object.ContributiveRoles, @object.ContributiveUsers))
				permissions.ContributiveRoles = permissions.ContributiveUsers = null;
			else
			{
				permissions.ContributiveRoles = @object.ContributiveRoles;
				permissions.ContributiveUsers = @object.ContributiveUsers;
			}

			if (AccessPermissions.IsEmpty(@object.EditableRoles, @object.EditableUsers))
				permissions.EditableRoles = permissions.EditableUsers = null;
			else
			{
				permissions.EditableRoles = @object.EditableRoles;
				permissions.EditableUsers = @object.EditableUsers;
			}

			if (AccessPermissions.IsEmpty(@object.ModerateRoles, @object.ModerateUsers))
				permissions.ModerateRoles = permissions.ModerateUsers = null;
			else
			{
				permissions.ModerateRoles = @object.ModerateRoles;
				permissions.ModerateUsers = @object.ModerateUsers;
			}

			if (AccessPermissions.IsEmpty(@object.AdministrativeRoles, @object.AdministrativeUsers))
				permissions.AdministrativeRoles = permissions.AdministrativeUsers = null;
			else
			{
				permissions.AdministrativeRoles = @object.AdministrativeRoles;
				permissions.AdministrativeUsers = @object.AdministrativeUsers;
			}

			if (AccessPermissions.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& AccessPermissions.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& AccessPermissions.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& AccessPermissions.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& AccessPermissions.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& AccessPermissions.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
		}

		/// <summary>
		/// Combines the original permissions of a business entity with parent permissions
		/// </summary>
		/// <param name="originalPermissions"></param>
		/// <param name="parentPermissions"></param>
		/// <returns></returns>
		public static AccessPermissions Combine(this AccessPermissions originalPermissions, AccessPermissions parentPermissions)
		{
			if (originalPermissions == null && parentPermissions == null)
				return null;

			var permissions = new AccessPermissions();

			if (originalPermissions != null && AccessPermissions.IsNotEmpty(originalPermissions.DownloadableRoles, originalPermissions.DownloadableUsers))
			{
				permissions.DownloadableRoles = originalPermissions.DownloadableRoles;
				permissions.DownloadableUsers = originalPermissions.DownloadableUsers;
			}
			else if (parentPermissions != null)
			{
				permissions.DownloadableRoles = parentPermissions.DownloadableRoles;
				permissions.DownloadableUsers = parentPermissions.DownloadableUsers;
			}

			if (originalPermissions != null && AccessPermissions.IsNotEmpty(originalPermissions.ViewableRoles, originalPermissions.ViewableUsers))
			{
				permissions.ViewableRoles = originalPermissions.ViewableRoles;
				permissions.ViewableUsers = originalPermissions.ViewableUsers;
			}
			else if (parentPermissions != null)
			{
				permissions.ViewableRoles = parentPermissions.ViewableRoles;
				permissions.ViewableUsers = parentPermissions.ViewableUsers;
			}

			if (originalPermissions != null && AccessPermissions.IsNotEmpty(originalPermissions.ContributiveRoles, originalPermissions.ContributiveUsers))
			{
				permissions.ContributiveRoles = originalPermissions.ContributiveRoles;
				permissions.ContributiveUsers = originalPermissions.ContributiveUsers;
			}
			else if (parentPermissions != null)
			{
				permissions.ContributiveRoles = parentPermissions.ContributiveRoles;
				permissions.ContributiveUsers = parentPermissions.ContributiveUsers;
			}

			if (originalPermissions != null && AccessPermissions.IsNotEmpty(originalPermissions.EditableRoles, originalPermissions.EditableUsers))
			{
				permissions.EditableRoles = originalPermissions.EditableRoles;
				permissions.EditableUsers = originalPermissions.EditableUsers;
			}
			else if (parentPermissions != null)
			{
				permissions.EditableRoles = parentPermissions.EditableRoles;
				permissions.EditableUsers = parentPermissions.EditableUsers;
			}

			if (originalPermissions != null && AccessPermissions.IsNotEmpty(originalPermissions.ModerateRoles, originalPermissions.ModerateUsers))
			{
				permissions.ModerateRoles = originalPermissions.ModerateRoles;
				permissions.ModerateUsers = originalPermissions.ModerateUsers;
			}
			else if (parentPermissions != null)
			{
				permissions.ModerateRoles = parentPermissions.ModerateRoles;
				permissions.ModerateUsers = parentPermissions.ModerateUsers;
			}

			if (originalPermissions != null && AccessPermissions.IsNotEmpty(originalPermissions.AdministrativeRoles, originalPermissions.AdministrativeUsers))
			{
				permissions.AdministrativeRoles = originalPermissions.AdministrativeRoles;
				permissions.AdministrativeUsers = originalPermissions.AdministrativeUsers;
			}
			else if (parentPermissions != null)
			{
				permissions.AdministrativeRoles = parentPermissions.AdministrativeRoles;
				permissions.AdministrativeUsers = parentPermissions.AdministrativeUsers;
			}

			if (AccessPermissions.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& AccessPermissions.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& AccessPermissions.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& AccessPermissions.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& AccessPermissions.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& AccessPermissions.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
		}

		/// <summary>
		/// Determines an user can manage (means the user can act like an administrator)
		/// </summary>
		/// <param name="userID">The string that presents the identity of an user</param>
		/// <param name="userRoles">The collection of strings that presents the roles of an users</param>
		/// <param name="originalPermissions">The object that presents original permissions</param>
		/// <param name="parentPermissions">The object that presents parent permissions</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanManage(string userID, IEnumerable<string> userRoles, AccessPermissions originalPermissions, AccessPermissions parentPermissions = null)
		{
			if (string.IsNullOrWhiteSpace(userID))
				return false;

			var can = originalPermissions != null && originalPermissions.AdministrativeUsers != null && originalPermissions.AdministrativeUsers.Contains(userID.ToLower());
			if (!can && userRoles != null && originalPermissions != null && originalPermissions.AdministrativeRoles != null)
				can = originalPermissions.AdministrativeRoles.Intersect(userRoles).Count() > 0;

			if (!can && parentPermissions != null)
			{
				can = parentPermissions.AdministrativeUsers != null && parentPermissions.AdministrativeUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && parentPermissions.AdministrativeRoles != null)
					can = parentPermissions.AdministrativeRoles.Intersect(userRoles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can moderate (means the user can act like a moderator)
		/// </summary>
		/// <param name="userID">The string that presents the identity of an user</param>
		/// <param name="userRoles">The collection of strings that presents the roles of an users</param>
		/// <param name="originalPermissions">The object that presents original permissions</param>
		/// <param name="parentPermissions">The object that presents parent permissions</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanModerate(string userID, IEnumerable<string> userRoles, AccessPermissions originalPermissions, AccessPermissions parentPermissions = null)
		{
			if (string.IsNullOrWhiteSpace(userID))
				return false;

			var can = SecurityHelper.CanManage(userID, userRoles, originalPermissions, parentPermissions);

			if (!can && originalPermissions != null)
			{
				can = originalPermissions.ModerateUsers != null && originalPermissions.ModerateUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && originalPermissions != null && originalPermissions.ModerateRoles != null)
					can = originalPermissions.ModerateRoles.Intersect(userRoles).Count() > 0;
			}

			if (!can && parentPermissions != null)
			{
				can = parentPermissions.ModerateUsers != null && parentPermissions.ModerateUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && parentPermissions.ModerateRoles != null)
					can = parentPermissions.ModerateRoles.Intersect(userRoles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can edit (means the user can act like an editor)
		/// </summary>
		/// <param name="userID">The string that presents the identity of an user</param>
		/// <param name="userRoles">The collection of strings that presents the roles of an users</param>
		/// <param name="originalPermissions">The object that presents original permissions</param>
		/// <param name="parentPermissions">The object that presents parent permissions</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanEdit(string userID, IEnumerable<string> userRoles, AccessPermissions originalPermissions, AccessPermissions parentPermissions = null)
		{
			if (string.IsNullOrWhiteSpace(userID))
				return false;

			var can = SecurityHelper.CanModerate(userID, userRoles, originalPermissions, parentPermissions);

			if (!can && originalPermissions != null)
			{
				can = originalPermissions.EditableUsers != null && originalPermissions.EditableUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && originalPermissions != null && originalPermissions.EditableRoles != null)
					can = originalPermissions.EditableRoles.Intersect(userRoles).Count() > 0;
			}

			if (!can && parentPermissions != null)
			{
				can = parentPermissions.EditableUsers != null && parentPermissions.EditableUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && parentPermissions.EditableRoles != null)
					can = parentPermissions.EditableRoles.Intersect(userRoles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can contribute (means the user can act like a contributor)
		/// </summary>
		/// <param name="userID">The string that presents the identity of an user</param>
		/// <param name="userRoles">The collection of strings that presents the roles of an users</param>
		/// <param name="originalPermissions">The object that presents original permissions</param>
		/// <param name="parentPermissions">The object that presents parent permissions</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanContribute(string userID, IEnumerable<string> userRoles, AccessPermissions originalPermissions, AccessPermissions parentPermissions = null)
		{
			if (string.IsNullOrWhiteSpace(userID))
				return false;

			var can = SecurityHelper.CanEdit(userID, userRoles, originalPermissions, parentPermissions);

			if (!can && originalPermissions != null)
			{
				can = originalPermissions.ContributiveUsers != null && originalPermissions.ContributiveUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && originalPermissions != null && originalPermissions.ContributiveRoles != null)
					can = originalPermissions.ContributiveRoles.Intersect(userRoles).Count() > 0;
			}

			if (!can && parentPermissions != null)
			{
				can = parentPermissions.ContributiveUsers != null && parentPermissions.ContributiveUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && parentPermissions.ContributiveRoles != null)
					can = parentPermissions.ContributiveRoles.Intersect(userRoles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can view (means the user can act like a viewer)
		/// </summary>
		/// <param name="userID">The string that presents the identity of an user</param>
		/// <param name="userRoles">The collection of strings that presents the roles of an users</param>
		/// <param name="originalPermissions">The object that presents original permissions</param>
		/// <param name="parentPermissions">The object that presents parent permissions</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanView(string userID, IEnumerable<string> userRoles, AccessPermissions originalPermissions, AccessPermissions parentPermissions = null)
		{
			if (string.IsNullOrWhiteSpace(userID))
				return false;

			var can = SecurityHelper.CanContribute(userID, userRoles, originalPermissions, parentPermissions);

			if (!can && originalPermissions != null)
			{
				can = originalPermissions.ViewableUsers != null && originalPermissions.ViewableUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && originalPermissions != null && originalPermissions.ViewableRoles != null)
					can = originalPermissions.ViewableRoles.Intersect(userRoles).Count() > 0;
			}

			if (!can && parentPermissions != null)
			{
				can = parentPermissions.ViewableUsers != null && parentPermissions.ViewableUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && parentPermissions.ViewableRoles != null)
					can = parentPermissions.ViewableRoles.Intersect(userRoles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can download (means the user can act like a downloader/viewer)
		/// </summary>
		/// <param name="userID">The string that presents the identity of an user</param>
		/// <param name="userRoles">The collection of strings that presents the roles of an users</param>
		/// <param name="originalPermissions">The object that presents original permissions</param>
		/// <param name="parentPermissions">The object that presents parent permissions</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanDownload(string userID, IEnumerable<string> userRoles, AccessPermissions originalPermissions, AccessPermissions parentPermissions = null)
		{
			if (string.IsNullOrWhiteSpace(userID))
				return false;

			var can = (originalPermissions == null || AccessPermissions.IsEmpty(originalPermissions.DownloadableUsers, originalPermissions.DownloadableRoles))
				&& (parentPermissions == null || AccessPermissions.IsEmpty(parentPermissions.DownloadableUsers, parentPermissions.DownloadableRoles))
				? SecurityHelper.CanView(userID, userRoles, originalPermissions, parentPermissions)
				: false;

			if (!can && originalPermissions != null)
			{
				can = originalPermissions.DownloadableUsers != null && originalPermissions.DownloadableUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && originalPermissions != null && originalPermissions.DownloadableRoles != null)
					can = originalPermissions.DownloadableRoles.Intersect(userRoles).Count() > 0;
			}

			if (!can && parentPermissions != null)
			{
				can = parentPermissions.DownloadableUsers != null && parentPermissions.DownloadableUsers.Contains(userID.ToLower());
				if (!can && userRoles != null && parentPermissions.DownloadableRoles != null)
					can = parentPermissions.DownloadableRoles.Intersect(userRoles).Count() > 0;
			}

			return can;
		}
	}
}