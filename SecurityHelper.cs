#region Related components
using System;
using System.Linq;
using System.Collections.Generic;
#endregion

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Collection of helper methods for working with security
	/// </summary>
	public static class SecurityHelper
	{

		#region Extensions: normalize & combine
		internal static bool IsEmpty(HashSet<string> roles, HashSet<string> users)
		{
			return (roles == null || roles.Count < 1) && (users == null || users.Count < 1);
		}

		internal static bool IsNotEmpty(HashSet<string> roles, HashSet<string> users)
		{
			return (roles != null && roles.Count > 0) || (users != null && users.Count > 0);
		}

		/// <summary>
		/// Normalizes the access permissions of an business entity
		/// </summary>
		/// <param name="object"></param>
		/// <returns></returns>
		public static Privileges Normalize(this Privileges @object)
		{
			if (@object == null)
				return null;

			var permissions = new Privileges();

			if (SecurityHelper.IsEmpty(@object.DownloadableRoles, @object.DownloadableUsers))
				permissions.DownloadableRoles = permissions.DownloadableUsers = null;
			else
			{
				permissions.DownloadableRoles = @object.DownloadableRoles;
				permissions.DownloadableUsers = @object.DownloadableUsers;
			}

			if (SecurityHelper.IsEmpty(@object.ViewableRoles, @object.ViewableUsers))
				permissions.ViewableRoles = permissions.ViewableUsers = null;
			else
			{
				permissions.ViewableRoles = @object.ViewableRoles;
				permissions.ViewableUsers = @object.ViewableUsers;
			}

			if (SecurityHelper.IsEmpty(@object.ContributiveRoles, @object.ContributiveUsers))
				permissions.ContributiveRoles = permissions.ContributiveUsers = null;
			else
			{
				permissions.ContributiveRoles = @object.ContributiveRoles;
				permissions.ContributiveUsers = @object.ContributiveUsers;
			}

			if (SecurityHelper.IsEmpty(@object.EditableRoles, @object.EditableUsers))
				permissions.EditableRoles = permissions.EditableUsers = null;
			else
			{
				permissions.EditableRoles = @object.EditableRoles;
				permissions.EditableUsers = @object.EditableUsers;
			}

			if (SecurityHelper.IsEmpty(@object.ModerateRoles, @object.ModerateUsers))
				permissions.ModerateRoles = permissions.ModerateUsers = null;
			else
			{
				permissions.ModerateRoles = @object.ModerateRoles;
				permissions.ModerateUsers = @object.ModerateUsers;
			}

			if (SecurityHelper.IsEmpty(@object.AdministrativeRoles, @object.AdministrativeUsers))
				permissions.AdministrativeRoles = permissions.AdministrativeUsers = null;
			else
			{
				permissions.AdministrativeRoles = @object.AdministrativeRoles;
				permissions.AdministrativeUsers = @object.AdministrativeUsers;
			}

			if (SecurityHelper.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& SecurityHelper.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& SecurityHelper.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& SecurityHelper.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& SecurityHelper.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& SecurityHelper.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
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

			if (originalPrivileges != null && SecurityHelper.IsNotEmpty(originalPrivileges.DownloadableRoles, originalPrivileges.DownloadableUsers))
			{
				permissions.DownloadableRoles = originalPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = originalPrivileges.DownloadableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.DownloadableRoles = parentPrivileges.DownloadableRoles;
				permissions.DownloadableUsers = parentPrivileges.DownloadableUsers;
			}

			if (originalPrivileges != null && SecurityHelper.IsNotEmpty(originalPrivileges.ViewableRoles, originalPrivileges.ViewableUsers))
			{
				permissions.ViewableRoles = originalPrivileges.ViewableRoles;
				permissions.ViewableUsers = originalPrivileges.ViewableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ViewableRoles = parentPrivileges.ViewableRoles;
				permissions.ViewableUsers = parentPrivileges.ViewableUsers;
			}

			if (originalPrivileges != null && SecurityHelper.IsNotEmpty(originalPrivileges.ContributiveRoles, originalPrivileges.ContributiveUsers))
			{
				permissions.ContributiveRoles = originalPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = originalPrivileges.ContributiveUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ContributiveRoles = parentPrivileges.ContributiveRoles;
				permissions.ContributiveUsers = parentPrivileges.ContributiveUsers;
			}

			if (originalPrivileges != null && SecurityHelper.IsNotEmpty(originalPrivileges.EditableRoles, originalPrivileges.EditableUsers))
			{
				permissions.EditableRoles = originalPrivileges.EditableRoles;
				permissions.EditableUsers = originalPrivileges.EditableUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.EditableRoles = parentPrivileges.EditableRoles;
				permissions.EditableUsers = parentPrivileges.EditableUsers;
			}

			if (originalPrivileges != null && SecurityHelper.IsNotEmpty(originalPrivileges.ModerateRoles, originalPrivileges.ModerateUsers))
			{
				permissions.ModerateRoles = originalPrivileges.ModerateRoles;
				permissions.ModerateUsers = originalPrivileges.ModerateUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.ModerateRoles = parentPrivileges.ModerateRoles;
				permissions.ModerateUsers = parentPrivileges.ModerateUsers;
			}

			if (originalPrivileges != null && SecurityHelper.IsNotEmpty(originalPrivileges.AdministrativeRoles, originalPrivileges.AdministrativeUsers))
			{
				permissions.AdministrativeRoles = originalPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = originalPrivileges.AdministrativeUsers;
			}
			else if (parentPrivileges != null)
			{
				permissions.AdministrativeRoles = parentPrivileges.AdministrativeRoles;
				permissions.AdministrativeUsers = parentPrivileges.AdministrativeUsers;
			}

			if (SecurityHelper.IsEmpty(permissions.DownloadableRoles, permissions.DownloadableUsers)
				&& SecurityHelper.IsEmpty(permissions.ViewableRoles, permissions.ViewableUsers)
				&& SecurityHelper.IsEmpty(permissions.ContributiveRoles, permissions.ContributiveUsers)
				&& SecurityHelper.IsEmpty(permissions.EditableRoles, permissions.EditableUsers)
				&& SecurityHelper.IsEmpty(permissions.ModerateRoles, permissions.ModerateUsers)
				&& SecurityHelper.IsEmpty(permissions.AdministrativeRoles, permissions.AdministrativeUsers))
				permissions = null;

			return permissions;
		}
		#endregion

		#region Helper: check which action that user can perform base on their roles
		/// <summary>
		/// Determines an user can manage (means the user can act like an administrator)
		/// </summary>
		/// <param name="user">The information of an user who want to perform the action</param>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanManage(this User user, Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			if (user == null || string.IsNullOrWhiteSpace(user.ID))
				return false;

			var can = originalPrivileges != null && originalPrivileges.AdministrativeUsers != null && originalPrivileges.AdministrativeUsers.Contains(user.ID.ToLower());
			if (!can && user.Roles != null && originalPrivileges != null && originalPrivileges.AdministrativeRoles != null)
				can = originalPrivileges.AdministrativeRoles.Intersect(user.Roles).Count() > 0;

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.AdministrativeUsers != null && parentPrivileges.AdministrativeUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && parentPrivileges.AdministrativeRoles != null)
					can = parentPrivileges.AdministrativeRoles.Intersect(user.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can moderate (means the user can act like a moderator)
		/// </summary>
		/// <param name="user">The information of an user who want to perform the moderation action</param>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanModerate(this User user, Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			if (user == null || string.IsNullOrWhiteSpace(user.ID))
				return false;

			var can = user.CanManage(originalPrivileges, parentPrivileges);

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.ModerateUsers != null && originalPrivileges.ModerateUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && originalPrivileges != null && originalPrivileges.ModerateRoles != null)
					can = originalPrivileges.ModerateRoles.Intersect(user.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.ModerateUsers != null && parentPrivileges.ModerateUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && parentPrivileges.ModerateRoles != null)
					can = parentPrivileges.ModerateRoles.Intersect(user.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can edit (means the user can act like an editor)
		/// </summary>
		/// <param name="user">The information of an user who want to perform the edit action</param>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanEdit(this User user, Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			if (user == null || string.IsNullOrWhiteSpace(user.ID))
				return false;

			var can = user.CanModerate(originalPrivileges, parentPrivileges);

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.EditableUsers != null && originalPrivileges.EditableUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && originalPrivileges != null && originalPrivileges.EditableRoles != null)
					can = originalPrivileges.EditableRoles.Intersect(user.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.EditableUsers != null && parentPrivileges.EditableUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && parentPrivileges.EditableRoles != null)
					can = parentPrivileges.EditableRoles.Intersect(user.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can contribute (means the user can act like a contributor)
		/// </summary>
		/// <param name="user">The information of an user who want to perform the contribute action</param>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanContribute(this User user, Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			if (user == null)
				return false;

			var can = user.CanEdit(originalPrivileges, parentPrivileges);

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.ContributiveUsers != null && !string.IsNullOrWhiteSpace(user.ID) && originalPrivileges.ContributiveUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && originalPrivileges != null && originalPrivileges.ContributiveRoles != null)
					can = originalPrivileges.ContributiveRoles.Intersect(user.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.ContributiveUsers != null && !string.IsNullOrWhiteSpace(user.ID) && parentPrivileges.ContributiveUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && parentPrivileges.ContributiveRoles != null)
					can = parentPrivileges.ContributiveRoles.Intersect(user.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can view (means the user can act like a viewer)
		/// </summary>
		/// <param name="user">The information of an user who want to perform the action</param>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanView(this User user, Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			if (user == null)
				return false;

			var can = user.CanContribute(originalPrivileges, parentPrivileges);

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.ViewableUsers != null && !string.IsNullOrWhiteSpace(user.ID) && originalPrivileges.ViewableUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && originalPrivileges != null && originalPrivileges.ViewableRoles != null)
					can = originalPrivileges.ViewableRoles.Intersect(user.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.ViewableUsers != null && !string.IsNullOrWhiteSpace(user.ID) && parentPrivileges.ViewableUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && parentPrivileges.ViewableRoles != null)
					can = parentPrivileges.ViewableRoles.Intersect(user.Roles).Count() > 0;
			}

			return can;
		}

		/// <summary>
		/// Determines an user can download (means the user can act like a downloader/viewer)
		/// </summary>
		/// <param name="user">The information of an user who want to perform the action</param>
		/// <param name="originalPrivileges">The object that presents the working permissions of current resource</param>
		/// <param name="parentPrivileges">The object that presents the working permissions of parent resource</param>
		/// <returns>true if the user got right; otherwise false</returns>
		public static bool CanDownload(this User user, Privileges originalPrivileges, Privileges parentPrivileges = null)
		{
			if (user == null)
				return false;

			var can = (originalPrivileges == null || SecurityHelper.IsEmpty(originalPrivileges.DownloadableUsers, originalPrivileges.DownloadableRoles))
				&& (parentPrivileges == null || SecurityHelper.IsEmpty(parentPrivileges.DownloadableUsers, parentPrivileges.DownloadableRoles))
				? user.CanView(originalPrivileges, parentPrivileges)
				: false;

			if (!can && originalPrivileges != null)
			{
				can = originalPrivileges.DownloadableUsers != null && !string.IsNullOrWhiteSpace(user.ID) && originalPrivileges.DownloadableUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && originalPrivileges != null && originalPrivileges.DownloadableRoles != null)
					can = originalPrivileges.DownloadableRoles.Intersect(user.Roles).Count() > 0;
			}

			if (!can && parentPrivileges != null)
			{
				can = parentPrivileges.DownloadableUsers != null && !string.IsNullOrWhiteSpace(user.ID) && parentPrivileges.DownloadableUsers.Contains(user.ID.ToLower());
				if (!can && user.Roles != null && parentPrivileges.DownloadableRoles != null)
					can = parentPrivileges.DownloadableRoles.Intersect(user.Roles).Count() > 0;
			}

			return can;
		}
		#endregion

	}
}