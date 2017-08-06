using System;

namespace net.vieapps.Components.Security
{
	/// <summary>
	/// Available actions
	/// </summary>
	[Serializable]
	public enum Action
	{
		/// <summary>
		/// Creates (Contributes) an object
		/// </summary>
		Create,

		/// <summary>
		/// Views (Reads) an object
		/// </summary>
		View,

		/// <summary>
		/// Downloads a resource (like attachment file, image, ..)
		/// </summary>
		Download,

		/// <summary>
		/// Updates an existing object
		/// </summary>
		Update,

		/// <summary>
		/// Deletes an existing object (means move the object into recycle-bin)
		/// </summary>
		Delete,

		/// <summary>
		/// Deletes an existing object permanently
		/// </summary>
		PermanentDelete,

		/// <summary>
		/// Rollbacks an existing object from a previous version
		/// </summary>
		Rollback,

		/// <summary>
		/// Restores an object (means put back the object from the recycle-bin)
		/// </summary>
		Restore,

		/// <summary>
		/// Approves an object (means change the approval/moderation status of an object)
		/// </summary>
		Approve,

		/// <summary>
		/// Archives an object (means backup or move an object into archiving repository)
		/// </summary>
		Archive,

		/// <summary>
		/// Synchronizes an object (means update/create new/delete an object by related information from other data-source)
		/// </summary>
		Synchronize,

		/// <summary>
		/// Votes up/down an object
		/// </summary>
		Vote,

		/// <summary>
		/// Comments on an object
		/// </summary>
		Comment,

		/// <summary>
		/// Checks an object out
		/// </summary>
		CheckOut,

		/// <summary>
		/// Checks an object in
		/// </summary>
		CheckIn,

		/// <summary>
		/// Registers an object
		/// </summary>
		Register,

		/// <summary>
		/// Activates an object
		/// </summary>
		Activate,

		/// <summary>
		/// Locks an object
		/// </summary>
		Lock,

		/// <summary>
		/// Unlocks an object
		/// </summary>
		Unlock,

		/// <summary>
		/// Fulls means all actions
		/// </summary>
		Full
	}

	//  --------------------------------------------------------------------------------------------

	/// <summary>
	/// Available system roles
	/// </summary>
	[Serializable]
	public enum SystemRole
	{
		/// <summary>
		/// All users (mean all kinds of users, include anonymous/visitor)
		/// </summary>
		All,

		/// <summary>
		/// Authenticated users (means all users that are signed-in with an account)
		/// </summary>
		Authenticated,

		/// <summary>
		/// Authenticated users of a specified serivce/site (means signed-in accounts that marked as member of a service/site)
		/// </summary>
		Authorized,

		/// <summary>
		/// Moderator of a specified serivce/site (means signed-in accounts that marked as moderator of a service/site)
		/// </summary>
		Moderator,

		/// <summary>
		/// Administrator of a specified serivce/site (means signed-in accounts that marked as moderator of a service/site)
		/// </summary>
		Administrator,

		/// <summary>
		/// Administrator of the whole system/services
		/// </summary>
		SystemAdministrator
	}

	//  --------------------------------------------------------------------------------------------

	/// <summary>
	/// Available privilege roles
	/// </summary>
	[Serializable]
	public enum PrivilegeRole
	{
		/// <summary>
		/// Presents the working role that able to download files/attachments of the published resources
		/// </summary>
		Downloader,

		/// <summary>
		/// Presents the working role that able to view the details (means read-only on published resources)
		/// </summary>
		Viewer,

		/// <summary>
		/// Presents the working role that able to contribute (means create new and view the published/their own resources)
		/// </summary>
		Contributor,

		/// <summary>
		/// Presents the working role that able to edit (means create new and re-update the published resources)
		/// </summary>
		Editor,

		/// <summary>
		/// Presents the working role that able to moderate (means moderate all kinds of resources)
		/// </summary>
		Moderator,

		/// <summary>
		/// Presents the working role that able to do anything (means full access)
		/// </summary>
		Administrator
	}

	//  --------------------------------------------------------------------------------------------

	/// <summary>
	/// Available type of an user's account
	/// </summary>
	[Serializable]
	public enum AccountType
	{
		/// <summary>
		/// Presents the built-in account (default)
		/// </summary>
		BuiltIn,

		/// <summary>
		/// Presents the OAth account
		/// </summary>
		OAuth,

		/// <summary>
		/// Presents the Windows LDAP account
		/// </summary>
		Windows
	}

	//  --------------------------------------------------------------------------------------------

	/// <summary>
	/// Available type of an OAuth's account
	/// </summary>
	[Serializable]
	public enum OAuthType
	{
		/// <summary>
		/// Presents the account that are authenticated by Facebook OAuth
		/// </summary>
		Facebook,

		/// <summary>
		/// Presents the account that are authenticated by Goole OAuth
		/// </summary>
		Google,

		/// <summary>
		/// Presents the account that are authenticated by Microsoft OAuth
		/// </summary>
		Microsoft,

		/// <summary>
		/// Presents the account that are authenticated by Twitter OAuth
		/// </summary>
		Twitter,

		/// <summary>
		/// Presents the account that are authenticated by LinkedIn OAuth
		/// </summary>
		LinkedIn
	}

}