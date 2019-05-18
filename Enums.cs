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
		/// Books an object
		/// </summary>
		Book,

		/// <summary>
		/// Gives an object
		/// </summary>
		Give,

		/// <summary>
		/// Sends an object
		/// </summary>
		Send,

		/// <summary>
		/// Returns an object
		/// </summary>
		Return,

		/// <summary>
		/// All actions
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
		/// All kinds of users (include anonymous/visitor)
		/// </summary>
		All,

		/// <summary>
		/// All kinds of users that are marked as signed-in account
		/// </summary>
		Authenticated,

		/// <summary>
		/// Signed-in accounts that mark as system administrator
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
	/// All available approval statuses
	/// </summary>
	[Serializable]
	public enum ApprovalStatus
	{
		/// <summary>
		/// Draft mean the content is in editing by owner.
		/// </summary>
		Draft,

		/// <summary>
		/// Pending mean the content is submited for approval review.
		/// </summary>
		Pending,

		/// <summary>
		/// Rejected mean the content is rejected by reviewer and need to re-edit.
		/// </summary>
		Rejected,

		/// <summary>
		/// Approved mean the content is approved but await for publishing to public.
		/// </summary>
		Approved,

		/// <summary>
		/// Published mean the content is published to public.
		/// </summary>
		Published,

		/// <summary>
		/// Archieved mean the content is archieved for using with other purpose in the furture.
		/// </summary>
		Archieved
	}

}