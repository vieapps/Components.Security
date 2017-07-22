using System;

namespace net.vieapps.Components.Security
{
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

	}

	//  --------------------------------------------------------------------------------------------

	[Serializable]
	public enum Role
	{
		/// <summary>
		/// All users (mean anonymous users)
		/// </summary>
		All,

		/// <summary>
		/// Authorized users (means signed-in accounts)
		/// </summary>
		Authorized,

		/// <summary>
		/// Authorized user of a specified site (means signed-in accounts that marked as member of a site)
		/// </summary>
		SiteMember,

		/// <summary>
		/// System Administrator
		/// </summary>
		Administrator,
	}

}