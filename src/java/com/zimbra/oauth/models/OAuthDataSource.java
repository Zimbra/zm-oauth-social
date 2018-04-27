/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth Social Extension
 * Copyright (C) 2018 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.oauth.models;

import org.apache.commons.lang.StringUtils;

import com.zimbra.client.ZDataSource;
import com.zimbra.client.ZFolder;
import com.zimbra.client.ZFolder.View;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.InvalidResponseException;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * The OAuthDataSource class.<br>
 * ZDataSource wrapper for storing oauth credentials.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.models
 * @copyright Copyright © 2018
 */
public class OAuthDataSource {

	/**
	 * The host identifier for this source.
	 */
	protected final String host;

	/**
	 * Constructor.
	 *
	 * @param host A host
	 */
	protected OAuthDataSource(String host) {
		this.host = host;
	}

	/**
	 * Returns a new handler for a Zimbra DataSource.
	 *
	 * @param host The host this source is for
	 * @return OAuthDataSource handler instance
	 */
	public static OAuthDataSource createDataSource(String host) {
		return new OAuthDataSource(host);
	}

	/**
	 * Ensures the specified folder exists, or create/get the default folder.<br>
	 * If folderId param is null, default folder path is used.
	 *
	 * @param mailbox The mailbox to check
	 * @param folderId The folder id to check for (optional)
	 * @return Id of existing data source storage folder
	 * @throws InvalidResponseException
	 */
	protected String getStorageFolderId(ZMailbox mailbox, String folderId) throws InvalidResponseException {
		ZFolder folder = null;
		try {
			// grab the specified folder
			if (!StringUtils.isEmpty(folderId)) {
				folder = mailbox.getFolderById(folderId);
			}
			// if folder does not exist or none specified
			if (folder == null) {
				// check if default storage folder exists under Contacts
				final ZFolder contactsFolder = mailbox.getFolderById(ZFolder.ID_CONTACTS);
				if (contactsFolder == null) {
					ZimbraLog.extensions.debug("Contacts folder is missing, cannot create default token storage folder.");
					throw new InvalidResponseException("Contacts folder is missing, cannot create default token storage folder.");
				}
				folder = contactsFolder.getSubFolderByPath(OAuth2Constants.DEFAULT_OAUTH_FOLDER_PATH);
				// create if it does not exist
				if (folder == null) {
					ZimbraLog.extensions.debug("Creating default oauth datasource storage folder.");
					folder = mailbox.createFolder(
						ZFolder.ID_CONTACTS,
						OAuth2Constants.DEFAULT_OAUTH_FOLDER_PATH,
						View.contact,
						null,
						null,
						null
					);
				}
			}
		}
		catch (final ServiceException e) {
			ZimbraLog.extensions.error("There was an issue acquiring or creating the token storage folder.", e);
			throw new InvalidResponseException("There was an issue acquiring or creating the token storage folder.");
		}
		// return the now existing folder's id
		return folder.getId();
	}

	/**
	 * Updates a DataSource refresh token, or creates one if none exists for the specified username.
	 *
	 * @param mailbox The user's mailbox
	 * @param credentials Credentials containing the username and refreshToken
	 * @param folderId The folder to store the data source
	 * @throws InvalidResponseException If there are issues
	 */
	public void updateCredentials(ZMailbox mailbox, OAuthInfo credentials, String folderId) throws InvalidResponseException {
		ZDataSource osource = null;
		final String refreshToken = credentials.getRefreshToken();
		final String username = credentials.getUsername();
		// get datasource
		try {
			osource = mailbox.getDataSourceByName(username);
			// create new datasource if missing
			if (osource == null) {
				// ensure the specified storage folder exists, fetch/(create) default if not
				final String storageFolderId = getStorageFolderId(mailbox, folderId);
				osource = new ZDataSource(username, true);
				osource.setFolderId(storageFolderId);
				osource.setRefreshToken(refreshToken);
				osource.setHost(host);
				mailbox.createDataSource(osource);
			// or update the named credentials in datasource attribute
			} else {
				osource.setRefreshToken(refreshToken);
				mailbox.modifyDataSource(osource);
			}
		} catch (final ServiceException e) {
			ZimbraLog.extensions.error("There was an issue storing the oauth credentials.", e);
			throw new InvalidResponseException("There was an issue storing the oauth credentials.", e);
		}
	}

	/**
	 * Retrieves the refreshToken from DataSource. Returns null token if a source does not exist.
	 *
	 * @param mailbox The user's mailbox
	 * @param username The user to get refreshToken for
	 * @return RefreshToken for specified username
	 * @throws InvalidResponseException If there are issues
	 */
	public String getRefreshToken(ZMailbox mailbox, String username) throws InvalidResponseException {
		ZDataSource osource = null;
		String refreshToken = null;
		// get datasource
		try {
			osource = mailbox.getDataSourceByName(username);
			// get the refresh token if the source is available
			if (osource != null) {
				refreshToken = osource.getRefreshToken();
			}
		} catch (final ServiceException e) {
			ZimbraLog.extensions.error("There was an issue storing the oauth credentials.", e);
			throw new InvalidResponseException("There was an issue storing the oauth credentials.", e);
		}

		return refreshToken;
	}
}
