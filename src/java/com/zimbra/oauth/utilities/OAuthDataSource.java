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
package com.zimbra.oauth.utilities;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import com.zimbra.client.ZDataSource;
import com.zimbra.client.ZFolder;
import com.zimbra.client.ZFolder.View;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.DataSource;
import com.zimbra.oauth.models.OAuthInfo;

/**
 * The OAuthDataSource class.<br>
 * ZDataSource wrapper for storing oauth credentials.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public class OAuthDataSource {

    /**
     * The client that owns this source.
     */
    protected final String client;

    /**
     * The host identifier for this source.
     */
    protected final String host;

    /**
     * Import `type` to `className` mapping.
     */
    protected final Map<String, String> importClassMap = new HashMap<String, String>();

    /**
     * Constructor.
     *
     * @param client A client
     * @param host A host
     */
    protected OAuthDataSource(String client, String host) {
        this.client = client;
        this.host = host;
    }

    /**
     * Returns a new handler for a Zimbra DataSource.
     *
     * @param client The client this source is for
     * @param host The host this source is for
     * @return OAuthDataSource handler instance
     */
    public static OAuthDataSource createDataSource(String client, String host) {
        return new OAuthDataSource(client, host);
    }

    /**
     * Ensures a folder of the name exists, creating one if necessary.
     *
     * @param mailbox The mailbox to check
     * @param folderName The folder name
     * @param type The type of folder to create (appointment, contact, etc)
     * @return Id of existing folder
     * @throws InvalidResponseException If there are issues acquiring/creating
     *             the folder
     */
    protected String ensureFolder(ZMailbox mailbox, String folderName, View type)
        throws ServiceException {
        ZFolder folder = null;
        try {
            // find target folder
            folder = mailbox.getFolderByPath(ZMailbox.PATH_SEPARATOR + folderName);
            // create target folder if it does not exist
            if (folder == null) {
                ZimbraLog.extensions.debug("Creating oauth datasource folder : " + folderName);
                folder = mailbox.createFolder(ZFolder.ID_USER_ROOT, folderName, type, null, null,
                    null);
            }
        } catch (final ServiceException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring or creating the datasource folder.", e);
            throw e;
        }
        // return target folder's id
        return folder.getId();
    }

    /**
     * Updates a DataSource refresh token, or creates one if none exists for the
     * specified username. Triggers the data sync if the importClass is defined.
     *
     * @param mailbox The user's mailbox
     * @param credentials Credentials containing the username, and refreshToken
     * @throws InvalidResponseException If there are issues
     */
    public void syncDatasource(ZMailbox mailbox, OAuthInfo credentials) throws ServiceException {
        final String username = credentials.getUsername();
        final String refreshToken = credentials.getRefreshToken();
        final String folderName = String.format(OAuth2Constants.DEFAULT_OAUTH_FOLDER_TEMPLATE,
            username, client);
        try {
            // get datasource, create if missing
            ZDataSource osource = mailbox.getDataSourceByName(username);
            if (osource == null) {
                // ensure the specified storage folder exists
                final String storageFolderId = ensureFolder(mailbox, folderName, View.contact);
                osource = new ZDataSource(username, true);
                osource.setFolderId(storageFolderId);
                osource.setRefreshToken(refreshToken);
                osource.setHost(host);
                // set the import class if one exists for this client and type
                if (importClassMap.containsKey(View.contact.name())) {
                    osource.setImportClass(importClassMap.get(View.contact.name()));
                }
                final String id = mailbox.createDataSource(osource);
                // define id on the source so import is possible
                osource.setId(id);
                // or update the named credentials in datasource attribute
            } else {
                osource.setRefreshToken(refreshToken);
                mailbox.modifyDataSource(osource);
            }
            // trigger import if class is set
            if (!StringUtils.isEmpty(osource.getImportClass())) {
                mailbox.importData(Arrays.asList(osource));
            }
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly(
                "There was an issue storing the credentials, or triggering the data import.", e);
            throw e;
        }
    }

    /**
     * Retrieves the refreshToken from DataSource. Returns null token if a
     * source does not exist.
     *
     * @param mailbox The user's mailbox
     * @param username The user to get refreshToken for
     * @return RefreshToken for specified username
     * @throws InvalidResponseException If there are issues
     */
    public String getRefreshToken(ZMailbox mailbox, String username) throws ServiceException {
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
            ZimbraLog.extensions.errorQuietly("There was an issue storing the oauth credentials.",
                e);
            throw e;
        }

        return refreshToken;
    }

    public static String getRefreshToken(DataSource source) throws ServiceException {
        final String refreshToken = source.getOauthRefreshToken();
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw ServiceException.FAILURE(String.format(
                "Refresh token is not set for DataSource %s of Account %s. Cannot access Yahoo API without a valid refresh token.",
                source.getName(), source.getAccountId()), null);
        }
        return refreshToken;
    }

    /**
     * Adds an import class to the mapping.
     *
     * @param type The type of View associated with the mapping.
     * @param className The import class canonical name
     */
    public void addImportClass(String type, String className) {
        importClassMap.put(type, className);
    }
}
