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
import com.zimbra.cs.account.Provisioning;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.soap.admin.type.DataSourceType;

/**
 * The OAuthDataSource class.<br>
 * ZDataSource wrapper for storing oauth credentials.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public class OAuth2DataSource {

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
    protected OAuth2DataSource(String client, String host) {
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
    public static OAuth2DataSource createDataSource(String client, String host) {
        return new OAuth2DataSource(client, host);
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
    public void syncDatasource(ZMailbox mailbox, OAuthInfo credentials, Map <String, Object> dsCustomAttrs) throws ServiceException {
        final String username = credentials.getUsername();
        final String refreshToken = credentials.getRefreshToken();
        final String type = credentials.getParam("type");
        final String dsFolderName = String
                .format(OAuth2Constants.DEFAULT_OAUTH_FOLDER_TEMPLATE, username, type);
        try {
            // get datasource, create if missing
            ZDataSource osource = mailbox.getDataSourceByName(dsFolderName);
            if (osource == null) {
                DataSourceType dsType = getDataSourceTypeForOAuth2(type);
                View view = getViewForDataSource(dsType);
                // define the import class and polling interval
                ZimbraLog.extensions.debug("Setting datasource polling interval and import class.");
                // build up attributes
                final Map<String, Object> dsAttrs = new HashMap<String, Object>();
                if (importClassMap.containsKey(dsType.name())) {
                    dsAttrs.put(Provisioning.A_zimbraDataSourceImportClassName, importClassMap.get(dsType.name()));
                } else {
                    ZimbraLog.extensions.error("Missing import class for %s datasource type", dsType.name());
                    throw ServiceException.FAILURE("Missing import class for " + dsType.name() + " datasource type", null);
                }

                dsAttrs.put(Provisioning.A_zimbraDataSourcePollingInterval, OAuth2Constants.DATASOURCE_POLLING_INTERVAL);
                dsAttrs.put(Provisioning.A_zimbraDataSourceEnabled, "TRUE");
                dsAttrs.put(Provisioning.A_zimbraDataSourceConnectionType, "cleartext");
                dsAttrs.put(Provisioning.A_zimbraDataSourceOAuthRefreshToken, refreshToken);
                dsAttrs.put(Provisioning.A_zimbraDataSourceHost, host);
                dsAttrs.put(Provisioning.A_zimbraDataSourceImportOnly, "FALSE");

                // ensure the specified storage folder exists
                final String storageFolderId = ensureFolder(mailbox, dsFolderName, view);
                dsAttrs.put(Provisioning.A_zimbraDataSourceFolderId, storageFolderId);

                if (dsCustomAttrs != null) {
                    dsAttrs.putAll(dsCustomAttrs);
                }
                // create the new datasource
                ZimbraLog.extensions.debug("Creating new datasource.");
                final Provisioning prov = Provisioning.getInstance();
                final DataSource source = prov.createDataSource(prov.getAccountById(mailbox.getAccountId()), dsType,
                        dsFolderName, dsAttrs);
                // fetch as ZDataSource so we can trigger it
                osource = mailbox.getDataSourceById(source.getId());
            } else {
                osource.setRefreshToken(refreshToken);
                mailbox.modifyDataSource(osource);
            }
            if (!StringUtils.isEmpty(osource.getImportClass())) {
                // trigger import once if data import class is set
                ZimbraLog.extensions.debug("Triggering data import.");
                mailbox.importData(Arrays.asList(osource));
            }
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly(
                "There was an issue storing the credentials, or triggering the data import.", e);
            throw ServiceException.FAILURE("There was an issue storing the credentials, or triggering the data import.", e);
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

    /**
     * map type sent in authorize request to appropriate data source type
     * @param type
     * @return
     * @throws ServiceException
     */
    public static DataSourceType getDataSourceTypeForOAuth2(String type) throws ServiceException {
        DataSourceType dsType = null;
        switch (type) {
        case "contact":
            dsType = DataSourceType.oauth2contact;
            break;
        case "calendar":
            dsType = DataSourceType.oauth2calendar;
            break;
        case "caldav":
            dsType = DataSourceType.oauth2caldav;
            break;
        default:
            ZimbraLog.extensions.error("Invalid type: %s", type);
            throw ServiceException.FAILURE("Invalid type: " + type, null);
        }
        return dsType;
    }

    /**
     * return folder view as per data source type
     * @param type
     * @return
     * @throws ServiceException
     */
    public static View getViewForDataSource(DataSourceType type) throws ServiceException {
        View view = null;
        switch (type) {
        case oauth2contact:
            view = View.contact;
            break;
        case oauth2calendar:
            view = View.appointment;
            break;
        case oauth2caldav:
            view = View.appointment;
            break;
        default:
            ZimbraLog.extensions.error("Invalid type received");
            throw ServiceException.FAILURE("Invalid type received", null);
        }
        return view;
    }
}
