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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.lang.StringUtils;

import com.zimbra.client.ZDataSource;
import com.zimbra.client.ZFolder;
import com.zimbra.client.ZFolder.View;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.Element;
import com.zimbra.common.soap.MailConstants;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
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
     * Ensures a folder of the name exists, creating one if necessary.<br>
     * Folder is created in user root, or real root if the View type is unknown
     * (for oauth2noop datasource).
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
        String parentId = ZFolder.ID_USER_ROOT;
        // use real root to hide the folder from view if this is a no-op datasource
        if (View.unknown.equals(type)) {
            parentId = ZFolder.ID_ROOT;
        }
        try {
            // create target folder, fetch if it exists
            ZimbraLog.extensions.debug("Creating oauth datasource folder: %s in parentId: %s", folderName, parentId);
            final Element req = mailbox.newRequestElement(MailConstants.CREATE_FOLDER_REQUEST);
            final Element folderEl = req.addUniqueElement(MailConstants.E_FOLDER);
            folderEl.addAttribute(MailConstants.A_NAME, folderName);
            folderEl.addAttribute(MailConstants.A_FOLDER, parentId);
            folderEl.addAttribute(MailConstants.A_DEFAULT_VIEW, type.name());
            folderEl.addAttribute(MailConstants.A_FETCH_IF_EXISTS, true);
            final Element newFolderEl = mailbox.invoke(req).getElement(MailConstants.E_FOLDER);
            // return target folder's id
            return newFolderEl.getAttribute(MailConstants.A_ID);
        } catch (final ServiceException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring or creating the datasource folder.", e);
            throw e;
        }
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
                .format(OAuth2Constants.DEFAULT_OAUTH_FOLDER_TEMPLATE.getValue(), username, type, client);
        try {
            // get datasource, create if missing
            ZDataSource osource = mailbox.getDataSourceByName(dsFolderName);
            if (osource == null) {
                final DataSourceType dsType = getDataSourceTypeForOAuth2(type);
                final View view = getViewForDataSource(dsType);
                // define the import class and polling interval
                // build up attributes
                ZimbraLog.extensions.debug("Building datasource of type: %s", dsType);
                final Map<String, Object> dsAttrs = new HashMap<String, Object>();
                if (importClassMap.containsKey(dsType.name())) {
                    ZimbraLog.extensions.debug("Setting datasource polling interval and import class.");
                    dsAttrs.put(Provisioning.A_zimbraDataSourceImportClassName,
                        importClassMap.get(dsType.name()));
                    dsAttrs.put(Provisioning.A_zimbraDataSourcePollingInterval,
                        OAuth2Constants.DATASOURCE_POLLING_INTERVAL.getValue());
                } else if (!DataSourceType.oauth2noop.equals(dsType)) {
                    ZimbraLog.extensions.error("Missing import class for %s datasource type",
                        dsType.name());
                    throw ServiceException.FAILURE(
                        "Missing import class for " + dsType.name() + " datasource type", null);
                }
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
                final DataSource source = prov.createDataSource(
                    prov.getAccountById(mailbox.getAccountId()), dsType, dsFolderName, dsAttrs);
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
     * @param identifier The user's social service identifier to get refreshToken for (email, id, etc)
     * @param type The datasource type
     * @return RefreshToken for specified username and type
     * @throws InvalidResponseException If there are issues
     */
    public String getRefreshToken(ZMailbox mailbox, String identifier, String type) throws ServiceException {
        ZDataSource osource = null;
        String refreshToken = null;
        final String dsFolderName = String
            .format(OAuth2Constants.DEFAULT_OAUTH_FOLDER_TEMPLATE.getValue(), identifier, type, client);
        // get datasource
        try {
            osource = mailbox.getDataSourceByName(dsFolderName);
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
                "Refresh token is not set for DataSource %s of Account %s. Cannot access API without a valid refresh token.",
                source.getName(), source.getAccountId()), null);
        }
        return refreshToken;
    }

    public Map<String, String> getRefreshTokens(Account account, String identifier, String type) throws ServiceException {
        final List<DataSource> datasources = new ArrayList<DataSource>();
        try {
            ZimbraLog.extensions.debug("Fetching datasources to find refresh token.");
            datasources.addAll(account.getAllDataSources().stream()
                .filter(s -> isDataSourceRelevant(s, identifier, type))
                .collect(Collectors.toList()));
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("Unable to retrieve datasources.", e);
            throw ServiceException.FAILURE("Unable to retrieve token data.", e);
        }
        if (datasources.size() < 1) {
            ZimbraLog.extensions.debug("No token found for: %s %s.", identifier, client);
            throw ServiceException
                .PERM_DENIED(String.format("No token found for: %s %s.", identifier, client));
        }
        final Map<String, String> tokens = new HashMap<String, String>();
        for (final DataSource source : datasources) {
            tokens.put(getIdentifier(source.getName(), type), source.getOauthRefreshToken());
        }
        return tokens;
    }

    protected String getIdentifier(String sourceName, String type) {
        return StringUtils.substringBeforeLast(sourceName, String.format("%s-%s", type, client));
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
        case "noop":
            dsType = DataSourceType.oauth2noop;
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
        case oauth2noop:
            view = View.unknown;
            break;
        default:
            ZimbraLog.extensions.error("Invalid type received");
            throw ServiceException.FAILURE("Invalid type received", null);
        }
        return view;
    }

    /**
     * Removes datasources relevant to the specified identifier.<br>
     * Null identifier will remove all datasources for the client.<br>
     * Note: this method does not delete the associated folder.
     *
     * @param account The target account
     * @param identifier The identifier to delete datasources for (optional)
     * @return True if there are no issues removing relevant datasources
     */
    public boolean removeDataSources(Account account, String identifier) {
        try {
            final Provisioning prov = Provisioning.getInstance();
            final List<DataSource> datasources = prov.getAllDataSources(account);
            for (final DataSource source : datasources) {
                // find the relevant datasources for this identifier + client, and purge
                if (isDataSourceRelevant(source, identifier)) {
                    prov.deleteDataSource(account, source.getId());
                }
            }
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("error deleting specified account's oauth datasources", e);
            return false;
        }
        return true;
    }

    /**
     * @see #isDataSourceRelevant(DataSource, String, String)
     */
    protected boolean isDataSourceRelevant(DataSource datasource, String identifier) {
        return isDataSourceRelevant(datasource, identifier, null);
    }

    /**
     * Determines if a datasource is oauth relevant for a given identifier, type, and client.<br>
     * Null identifier, or client will not be used to determine relevance.
     *
     * @param datasource The datasource to check
     * @param identifier The identifier to delete datasources for (optional)
     * @return True if the datasource is any oauth2 datasource for the identifier and client
     */
    protected boolean isDataSourceRelevant(DataSource datasource, String identifier, String type) {
        final String dsName = datasource.getName();
        // should have a refresh token
        return datasource.getOauthRefreshToken() != null
            // format: {identifier}-{type}-{client}
            && (identifier == null || StringUtils.startsWith(dsName, identifier))
            && (type == null || StringUtils.endsWith(dsName, String.format("%s-%s", type, client)))
            && StringUtils.endsWith(dsName, client);
    }
}
