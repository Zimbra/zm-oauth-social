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

package com.zimbra.oauth.handlers.impl;

import java.io.IOException;
import java.util.HashMap;

import org.apache.commons.lang.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.datasource.CalDavDataImport;
import com.zimbra.cs.dav.DavException;
import com.zimbra.cs.dav.client.CalDavClient;
import com.zimbra.oauth.handlers.impl.GoogleOAuth2Handler.GoogleConstants;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.CalDavOAuth2Client;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.LdapConfiguration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2Utilities;
import com.zimbra.oauth.utilities.OAuth2DataSource;

public class CalDavOAuth2DataImport extends CalDavDataImport {

    private Configuration config;

    public CalDavOAuth2DataImport(DataSource ds) throws ServiceException {
        super(ds);
        try {
            config = LdapConfiguration.buildConfiguration(GoogleConstants.CLIENT_NAME);
        } catch (final ServiceException e) {
            ZimbraLog.extensions.info("Error loading configuration for google caldav: %s", e.getMessage());
            ZimbraLog.extensions.debug(e);
        }
    }

    /**
     * Initialize the dav client and refresh the access token
     */
    protected CalDavClient getClient() throws ServiceException, IOException, DavException {
        if (mClient == null) {
            mClient = new CalDavOAuth2Client(getTargetUrl());
            mClient.setAppName(getAppName());
            mClient.setDebugEnabled(dataSource.isDebugTraceEnabled());
            mClient.setAccessToken(refresh());
            mClient.login(getDefaultPrincipalUrl());
        }
        mClient.setAccessToken(refresh());
        return mClient;
    }

    /**
     * Retrieves the Google user accessToken.
     *
     * @return accessToken A live access token
     * @throws ServiceException If there are issues
     */
    protected String refresh() throws ServiceException {
        final Account acct = dataSource.getAccount();
        final OAuthInfo oauthInfo = new OAuthInfo(new HashMap<String, String>());
        final String refreshToken = OAuth2DataSource.getRefreshToken(dataSource);
        final String clientId = config.getString(String
            .format(OAuth2Constants.LC_OAUTH_CLIENT_ID_TEMPLATE, GoogleConstants.CLIENT_NAME), GoogleConstants.CLIENT_NAME, acct);
        final String clientSecret = config.getString(String
            .format(OAuth2Constants.LC_OAUTH_CLIENT_SECRET_TEMPLATE, GoogleConstants.CLIENT_NAME), GoogleConstants.CLIENT_NAME,  acct);
        final String clientRedirectUri = config.getString(String.format(
            OAuth2Constants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE, GoogleConstants.CLIENT_NAME), GoogleConstants.CLIENT_NAME, acct);

        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(clientSecret)
            || StringUtils.isEmpty(clientRedirectUri)) {
            throw ServiceException.FAILURE("Required config(id, secret and redirectUri) parameters are not provided.", null);
        }
        // set client specific properties
        oauthInfo.setRefreshToken(refreshToken);
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setClientRedirectUri(clientRedirectUri);
        oauthInfo.setTokenUrl(GoogleConstants.AUTHENTICATE_URI);

        ZimbraLog.extensions.debug("Fetching access credentials for import.");
        final JsonNode credentials = GoogleOAuth2Handler.getTokenRequest(oauthInfo,
            OAuth2Utilities.encodeBasicHeader(clientId, clientSecret));

        return credentials.get("access_token").asText();
    }
}
