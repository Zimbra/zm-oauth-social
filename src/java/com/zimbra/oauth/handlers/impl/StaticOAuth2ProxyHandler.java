/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth Social Extension
 * Copyright (C) 2019 Synacor, Inc.
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

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2ProxyHandler;
import com.zimbra.oauth.utilities.LdapConfiguration;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The StaticOAuth2ProxyHandler class.<br>
 * Handles token fetching for clients with predetermined credentials.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2019
 */
public abstract class StaticOAuth2ProxyHandler implements IOAuth2ProxyHandler {

    @Override
    public Map<String, String> headers(Map<String, String> params, Account account) throws ServiceException {
        final String client = params.get("client");
        final String credentialsString = LdapConfiguration.getFirstConfig(
            OAuth2ConfigConstants.OAUTH_STATIC_CREDENTIALS.getValue(), client, account);
        // credentials may vary in 3 parts:
        // {account}:{apiToken}:{client}
        // :{bearer token}:{client}
        // . . .
        if (credentialsString != null) {
            final String[] credentials = credentialsString.split(":");
            if (credentials.length == 3) {
                return ImmutableMap.of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
                    buildAuthorizationHeader(credentials, client));
            }
        }
        ZimbraLog.extensions.debug("No valid credentials found for the client %s.", client);
        throw ServiceException.PERM_DENIED("No valid credentials found for the client.");
    }

    @Override
    public abstract boolean isProxyRequestAllowed(String client, String method, String path,
        InputStream body);

    @Override
    public List<String> getHeadersParamKeys() {
        return ImmutableList.of("target");
    }

    /**
     * @param credentials The credentials to build auth header from
     * @param client The client (may contain details on the type of token)
     * @return The Authorization header value
     */
    protected String buildAuthorizationHeader(String[] credentials, String client) {
        String header = "";
        switch(getTokenType(client)) {
        case "basic":
            header = String.format(
                "Basic %s",
                OAuth2Utilities.encodeBasicHeader(credentials[0], credentials[1]));
            break;
        case "bearer":
            header = String.format(
                "Bearer %s", credentials[1]);
            break;
        default:
            header = credentials[1];
        }
        return header;
    }

    /**
     * @param client The client (may contain details on the type of token)
     * @return The type of token - if specified
     */
    protected String getTokenType(String client) {
        final String[] clientParts = client.split("-");
        if (clientParts.length < 3) {
            return "";
        }
        return clientParts[1];
    }

}
