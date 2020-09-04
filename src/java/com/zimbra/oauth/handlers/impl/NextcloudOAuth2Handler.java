/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth2 Extension
 * Copyright (C) 2019-2020 Synacor, Inc.
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
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The NextcloudOAuth2Handler class.<br>
 * Nextcloud OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2019
 */
public class NextcloudOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

    private final static String ERROR_TEMPLATE = "%s | Nextcloud error code: %s | Reason: %s";

    /**
     * Contains error constants used in this implementation.
     */
    protected enum NextcloudErrorConstants {

        /**
         * Invalid request response code from Nextcloud.
         */
        RESPONSE_ERROR_INVALID_REQUEST("invalid_request"),

        /**
         * Default error.
         */
        DEFAULT_ERROR("internal_error");

        /**
         * The value of this enum.
         */
        private String constant;

        /**
         * @return The enum value
         */
        public String getValue() {
            return constant;
        }

        /**
         * @param constant The enum value to set
         */
        private NextcloudErrorConstants(String constant) {
            this.constant = constant;
        }

        /**
         * ValueOf wrapper for constants.
         *
         * @param code The code to check for
         * @return Enum instance
         */
        protected static NextcloudErrorConstants fromString(String code) {
            for (final NextcloudErrorConstants t : NextcloudErrorConstants.values()) {
                if (StringUtils.equals(t.getValue(), code)) {
                    return t;
                }
            }
            return DEFAULT_ERROR;
        }

    }

    /**
     * Contains oauth2 constants used in this implementation.
     */
    protected enum NextcloudOAuth2Constants {
        /**
         * The authorize endpoint for Nextcloud.
         */
        AUTHORIZE_URI_TEMPLATE("/apps/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=code"),

        /**
         * The authenticate endpoint for Nextcloud.
         */
        AUTHENTICATE_URI("/apps/oauth2/api/v1/token"),

        /**
         * Nextcloud does not implement scope, we use it to store additional configs for Nextcloud. For now only the base URL of the Nextcloud server.
         */
        REQUIRED_SCOPES(""),

        /**
         * The scope delimiter for Nextcloud.
         */
        SCOPE_DELIMITER(","),

        /**
         * The relay key for Nextcloud.
         */
        RELAY_KEY("state"),

        /**
         * The implementation name.
         */
        CLIENT_NAME("nextcloud"),

        /**
         * The implementation host.
         */
        HOST_NEXTCLOUD("nextcloud_dummy_host");

        /**
         * The value of this enum.
         */
        private String constant;

        /**
         * @return The enum value
         */
        public String getValue() {
            return constant;
        }

        /**
         * @param constant The enum value to set
         */
        private NextcloudOAuth2Constants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Constructs a NextcloudOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public NextcloudOAuth2Handler(Configuration config) {
        super(config, NextcloudOAuth2Constants.CLIENT_NAME.getValue(), NextcloudOAuth2Constants.HOST_NEXTCLOUD.getValue());
        authenticateUri = NextcloudOAuth2Constants.AUTHENTICATE_URI.getValue();
        authorizeUriTemplate = NextcloudOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        requiredScopes = NextcloudOAuth2Constants.REQUIRED_SCOPES.getValue();
        scopeDelimiter = NextcloudOAuth2Constants.SCOPE_DELIMITER.getValue();
        relayKey = NextcloudOAuth2Constants.RELAY_KEY.getValue();
    }

    @Override
    protected void setResponseParams(JsonNode tokenResponse, OAuthInfo oauthInfo) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("access_token", tokenResponse.get("access_token").asText());
        params.put("user_id", oauthInfo.getUsername());
        oauthInfo.setParams(params);
    }

    protected String getNextcloudURL(Account account) throws ServiceException {
        try {
            String nextcloudURL = config.getString(
                    String.format(OAuth2ConfigConstants.LC_OAUTH_SCOPE_TEMPLATE.getValue(), "nextcloud"),
                    "nextcloud_noop",
                    account);
            URL validNextcloudUrl = new URL(nextcloudURL);
            return validNextcloudUrl.toString();
        } catch (Exception e) {
            ZimbraLog.extensions.error(String.format(ERROR_TEMPLATE,
                    "Nextcloud base URL is not a valid URL. Configure zimbraOAuthConsumerAPIScope. Example: `zmprov md example.com zimbraOAuthConsumerAPIScope  'https://example.com/nextcloud/index.php:nextcloud_noop'`.",
                    null, e.toString()));
            return "";
        }
    }

    protected String getStorableRefreshToken(JsonNode credentials) {
        return credentials.get("refresh_token").asText();
    }

    @Override
    public JsonNode getToken(OAuthInfo authInfo, String basicToken) throws ServiceException {
        final String refreshToken = authInfo.getRefreshToken();
        final HttpPost request = new HttpPost(this.getNextcloudURL(authInfo.getAccount()) + authInfo.getTokenUrl());
        final List<NameValuePair> params = new ArrayList<NameValuePair>();
        if (!StringUtils.isEmpty(refreshToken)) {
            // set refresh token if we have one
            params.add(new BasicNameValuePair("grant_type", "refresh_token"));
            params.add(new BasicNameValuePair("refresh_token", refreshToken));
        } else {
            // otherwise use the code
            params.add(new BasicNameValuePair("grant_type", "authorization_code"));
            params.add(new BasicNameValuePair("code", authInfo.getParam("code")));
        }
        params.add(new BasicNameValuePair("redirect_uri", authInfo.getClientRedirectUri()));
        params.add(new BasicNameValuePair("client_secret", authInfo.getClientSecret()));
        params.add(new BasicNameValuePair("client_id", authInfo.getClientId()));
        setFormEntity(request, params);
        request.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
                "application/x-www-form-urlencoded");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
                "Basic " + basicToken);
        request.setHeader(OAuth2HttpConstants.HEADER_ACCEPT.getValue(), MediaType.APPLICATION_JSON);
        JsonNode json = null;
        try {
            json = executeRequestForJson(request);
            ZimbraLog.extensions.debug("Request for auth token completed.");
        } catch (final IOException e) {
            ZimbraLog.extensions
                    .errorQuietly("There was an issue acquiring the authorization token.", e);
            throw ServiceException
                    .PERM_DENIED("There was an issue acquiring an authorization token for this user.");
        }
        return json;
    }

    /**
     * Validates that the token response has no errors, and contains the
     * requested access information.
     *
     * @param response The json token response
     * @throws ServiceException<br> OPERATION_DENIED If the refresh token request was deemed invalid due
     *                              to inorrect request parameters (code, client id/secret, etc).<br>
     *                              PARSE_ERROR If the response from Nextcloud has no errors, but
     *                              the access info is missing.<br>
     *                              PERM_DENIED If the refresh token or code is expired, or for
     *                              general rejection.
     */
    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response.has("error")) {
            final String error = response.get("error").asText();
            String errorMsg = error;
            if (response.has("reason")) {
                errorMsg = response.get("reason").asText();
            }
            ZimbraLog.extensions.debug("Response from nextcloud: %s", response.asText());
            switch (NextcloudErrorConstants.fromString(StringUtils.lowerCase(error))) {
                case RESPONSE_ERROR_INVALID_REQUEST:
                    ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                            "Invalid oauth token request parameter(s) provided, check configuration.",
                            error, errorMsg));
                    throw ServiceException
                            .OPERATION_DENIED("Invalid oauth token request parameter(s) provided.");
                default:
                    ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                            "Unexpected error while trying to authenticate the user.", error, errorMsg));
                    throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
            }
        }

        // ensure the tokens we requested are present
        if (!response.has("access_token")) {
            throw ServiceException.PARSE_ERROR(
                    "Unexpected response from social service. Missing any of required params: access_token.",
                    null);
        }

    }

    /* Returns a unique identifier for the Nextcloud account, it is not an email address.
     * */
    @Override
    protected String getPrimaryEmail(JsonNode credentials, Account account)
            throws ServiceException {
        return credentials.get("user_id").toString().replace("\"", "");
    }

    /**
     * @see IOAuth2Handler#authorize(String, Account)
     */
    @Override
    public String authorize(Map<String, String> params, Account account) throws ServiceException {
        final String relay = StringUtils.defaultString(params.get(relayKey), "");
        final String type = StringUtils.defaultString(params.get(typeKey), "");
        final String jwt = StringUtils
                .defaultString(params.get(OAuth2HttpConstants.JWT_PARAM_KEY.getValue()), "");
        final String relayValue = buildStateString("&", relay, type, jwt);
        return buildAuthorizeUri(this.getNextcloudURL(account) + authorizeUriTemplate, account,
            type) + relayValue;
    }

    /**
     * @see IOAuth2Handler#authenticate(OAuthInfo)
     */
    @Override
    public Boolean authenticate(OAuthInfo oauthInfo) throws ServiceException {
        final Account account = oauthInfo.getAccount();
        loadClientConfig(account, oauthInfo);
        final String basicToken = OAuth2Utilities.encodeBasicHeader(
                oauthInfo.getClientId(), oauthInfo.getClientSecret());
        oauthInfo.setTokenUrl(authenticateUri);
        // request credentials from social service
        final JsonNode credentials = getToken(oauthInfo, basicToken);
        // ensure the response contains the necessary credentials
        validateTokenResponse(credentials);
        // determine account associated with credentials
        final String username = getPrimaryEmail(credentials, account);
        ZimbraLog.extensions.trace("Authentication performed for:" + username);

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken(), account);

        // store refreshToken
        oauthInfo.setUsername(username);
        oauthInfo.setRefreshToken(getStorableRefreshToken(credentials));
        dataSource.syncDatasource(mailbox, oauthInfo, getDatasourceCustomAttrs(oauthInfo));

        oauthInfo.setClientSecret(null);
        // allow clients to set response params
        setResponseParams(credentials, oauthInfo);

        return true;
    }

    /**
     * @see IOAuth2Handler#info(OAuthInfo)
     */
    @Override
    public Boolean info(OAuthInfo oauthInfo) throws ServiceException {
        // used to verify that the client id, client secret are configured
        final Account account = oauthInfo.getAccount();
        loadClientConfig(account, oauthInfo);
        oauthInfo.setClientSecret(null);

        // only these params will be returned to the client
        oauthInfo.setParams(Collections.singletonMap("nextcloud_url", this.getNextcloudURL(account)));
        return true;
    }

}
