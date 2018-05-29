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
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * The FacebookOAuth2Handler class.<br>
 * Facebook OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class FacebookOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

  /**
   * Contains the constants used in this implementation.
   */
  protected class FacebookConstants {

    /**
     * Invalid request error from Facebook.<br>
     * Protocol error, such as a invalid or missing required parameter.
     */
    protected static final String RESPONSE_ERROR_INVALID_CODE = "100";

    /**
     * API Session.<br>
     * The login status or access token has expired,<br>
     * been revoked, or is otherwise invalid.
     */
    protected static final String RESPONSE_ERROR_SESSION_EXPIRED = "102";

    /**
     * API Unknown.<br>
     * Possibly a temporary issue due to downtime.<br>
     * Wait and retry the operation.<br>
     * If it occurs again, check you are requesting an existing API.
     */
    protected static final String RESPONSE_ERROR_API_UNKNOWN = "1";

    /**
     * API Service.<br>
     * Temporary issue due to downtime. Wait and retry the operation.
     */
    protected static final String RESPONSE_ERROR_API_SERVICE = "2";

    /**
     * API Too Many Calls.<br>
     * Temporary issue due to throttling.<br>
     * Wait and retry the operation, or examine your API request volume.
     */
    protected static final String RESPONSE_ERROR_EXCESSIVE_CALLS = "4";

    /**
     * API User Too Many Calls.<br>
     * Temporary issue due to throttling.<br>
     * Wait and retry the operation, or examine your API request volume.
     */
    protected static final String RESPONSE_ERROR_USER_EXCESSIVE_CALLS = "17";

    /**
     * API Permission Denied.<br>
     * Permission is either not granted or has been removed.
     */
    protected static final String RESPONSE_ERROR_PERM_DENIED = "10";

    /**
     * Access token has expired.<br>
     * Expired access token.
     */
    protected static final String RESPONSE_ERROR_TOKEN_EXPIRED = "190";

    /**
     * API Permission.<br>
     * Permission is either not granted or has been removed.
     */
    protected static final String RESPONSE_ERROR_PERMISSIONS_ERROR = "200-299";

    /**
     * Application limit reached.<br>
     * Temporary issue due to downtime or throttling.<br>
     * Wait and retry the operation, or examine your API request volume.
     */
    protected static final String RESPONSE_ERROR_LIMIT_REACHED = "341";

    /**
     * Temporarily blocked for policies violations.<br>
     * Wait and retry the operation.
     */
    protected static final String RESPONSE_ERROR_POLICIES_VIOLATION = "368";

    /**
     * Too many requests.<br>
     * Picture profile URL rate-limit reached. Wait and retry the operation.
     */
    protected static final String RESPONSE_ERROR_TOO_MANY_REQUESTS = "429";

    /**
     * The authorize uri template for Facebook.
     */
    protected static final String AUTHORIZE_URI_TEMPLATE = "https://www.facebook.com/v3.0/dialog/oauth?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s";

    /**
     * The debug token uri, used to fetch the user_id from Facebook.
     */
    public static final String DEBUG_TOKEN_URI = "https://graph.facebook.com/debug_token";

    /**
     * The uri used to make backend call to fetch an access token.
     */
    public static final String AUTHENTICATE_URI = "https://graph.facebook.com/v3.0/oauth/access_token";

    /**
     * The scope required for Facebook.
     */
    protected static final String REQUIRED_SCOPES = "email";

    /**
     * The state parameter.
     */
    public static final String RELAY_KEY = "state";

    /**
     * The implementation name.
     */
    public static final String CLIENT_NAME = "facebook";

    /**
     * The implementation host.
     */
    public static final String HOST_FACEBOOK = "graph.facebook.com";

  }
  /**
   * Constructs an FacebookOAuth2Handler object.
   *
   * @param config For accessing configured properties
   */

  public FacebookOAuth2Handler(Configuration config) {
    super(config, FacebookConstants.CLIENT_NAME, FacebookConstants.HOST_FACEBOOK);
    scope = StringUtils.join(
      new String[] { FacebookConstants.REQUIRED_SCOPES, config.getString(String
          .format(OAuth2Constants.LC_OAUTH_SCOPE_TEMPLATE, FacebookConstants.CLIENT_NAME)) },
      "+");
    authenticateUri = FacebookConstants.AUTHENTICATE_URI;
    authorizeUri = buildAuthorizeUri(FacebookConstants.AUTHORIZE_URI_TEMPLATE);
    relayKey = FacebookConstants.RELAY_KEY;
  }

  /**
   * Facebook authenticate handler.
   *
   * @see IOAuth2Handler#authenticate(OAuthInfo)
   */
  @Override
  public Boolean authenticate(OAuthInfo oauthInfo) throws ServiceException {
    // set client specific properties
    oauthInfo.setClientId(clientId);
    oauthInfo.setClientSecret(clientSecret);
    oauthInfo.setClientRedirectUri(clientRedirectUri);
    oauthInfo.setTokenUrl(authenticateUri);
    // request credentials from social service
    final JsonNode credentials = getTokenRequest(oauthInfo, basicToken);
    // ensure the response contains the necessary credentials
    validateTokenResponse(credentials);
    // determine account associated with credentials
    final String username = getPrimaryEmail(credentials);
    ZimbraLog.extensions.trace("Authentication performed for:" + username);

    // get zimbra mailbox
    final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken());

    // store refreshToken
    oauthInfo.setUsername(username);
    oauthInfo.setRefreshToken(credentials.get("access_token").asText());
    dataSource.syncDatasource(mailbox, oauthInfo);
    return true;
  }

  /**
   * Validates that the response from authenticate has no errors, and contains
   * the requested access information.
   *
   * @param response The json response from authenticate
   * @throws ServiceException
   *             OPERATION_DENIED If the refresh token was deemed invalid, or
   *             incorrect redirect uri.<br>
   *             If the client id or client secret are incorrect.<br>
   *             PARSE_ERROR If the response from Google has no errors, but
   *             the access info is missing.<br>
   *             PERM_DENIED If the refresh token or code is expired, or for
   *             general rejection.<br>
   *             INVALID_REQUEST If the request parameters are invalid.<br>
   *             TEMPORARILY_UNAVAILABLE If there was an issue with the FB OAuth server.
   */
  @Override
  protected void validateTokenResponse(JsonNode response) throws ServiceException {
    // check for errors
    if (response.has("error")) {
      final JsonNode errorDetails = response.get("error");
      String errorCode = errorDetails.get("code").asText();
      final String errorMsg = errorDetails.get("message").asText();

      errorCode = inErrorCodeRange(errorCode);

      switch (errorCode) {
        case FacebookConstants.RESPONSE_ERROR_INVALID_CODE:
          ZimbraLog.extensions.debug("Invalid request error from Facebook: " + errorMsg);
          throw ServiceException.INVALID_REQUEST("The authentication "
             + "request parameters are invalid.", null);
        case FacebookConstants.RESPONSE_ERROR_SESSION_EXPIRED:
          ZimbraLog.extensions.debug("API Session error: " + errorMsg);
          throw ServiceException.OPERATION_DENIED("The login status or "
            + "access token has expired, been revoked, or is otherwise invalid.");
        case FacebookConstants.RESPONSE_ERROR_API_UNKNOWN:
          ZimbraLog.extensions.debug("API Unknown: " + errorMsg);
          throw ServiceException.OPERATION_DENIED("API Unknown. Possibly a temporary "
            + "issue due to downtime. If it occurs again, check you are requesting an "
            + "existing API.");
        case FacebookConstants.RESPONSE_ERROR_API_SERVICE:
          ZimbraLog.extensions.debug("API Service issue: " + errorMsg);
          throw ServiceException.TEMPORARILY_UNAVAILABLE();
        case FacebookConstants.RESPONSE_ERROR_EXCESSIVE_CALLS:
          ZimbraLog.extensions.debug("Too Many Calls: " + errorMsg);
          throw ServiceException.TEMPORARILY_UNAVAILABLE();
        case FacebookConstants.RESPONSE_ERROR_USER_EXCESSIVE_CALLS:
          ZimbraLog.extensions.debug("User, Too Many Calls: " + errorMsg);
          throw ServiceException.TEMPORARILY_UNAVAILABLE();
        case FacebookConstants.RESPONSE_ERROR_TOKEN_EXPIRED:
          ZimbraLog.extensions.debug("Access token has expired: " + errorMsg);
          throw ServiceException.OPERATION_DENIED("Expired access token.");
        case FacebookConstants.RESPONSE_ERROR_PERM_DENIED:
        case FacebookConstants.RESPONSE_ERROR_PERMISSIONS_ERROR:
          ZimbraLog.extensions.debug("API Permissions issue: " + errorMsg);
          throw ServiceException.PERM_DENIED("Permission is either not granted or has "
            + "been removed.");
        case FacebookConstants.RESPONSE_ERROR_LIMIT_REACHED:
          ZimbraLog.extensions.debug("Application limit reached: " + errorMsg);
          throw ServiceException.TEMPORARILY_UNAVAILABLE();
        case FacebookConstants.RESPONSE_ERROR_POLICIES_VIOLATION:
          ZimbraLog.extensions.debug("Temporarily blocked for policies violations: " + errorMsg);
          throw ServiceException.TEMPORARILY_UNAVAILABLE();
        case FacebookConstants.RESPONSE_ERROR_TOO_MANY_REQUESTS:
          ZimbraLog.extensions.debug("Too many requests: " + errorMsg);
          throw ServiceException.TEMPORARILY_UNAVAILABLE();
        default:
          ZimbraLog.extensions.warn("Unexpected error while trying to authenticate "
              + "the user." + response.toString());
          throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
      }
    }
  }

  /**
   * Check code and return range which is listed in the FacebookConstants class.<br>
   * See Facebook error code range for Permission denied errors<br>
   * https://developers.facebook.com/docs/graph-api/using-graph-api/error-handling
   *
   * @param errorCode An error code from value
   * @return The Range that matches the error type
   */
  protected String inErrorCodeRange(String errorCode) {
    if (!errorCode.isEmpty()) {
      final Integer errorCodeInt = Integer.getInteger(errorCode);
      if (errorCodeInt >= 200 && errorCodeInt <= 299) {
        errorCode = "200-299";
      }
    }
    return errorCode;
  }

  /**
   * Retrieves the primary email of the user with the access_token and auth
   * token.
   *
   * @param credentials The json containing an access_token
   * @return The unique user ID
   * @throws ServiceException If there are issues determining the primary address
   */
  @Override
  protected String getPrimaryEmail(JsonNode credentials) throws ServiceException {
    JsonNode json = null;
    final String authToken = credentials.get("access_token").asText();
    String queryString;
    try {
      queryString = "?input_token=" + authToken + "&access_token="
          + URLEncoder.encode(getAppToken(), OAuth2Constants.ENCODING);
    } catch (final UnsupportedEncodingException e) {
      throw ServiceException.PARSE_ERROR("Url encoding the social service app token failed.", e);
    }

    try {
      final GetMethod request = new GetMethod(FacebookConstants.DEBUG_TOKEN_URI);
      request.setQueryString(queryString);
      json = executeRequestForJson(request);
    } catch (final IOException e) {
      ZimbraLog.extensions.warnQuietly("There was an issue acquiring the account details.", e);
      throw ServiceException.FAILURE("There was an issue acquiring the account details.", null);
    }
    final String userId = json.get("data").get("user_id").asText();
    if (userId.isEmpty()) {
      ZimbraLog.extensions.warn("The user id could not be retrieved from the social service api.");
      ZimbraLog.extensions.trace(json.toString());
      throw ServiceException.UNSUPPORTED();
    }

    return userId;
  }

  /**
   * Retrieves the App Token.
   *
   * @return The Facebook App token
   * @throws ServiceException If there was an issue with the request
   * @throws GenericOAuthException If there are issues acquiring the user id
   */
  protected String getAppToken() throws ServiceException {
    JsonNode json = null;
    final String url = FacebookConstants.AUTHENTICATE_URI;
    final String queryString = "?client_id=" + this.clientId + "&client_secret="
        + this.clientSecret + "&grant_type=client_credentials";
    try {
      final GetMethod request = new GetMethod(url);
      request.setQueryString(queryString);
      json = executeRequestForJson(request);
    } catch (final IOException e) {
      ZimbraLog.extensions.warnQuietly("There was an issue acquiring the social service app access token.", e);
      throw ServiceException.FAILURE("There was an issue acquiring the social service app access token.", null);
    }

    final String appAccessToken = json.get("access_token").asText();
    if (appAccessToken.isEmpty()) {
      ZimbraLog.extensions.warn("Unable to retrieve app token from social service api.");
      ZimbraLog.extensions.trace(json.toString());
      throw ServiceException.UNSUPPORTED();
    }
    return appAccessToken;
  }
}