/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth2 Extension
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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.HttpResponseWrapper;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2ErrorConstants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2Utilities;
import com.zimbra.soap.admin.type.DataSourceType;

/**
 * The TwitterOAuth2Handler class.<br>
 * Twitter OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class TwitterOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

    /**
     * Contains error constants used in this implementation.
     */
    protected enum TwitterErrorConstants {
        /**
         * Rate limit error from Twitter.<br>
         * The service has surpassed the rate limit for the current window.
         */
        RESPONSE_ERROR_RATE_LIMIT_EXCEEDED("88"),

        /**
         * Insufficient privileges error from Twitter.<br>
         * Insufficient privileges were provided for the specified resource.
         */
        RESPONSE_ERROR_CLIENT_NOT_PERMITTED("87"),
        RESPONSE_ERROR_INSUFFICIENT_PRIVILEGES("220"),

        /**
         * Access denied error from Twitter.<br>
         * Could not authenticate the user.
         */
        RESPONSE_ERROR_COULD_NOT_AUTHENTICATE("32"),
        RESPONSE_ERROR_INVALID_TOKEN("89"),
        RESPONSE_ERROR_BAD_CREDENTIALS("99"),
        RESPONSE_ERROR_BAD_TIMESTAMP("135"),
        RESPONSE_ERROR_BAD_AUTH_DATA("215"),

        /**
         * Bad callback error from twitter.<br>
         * The callback is invalid or not approved for this service.
         */
        RESPONSER_ERROR_BAD_CALLBACK("415"),

        /**
         * Server error from Twitter.<br>
         * The server encountered an unexpected error.
         */
        RESPONSE_ERROR_SERVER_ERROR("131"),

        /**
         * Resource unavailable from Twitter.<br>
         * The service endpoint has been retired and should not be used.
         */
        RESPONSE_ERROR_ENDPOINT_RETIRED("251"),

        /**
         * Invalid client error from Twitter.<br>
         * The zm-oauth client credentials are not valid.
         */
        RESPONSE_ERROR_INVALID_CLIENT("416"),

        /**
         * Default error.
         */
        DEFAULT_ERROR("DEFAULT_ERROR");

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
        TwitterErrorConstants(String constant) {
            this.constant = constant;
        }

        /**
         * ValueOf wrapper for constants.
         *
         * @param code The code to check for
         * @return Enum instance
         */
        protected static TwitterErrorConstants fromString(String code) {
            for (final TwitterErrorConstants t : TwitterErrorConstants.values()) {
                if (StringUtils.equals(t.getValue(), code)) {
                    return t;
                }
            }
            return DEFAULT_ERROR;
        }
    }

    /**
     * Contains contact constants used in this implementation.
     */
    protected enum TwitterContactConstants {

        /**
         * The contacts endpoint for Twitter.
         */
        CONTACTS_URI("https://api.twitter.com/1.1/friends/list.json"),

        /**
         * The contacts pagination size for Twitter.
         */
        CONTACTS_PAGE_SIZE("100"),

        /**
         * The contact identifier key for Twitter.
         */
        CONTACT_ID("TwitterId");

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
        TwitterContactConstants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Contains oauth constants used in this implementation.
     */
    protected enum TwitterOAuth2Constants {

        /**
         * The authorize token endpoint for Twitter.
         */
        AUTHORIZE_TOKEN_URI("https://api.twitter.com/oauth/request_token"),

        /**
         * The authorize endpoint for Twitter.
         */
        AUTHORIZE_URI_TEMPLATE("https://api.twitter.com/oauth/authorize?oauth_token=%s"),

        /**
         * The authenticate endpoint for Twitter.
         */
        AUTHENTICATE_URI("https://api.twitter.com/oauth/access_token"),

        /**
         * The token split key.
         */
        TOKEN_DELIMITER("::"),

        /**
         * The relay key for Twitter.
         */
        RELAY_KEY("state"),

        /**
         * The implementation name.
         */
        CLIENT_NAME("twitter"),

        /**
         * The implementation host.
         */
        HOST_TWITTER("api.twitter.com");

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
        TwitterOAuth2Constants(String constant) {
            this.constant = constant;
        }
    }

    /**
     * Constructs a TwitterOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public TwitterOAuth2Handler(Configuration config) {
        super(config, TwitterOAuth2Constants.CLIENT_NAME.getValue(),
            TwitterOAuth2Constants.HOST_TWITTER.getValue());
        authenticateUri = TwitterOAuth2Constants.AUTHENTICATE_URI.getValue();
        authorizeUriTemplate = TwitterOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        relayKey = TwitterOAuth2Constants.RELAY_KEY.getValue();
        dataSource.addImportClass(DataSourceType.oauth2contact.name(),
            TwitterContactsImport.class.getCanonicalName());
    }

    @Override
    public String authorize(Map<String, String> params, Account account) throws ServiceException {
        final String relay = StringUtils.defaultString(params.get(relayKey), "");
        final String type = StringUtils.defaultString(params.get(typeKey), "");
        final String jwt = StringUtils
            .defaultString(params.get(OAuth2HttpConstants.JWT_PARAM_KEY.getValue()), "");
        final String stateValue = buildStateString("?", relay, type, jwt);

        final String authorizeTokensRaw = authorizeRequest(account, stateValue);

        final Map<String, String> response = splitToMap(authorizeTokensRaw);

        // make sure token and secret are not empty
        // make sure the callback exists and is confirmed
        final String authorizeToken = response.get("oauth_token");
        final String secret = response.get("oauth_token_secret");
        final String isConfirmed = response.get("oauth_callback_confirmed");
        if (StringUtils.isEmpty(authorizeToken) || StringUtils.isEmpty(secret)
            || !StringUtils.equalsIgnoreCase(isConfirmed, "true")) {
            ZimbraLog.extensions.error("Unexpected authorize response from Twitter.");
            throw ServiceException.PARSE_ERROR("Unexpected authorize response from Twitter.", null);
        }

        return String.format(authorizeUriTemplate, authorizeToken);
    }

    @Override
    public Boolean authenticate(OAuthInfo oauthInfo) throws ServiceException {
        // fetch client config
        final Account account = oauthInfo.getAccount();
        loadClientConfig(account, oauthInfo);
        final String clientId = oauthInfo.getClientId();
        final String clientSecret = oauthInfo.getClientSecret();
        // build auth header
        final String authorizationHeader = new TwitterAuthorizationBuilder(clientId, clientSecret)
            .withMethod("POST")
            .withEndpoint(TwitterOAuth2Constants.AUTHENTICATE_URI.getValue())
            .withToken(oauthInfo.getParam("oauth_token"))
            .build();
        oauthInfo.setTokenUrl(authenticateUri);
        // request credentials from Twitter then ensure what we need exists
        final Map<String, String> credentials = getTokenRequestMap(oauthInfo, authorizationHeader);
        final String authToken = credentials.get("oauth_token");
        final String tokenSecret = credentials.get("oauth_token_secret");
        final String screenName = credentials.get("screen_name");
        if (StringUtils.isEmpty(authToken) || StringUtils.isEmpty(tokenSecret)
            || StringUtils.isEmpty(screenName)) {
            ZimbraLog.extensions.error("Unexpected authenticate response from Twitter.");
            throw ServiceException.PARSE_ERROR("Unexpected authenticate response from Twitter.", null);
        }

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken(), account);

        // store screenName, access token::token secret
        oauthInfo.setUsername(screenName);
        oauthInfo.setRefreshToken(
            authToken + TwitterOAuth2Constants.TOKEN_DELIMITER.getValue() + tokenSecret);
        dataSource.syncDatasource(mailbox, oauthInfo, getDatasourceCustomAttrs(oauthInfo));
        return true;
    }

    @Override
    public List<String> getAuthenticateParamKeys() {
        // code, error, state are default oauth2 keys
        return Arrays.asList("oauth_token", "oauth_verifier", "error", relayKey);
    }

    @Override
    public void verifyAuthenticateParams(Map<String, String> params) throws ServiceException {
        // check for errors
        final String error = params.get("error");
        if (!StringUtils.isEmpty(error)) {
            throw ServiceException.PERM_DENIED(error);
        // ensure code exists
        } else if (!params.containsKey("oauth_token") || !params.containsKey("oauth_verifier")) {
            throw ServiceException
                .INVALID_REQUEST(OAuth2ErrorConstants.ERROR_INVALID_AUTH_CODE.getValue(), null);
        }
    }

    /**
     * Generates and executes a request to the authorize token endpoint.
     *
     * @param account The zimbra account performing this context's request
     * @param stateValue A state query param
     * @return A location provided by the authorize token endpoint
     * @throws ServiceException If there are issues
     */
    protected String authorizeRequest(Account account, String stateValue) throws ServiceException {
        final OAuthInfo authInfo = new OAuthInfo(Collections.emptyMap());
        loadClientConfig(account, authInfo);
        final String clientRedirectUri = authInfo.getClientRedirectUri();
        final String clientId = authInfo.getClientId();
        final String clientSecret = authInfo.getClientSecret();
        final String authorizationHeader = new TwitterAuthorizationBuilder(clientId, clientSecret)
            .withMethod("POST")
            .withEndpoint(TwitterOAuth2Constants.AUTHORIZE_TOKEN_URI.getValue())
            .withParam("oauth_callback", clientRedirectUri + stateValue)
            .build();
        final HttpPost request = new HttpPost(
            TwitterOAuth2Constants.AUTHORIZE_TOKEN_URI.getValue());
        final List<NameValuePair> params = Arrays.asList(
            new BasicNameValuePair("oauth_callback", clientRedirectUri + stateValue));
        setFormEntity(request, params);
        request.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            "application/x-www-form-urlencoded");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
            authorizationHeader);
        String responseParams = null;
        try {
            final HttpResponseWrapper response = OAuth2Utilities.executeRequestRaw(request);
            responseParams = validateTwitterResponse(response);
        } catch (final IOException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring the authorization token.", e);
            throw ServiceException
                .PERM_DENIED("There was an issue acquiring an authorization token for this user.");
        }

        return responseParams;
    }

    /**
     * Returns a map with credentials from the Twitter token endpoint.
     *
     *  @see OAuth2Handler#getTokenRequest(OAuthInfo, String)
     */
    protected Map<String, String> getTokenRequestMap(OAuthInfo authInfo, String authorizationHeader)
        throws ServiceException {
        final HttpPost request = new HttpPost(authInfo.getTokenUrl());
        final List<NameValuePair> params = Arrays.asList(
            new BasicNameValuePair("grant_type", "client_credentials"),
            new BasicNameValuePair("oauth_verifier", authInfo.getParam("oauth_verifier")));
        setFormEntity(request, params);
        request.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            "application/x-www-form-urlencoded");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
            authorizationHeader);
        String rawResponse = null;
        try {
            final HttpResponseWrapper response = OAuth2Utilities.executeRequestRaw(request);
            rawResponse = validateTwitterResponse(response);
            ZimbraLog.extensions.debug("Request for auth token completed.");
        } catch (final IOException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring the authentication token.", e);
            throw ServiceException
                .PERM_DENIED("There was an issue acquiring an authentication token for this user.");
        }

        return splitToMap(rawResponse);
    }

    /**
     * Validates the twitter response by handling it as json for errors, raw string for success.
     *
     * @param response The http response
     * @return The response body string
     * @throws ServiceException If there was an issue with the response (non OK status)
     * @throws IOException If there are issues parsing the response (non OK status or otherwise)
     */
    protected String validateTwitterResponse(HttpResponseWrapper responseWrapper)
        throws ServiceException, IOException {
        String rawResponse = null;
        // always get the body if available
        final HttpResponse response = responseWrapper.getResponse();
        final byte[] entityBytes = responseWrapper.getEntityBytes();
        if (entityBytes != null) {
            rawResponse = new String(entityBytes);
        }
        // check for known errors if the status is not ok
        if (HttpStatus.SC_OK != response.getStatusLine().getStatusCode()) {
            validateTokenResponse(stringToJson(rawResponse));
        }
        return rawResponse;
    }

    /**
     * Validates response errors - always throws an error for Twitter.
     *
     * @param response The json token response
     * @throws ServiceException<br>
     *             FORBIDDEN If the social service rejects request as
     *             `access_denied`.<br>
     *             OPERATION_DENIED If the refresh token was deemed invalid, or
     *             incorrect redirect uri.<br>
     *             If the client id or client secret are incorrect.<br>
     *             PERM_DENIED If the refresh token or code is expired, or for
     *             general rejection.<br>
     *             TEMPORARILY_UNAVAILABLE If the response is rate limited
     *             or the service is suspended.
     */
    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response != null && response.has("errors")) {
            final JsonNode errorNodes = response.get("errors");
            ZimbraLog.extensions.debug(errorNodes.toString());
            // throw exception on first valid error
            for (final JsonNode errorNode : errorNodes) {
                // skip invalid error node
                if (!errorNode.has("code") || !errorNode.has("message")) {
                    continue;
                }
                final String errorCode = errorNode.get("code").asText();
                final String errorMsg = errorNode.get("message").asText();
                switch (TwitterErrorConstants.fromString(errorCode)) {
                case RESPONSE_ERROR_RATE_LIMIT_EXCEEDED:
                    ZimbraLog.extensions.error("Rate limit exceeded for the current window. %s",
                        errorMsg);
                    throw ServiceException.TEMPORARILY_UNAVAILABLE();
                case RESPONSE_ERROR_CLIENT_NOT_PERMITTED:
                case RESPONSE_ERROR_INSUFFICIENT_PRIVILEGES:
                    ZimbraLog.extensions.error(
                        "Insufficient privileges to perform the requested action. %s", errorMsg);
                    throw ServiceException.OPERATION_DENIED(
                        "Insufficient privileges to perform the requested action.");
                case RESPONSE_ERROR_COULD_NOT_AUTHENTICATE:
                case RESPONSE_ERROR_INVALID_TOKEN:
                case RESPONSE_ERROR_BAD_CREDENTIALS:
                case RESPONSE_ERROR_BAD_TIMESTAMP:
                case RESPONSE_ERROR_BAD_AUTH_DATA:
                    ZimbraLog.extensions.info("Unable to authenticate: %s", errorMsg);
                    throw ServiceException.FORBIDDEN("Unable to authenticate.");
                case RESPONSE_ERROR_SERVER_ERROR:
                    ZimbraLog.extensions
                        .debug("There was an issue with the remote social service. %s", errorMsg);
                    throw ServiceException
                        .PROXY_ERROR("There was an issue with the remote social service.", null);
                case RESPONSE_ERROR_ENDPOINT_RETIRED:
                    ZimbraLog.extensions.error("Invalid resource. %s", errorMsg);
                    throw ServiceException.FORBIDDEN("The specified resource is invalid.");
                case RESPONSE_ERROR_INVALID_CLIENT:
                    ZimbraLog.extensions.error(
                        "Invalid client credentials. This application has been suspended. %s",
                        errorMsg);
                    throw ServiceException.TEMPORARILY_UNAVAILABLE();
                case RESPONSER_ERROR_BAD_CALLBACK:
                    ZimbraLog.extensions.error("Callback url is not approved for this service. %s",
                        errorMsg);
                    throw ServiceException
                        .OPERATION_DENIED("Callback url is not approved for this service.");
                case DEFAULT_ERROR:
                default:
                    ZimbraLog.extensions.info(
                        "Unexpected error while trying to authenticate the user. %s", errorMsg);
                    throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
                }
            }
        }
        ZimbraLog.extensions.info("Unexpected error while trying to authenticate the user.");
        throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
    }

    /**
     * Split a tokenized string into a map.<br>
     * Assumes '=' and '&' as delimiters.<br>
     * Returns an empty map on empty input.
     *
     * @param input The tokenized string
     * @return A map of input tokens
     */
    protected Map<String, String> splitToMap(String input) {
        if (StringUtils.isEmpty(input)) {
            return Collections.emptyMap();
        }
        return Arrays.stream(input.split("&"))
            // filter broken tokens (no key value delimiter)
            .filter(s -> StringUtils.contains(s, "="))
            // allow empty value strings
            .map(s -> StringUtils.splitPreserveAllTokens(s, "="))
            .collect(Collectors.toMap(
                a -> a[0],
                a -> a[1]
            ));
    }

    /**
     * Builder for Twitter authorization headers.<br>
     * For ease of generating the auth header with varying request types.
     *
     * @author Zimbra API Team
     * @package com.zimbra.oauth.handlers.impl
     * @copyright Copyright © 2018
     */
    protected static class TwitterAuthorizationBuilder {

        /**
         * The request method.
         */
        protected String method;

        /**
         * The request endpoint.
         */
        protected String endpoint;

        /**
         * Consumer secret to sign the request with.
         */
        protected String consumerSecret;

        /**
         * The token secret to sign the request with.
         */
        protected String tokenSecret;

        /**
         * The sorted header elements.
         */
        protected SortedMap<String, String> headerElements;

        /**
         * The unsorted signature elements.
         */
        protected Map<String, String> signatureElements;

        /**
         * Constructs a new builder instance.
         *
         * @param consumerKey The consumer key for the request
         * @param consumerSecret The consumer secret for the request
         */
        public TwitterAuthorizationBuilder(String consumerKey, String consumerSecret) {
            this.method = "";
            this.endpoint = "";
            this.tokenSecret = "";
            this.consumerSecret = consumerSecret;
            // signature elements remain unsorted until necessary
            signatureElements = new HashMap<String, String>();
            // header elements are sorted
            headerElements = new TreeMap<String, String>();
            headerElements.put("oauth_consumer_key", consumerKey);
            headerElements.put("oauth_nonce", computeNonce());
            headerElements.put("oauth_signature_method", "HMAC-SHA1");
            headerElements.put("oauth_timestamp", String.valueOf(System.currentTimeMillis() / 1000));
            headerElements.put("oauth_version", "1.0");
        }

        /**
         * @param method The request method (POST, GET, etc)
         * @return Builder instance
         */
        public TwitterAuthorizationBuilder withMethod(String method) {
            if (method != null) {
                this.method = method;
            }
            return this;
        }

        /**
         * @param endpoint The request endpoint
         * @return Builder instance
         */
        public TwitterAuthorizationBuilder withEndpoint(String endpoint) {
            if (endpoint != null) {
                this.endpoint = endpoint;
            }
            return this;
        }

        /**
         * @param token The request token or access token
         * @return Builder instance
         */
        public TwitterAuthorizationBuilder withToken(String token) {
            withElement("oauth_token", token);
            return this;
        }

        /**
         * @param tokenSecret The access token secret
         * @return Builder instance
         */
        public TwitterAuthorizationBuilder withTokenSecret(String tokenSecret) {
            if (tokenSecret != null) {
                this.tokenSecret = tokenSecret;
            }
            return this;
        }

        /**
         * Adds a key value pair to the signature elements.<br>
         * Request parameters should be added via this method.
         *
         * @param key The param key
         * @param value The unencoded param value (will be encoded)
         * @return Builder instance
         */
        public TwitterAuthorizationBuilder withParam(String key, String value) {
            if (key != null && value != null) {
                signatureElements.put(key, encode(value));
            }
            return this;
        }

        /**
         * Adds kv pair to both signature and header elements.
         *
         * @param key The element key
         * @param value The unencoded element value (will be encoded)
         * @return Builder instance
         */
        protected TwitterAuthorizationBuilder withElement(String key, String value) {
            if (key != null && value != null) {
                headerElements.put(key, encode(value));
                signatureElements.put(key, encode(value));
            }
            return this;
        }

        /**
         * Builds the authorization header with signature.
         *
         * @return The authorization header
         * @throws ServiceException If there are issues
         */
        public String build() throws ServiceException {
            // clear previous signature before creating new one
            headerElements.remove("oauth_signature");
            // sorted local map containing all elements to generate the signature
            final SortedMap<String, String> localSig = new TreeMap<String, String>();
            localSig.putAll(signatureElements);
            localSig.putAll(headerElements);
            // create signature
            final String paramString = tokenize(localSig, "%s=%s", "&");
            try {
                final String unsignedParams = method + "&" + encode(endpoint) + "&"
                    + encode(paramString);
                final String oauthSignature = computeSignature(unsignedParams,
                    encode(consumerSecret) + "&" + encode(tokenSecret));
                // set the signature in the elements list
                headerElements.put("oauth_signature", encode(oauthSignature));
            } catch (final InvalidKeyException | NoSuchAlgorithmException e) {
                ZimbraLog.extensions.errorQuietly("Unable to sign authorization header data.", e);
                throw ServiceException.FAILURE("Unable to sign authorization header data.", e);
            }
            // generate header with prefix, signature, and header elements
            return "OAuth " + tokenize(headerElements, "%s=\"%s\"", ", ");
        }

        /**
         * Generates a string from the given elements with a template and delimiter.
         *
         * @param elements The elements to generate a string from
         * @param template The template for key value pairs
         * @param delimiter The delimiter for each element
         * @return A tokenized string
         */
        protected String tokenize(SortedMap<String, String> elements, String template,
            String delimiter) {
            final StringBuilder builder = new StringBuilder();
            for (final Entry<String, String> element : elements.entrySet()) {
                if (builder.length() > 0) {
                    builder.append(delimiter);
                }
                builder.append(
                    String.format(template, element.getKey(), element.getValue()));
            }
            return builder.toString();
        }

        /**
         * Computes a signature from base string and secret key string.
         *
         * @param baseString The base string
         * @param keyString The secret key string
         * @return The signature
         * @throws NoSuchAlgorithmException If the algorithm is unsupported
         * @throws InvalidKeyException If the secret key is invalid
         */
        protected String computeSignature(String baseString, String keyString)
            throws NoSuchAlgorithmException, InvalidKeyException {
            SecretKey secretKey = null;

            final byte[] keyBytes = keyString.getBytes();
            secretKey = new SecretKeySpec(keyBytes, "HmacSHA1");

            final Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(secretKey);

            final byte[] text = baseString.getBytes();

            return new String(Base64.encodeBase64(mac.doFinal(text))).trim();
        }

        /**
         * @return A uuid
         */
        protected String computeNonce() {
            return UUID.randomUUID().toString().replaceAll("-", "");
        }

        /**
         * @param toEncode The string to url encode
         * @return Url encoded string with substituted + keys || original string on failure
         */
        protected String encode(String toEncode) {
            try {
                return URLEncoder.encode(toEncode, OAuth2Constants.ENCODING.getValue())
                    .replaceAll("\\+", "%20");
            } catch (final UnsupportedEncodingException e) {
                ZimbraLog.extensions.error("There was an issue encoding the string: %s", toEncode);
                // do not error
            }
            return toEncode;
        }
    }
}
