package com.zimbra.oauth.handlers.impl;

import java.io.IOException;

import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;

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
import com.zimbra.soap.admin.type.DataSourceType;

public class LinkedinOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {
    protected enum LinkedinOAuth2Constants {
        AUTHORIZE_URI_TEMPLATE("https://www.linkedin.com/oauth/v2/authorization?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s"),
        RESPONSE_TYPE("code"),
        RELAY_KEY("state"),
        CLIENT_NAME("linkedin"),
        HOST_LINKEDIN("www.linkedin.com"),
        REQUIRED_SCOPES("r_basicprofile,r_emailaddress"),
        SCOPE_DELIMITER(" "),
        AUTHENTICATE_URI("https://www.linkedin.com/oauth/v2/accessToken"),
        ACCESS_TOKEN("access_token"),
        EXPIRES_IN("expires_in")
        ;

        private String constant;

        LinkedinOAuth2Constants(String value) {
            constant = value;
        }

        public String getValue() {
            return constant;
        }
    }

    protected enum LinkedinMeConstants {
        ME_URI("https://api.linkedin.com/v2/me"),
        ID("id"),
        FIRST_NAME("firstName"),
        LAST_NAME("lastName")
        ;

        private String constant;

        LinkedinMeConstants(String value) {
            constant = value;
        }

        public String getValue() {
            return constant;
        }
    }

    protected enum LinkedinErrorCodes {
        ERROR("error"),
        USER_CANCELLED_LOGIN("user_cancelled_login"),
        USER_CANCELLED_AUTHORIZE("user_cancelled_authorize"),
        ERROR_DESCRIPTION("error_description"),
        DEFAULT_ERROR("default_error"),
        SERVICE_ERROR_CODE("serviceErrorCode"),
        ERROR_MESSAGE("message"),
        ERROR_STATUS("status"),
        SERVICE_ERROR_CODE_100("100"),
        ERROR_MESSAGE_NOT_ENOUGH_PERM("Not enough permissions to access")
        ;

        private String constant;

        LinkedinErrorCodes(String value) {
            constant = value;
        }

        public String getValue() {
            return constant;
        }

        public static LinkedinErrorCodes fromString(String value) {
            for (LinkedinErrorCodes code : LinkedinErrorCodes.values()) {
                if (code.getValue().equals(value)) {
                    return code;
                }
            }
            return LinkedinErrorCodes.DEFAULT_ERROR;
        }
    }

    public LinkedinOAuth2Handler(Configuration config) {
        super(config, LinkedinOAuth2Constants.CLIENT_NAME.getValue(), LinkedinOAuth2Constants.HOST_LINKEDIN.getValue());
        authorizeUriTemplate = LinkedinOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        requiredScopes = LinkedinOAuth2Constants.REQUIRED_SCOPES.getValue();
        scopeDelimiter = LinkedinOAuth2Constants.SCOPE_DELIMITER.getValue();
        relayKey = LinkedinOAuth2Constants.RELAY_KEY.getValue();
        authenticateUri = LinkedinOAuth2Constants.AUTHENTICATE_URI.getValue();
        dataSource.addImportClass(DataSourceType.oauth2contact.name(), LinkedinContactsImport.class.getCanonicalName());
    }

    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        if (response.has(LinkedinErrorCodes.ERROR.getValue())) {
            final String error = response.get(LinkedinErrorCodes.ERROR.getValue()).asText();
            final JsonNode errorMsg = response.get(LinkedinErrorCodes.ERROR_DESCRIPTION.getValue());
            ZimbraLog.extensions.debug("Response from linkedin: %s", response.asText());
            switch (LinkedinErrorCodes.fromString(StringUtils.upperCase(error))) {
            case USER_CANCELLED_LOGIN:
                ZimbraLog.extensions.info(
                    "User cancelled on login screen : " + errorMsg);
                throw ServiceException.OPERATION_DENIED(
                    "User cancelled on login screen");
            case USER_CANCELLED_AUTHORIZE:
                ZimbraLog.extensions.info(
                        "User cancelled to authorize : " + errorMsg);
                    throw ServiceException.OPERATION_DENIED(
                        "User cancelled to authorize");
            case DEFAULT_ERROR:
            default:
                ZimbraLog.extensions
                    .warn("Unexpected error while trying to validate token: " + errorMsg);
                throw ServiceException.PERM_DENIED("Token validation failed");
            }
        }

        // ensure the tokens we requested are present
        if (!response.has(LinkedinOAuth2Constants.ACCESS_TOKEN.getValue()) || !response.has(LinkedinOAuth2Constants.EXPIRES_IN.getValue())) {
            throw ServiceException.PARSE_ERROR("Unexpected response from social service.", null);
        }
    }

    @Override
    protected String getPrimaryEmail(JsonNode credentials, Account account) throws ServiceException {
        JsonNode json = null;
        final String basicToken = credentials.get(LinkedinOAuth2Constants.ACCESS_TOKEN.getValue()).asText();
        final String url = LinkedinMeConstants.ME_URI.getValue();

        try {
            final GetMethod request = new GetMethod(url);
            request.setRequestHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
                "application/x-www-form-urlencoded");
            request.setRequestHeader(OAuth2HttpConstants.HEADER_ACCEPT.getValue(), "application/json");
            request.setRequestHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
                "Bearer " + basicToken);
            json = executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions.warnQuietly("There was an issue acquiring the account details.",
                    e);
            throw ServiceException.FAILURE("There was an issue acquiring the account details.",
                    null);
        }
        // check for errors
        if (json.has(LinkedinErrorCodes.SERVICE_ERROR_CODE.getValue())
                && json.has(LinkedinErrorCodes.ERROR_MESSAGE.getValue())) {
            if (json.get(LinkedinErrorCodes.SERVICE_ERROR_CODE.getValue()).asText().equals(LinkedinErrorCodes.SERVICE_ERROR_CODE_100.getValue())
                    && json.get(LinkedinErrorCodes.ERROR_MESSAGE.getValue()).asText().contains(LinkedinErrorCodes.ERROR_MESSAGE_NOT_ENOUGH_PERM.getValue())
                    ) {
                return account.getMail();
            }
            ZimbraLog.extensions.warnQuietly("Error occured while getting profile details."
                    + " Code=" + json.get(LinkedinErrorCodes.SERVICE_ERROR_CODE.getValue())
                    + ", Status=" + json.get(LinkedinErrorCodes.ERROR_STATUS.getValue())
                    + ", ErrorMessage=" + json.get(LinkedinErrorCodes.ERROR_MESSAGE.getValue()),
                    null);
            throw ServiceException.FAILURE("Error occured while getting profile details.",
                    null);
        }
        // no errors found
        if (json.has(LinkedinMeConstants.FIRST_NAME.getValue()) && json.has(LinkedinMeConstants.LAST_NAME.getValue())
                && !json.get(LinkedinMeConstants.FIRST_NAME.getValue()).asText().isEmpty()
                && !json.get(LinkedinMeConstants.LAST_NAME.getValue()).asText().isEmpty()) {
            return json.get(LinkedinMeConstants.FIRST_NAME.getValue()).asText() + "." + json.get(LinkedinMeConstants.LAST_NAME.getValue()).asText();
        } else if (json.has(LinkedinMeConstants.ID.getValue()) && !json.get(LinkedinMeConstants.ID.getValue()).asText().isEmpty()) {
            return json.get(LinkedinMeConstants.ID.getValue()).asText();
        }

        // if we couldn't retrieve the user first & last name, the response from
        // downstream is missing data
        // this could be the result of a misconfigured application id/secret
        // (not enough scopes)
        ZimbraLog.extensions.error("The user id could not be retrieved from the social service api.");
        throw ServiceException.UNSUPPORTED();
    }

    @Override
    public Boolean authenticate(OAuthInfo oauthInfo) throws ServiceException {
        final Account account = oauthInfo.getAccount();
        final String clientId = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_ID_TEMPLATE.getValue(), client), client,
            account);
        final String clientSecret = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_SECRET_TEMPLATE.getValue(), client),
            client, account);
        final String clientRedirectUri = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE.getValue(), client),
            client, account);
        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(clientSecret)
            || StringUtils.isEmpty(clientRedirectUri)) {
            throw ServiceException.FAILURE("Required config(id, secret and redirectUri) parameters are not provided.", null);
        }
        final String basicToken = OAuth2Utilities.encodeBasicHeader(clientId, clientSecret);
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
        final String username = getPrimaryEmail(credentials, account);
        ZimbraLog.extensions.trace("Authentication performed for:" + username);

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken());

        // store refreshToken
        oauthInfo.setUsername(username);
        oauthInfo.setRefreshToken(credentials.get(LinkedinOAuth2Constants.ACCESS_TOKEN.getValue()).asText());
        dataSource.syncDatasource(mailbox, oauthInfo, null);
        return true;
    }

}
