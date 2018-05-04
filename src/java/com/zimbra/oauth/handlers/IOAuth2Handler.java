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
package com.zimbra.oauth.handlers;

import java.util.List;
import java.util.Map;

import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.models.OAuthInfo;

/**
 * The IOAuth2Handler class.<br>
 * Interface for OAuth operations in this project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers
 * @copyright Copyright © 2018
 */
public interface IOAuth2Handler {

    /**
     * Returns authorize endpoint for the client.
     *
     * @param relayState The location to direct the user after authenticating
     * @return The authorize endpoint
     * @throws GenericOAuthException If there are issues determining the
     *             endpoint
     */
    public String authorize(String relayState) throws GenericOAuthException;

    /**
     * Authenticates a user with the endpoint and stores credentials in
     * ephemeral-store.
     *
     * @param oauthInfo Contains a code provided by authorizing endpoint
     * @return True on success
     * @throws GenericOAuthException If there are issues in this process
     */
    public Boolean authenticate(OAuthInfo oauthInfo) throws GenericOAuthException;

    /**
     * Refreshes credentials for an endpoint user.
     *
     * @param oauthInfo Contains the client and email address of the endpoint
     *            user to refresh (e.g. user@yahoo.com)
     * @return True on success
     * @throws GenericOAuthException If there are issues in this process
     */
    public Boolean refresh(OAuthInfo oauthInfo) throws GenericOAuthException;

    /**
     * Returns a list of keys to expect during authenticate callback.
     *
     * @return List of query param keys
     */
    public List<String> getAuthenticateParamKeys();

    /**
     * Throws an exception if there are invalid params passed in.
     *
     * @param params The authenticate request params
     * @throws GenericOAuthException If any params are invalid
     */
    public void verifyAuthenticateParams(Map<String, String> params) throws GenericOAuthException;

    /**
     * Returns the appropriate relay for this client.
     *
     * @param params Map of params to retrieve relay from
     * @return Relay as specified in params, or client default
     */
    public String getRelay(Map<String, String> params);
}
