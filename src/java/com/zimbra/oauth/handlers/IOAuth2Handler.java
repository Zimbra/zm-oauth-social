package com.zimbra.oauth.handlers;

import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.models.OAuthInfo;

public interface IOAuth2Handler {
	/**
	 * Returns authorize endpoint for the client.
	 *
	 * @param relayState The location to direct the user after authenticating
	 * @return The authorize endpoint
	 * @throws GenericOAuthException If there are issues determining the endpoint
	 */
	public String authorize(String relayState) throws GenericOAuthException;

	/**
	 * Authenticates a user with the endpoint and stores credentials in ephemeral-store.
	 *
	 * @param oauthInfo Contains a code provided by authorizing endpoint
	 * @return True on success
	 * @throws GenericOAuthException If there are issues in this process
	 */
	public Boolean authenticate(OAuthInfo oauthInfo) throws GenericOAuthException;

	/**
	 * Refreshes credentials for an endpoint user.
	 *
	 * @param client The client
	 * @param username The email address of the endpoint user to refresh (e.g. user@yahoo.com)
	 * @return
	 * @throws GenericOAuthException
	 */
	public Boolean refresh(String client, String username) throws GenericOAuthException;
}
