package com.zimbra.oauth.handlers;

import java.util.List;
import java.util.Map;

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
	 * @param oauthInfo Contains the client and email address of the endpoint user to refresh (e.g. user@yahoo.com)
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
