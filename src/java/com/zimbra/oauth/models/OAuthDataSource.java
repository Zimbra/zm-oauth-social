package com.zimbra.oauth.models;

import com.zimbra.client.ZDataSource;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.InvalidResponseException;

/**
 * ZDataSource wrapper for storing oauth credentials.
 */
public class OAuthDataSource {

	/**
	 * The host identifier for this source.
	 */
	protected final String host;

	public OAuthDataSource(String host) {
		this.host = host;
	}

	/**
	 * Updates a DataSource refresh token, or creates one if none exists for the specified username.
	 *
	 * @param mailbox The user's mailbox
	 * @param credentials Credentials containing the username and refreshToken
	 * @throws InvalidResponseException If there are issues
	 */
	public void updateCredentials(ZMailbox mailbox, OAuthInfo credentials) throws InvalidResponseException {
		ZDataSource osource = null;
		final String refreshToken = credentials.getRefreshToken();
		final String username = credentials.getUsername();
		// get datasource
		try {
			osource = mailbox.getDataSourceByName(username);
			// create new datasource if missing
			if (osource == null) {
				osource = new ZDataSource(username, true);
				osource.setRefreshToken(refreshToken);
				osource.setHost(host);
				mailbox.createDataSource(osource);
			// or update the named credentials in datasource attribute
			} else {
				osource.setRefreshToken(refreshToken);
				mailbox.modifyDataSource(osource);
			}
		} catch (final ServiceException e) {
			ZimbraLog.extensions.error("There was an issue storing the oauth credentials.", e);
			throw new InvalidResponseException("There was an issue storing the oauth credentials.", e);
		}
	}

	/**
	 * Retrieves the refreshToken from DataSource. Returns null token if a source does not exist.
	 *
	 * @param mailbox The user's mailbox
	 * @param username The user to get refreshToken for
	 * @return RefreshToken for specified username
	 * @throws InvalidResponseException If there are issues
	 */
	public String getRefreshToken(ZMailbox mailbox, String username) throws InvalidResponseException {
		ZDataSource osource = null;
		String refreshToken = null;
		// get datasource
		try {
			osource = mailbox.getDataSourceByName(username);
			// get the refresh token if the source is available
			if (osource != null) {
				refreshToken = osource.getRefreshToken();
			}
		} catch (final ServiceException e) {
			ZimbraLog.extensions.error("There was an issue storing the oauth credentials.", e);
			throw new InvalidResponseException("There was an issue storing the oauth credentials.", e);
		}

		return refreshToken;
	}
}
