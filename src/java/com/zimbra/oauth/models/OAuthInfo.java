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
package com.zimbra.oauth.models;

import java.util.Map;

/**
 * The OAuthInfo class.<br>
 * Contains OAuth related data.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.models
 * @copyright Copyright © 2018
 */
public class OAuthInfo {

	/**
	 * A client id.
	 */
	protected String clientId;

	/**
	 * A client secret.
	 */
	protected String clientSecret;

	/**
	 * An access token.
	 */
	protected String accessToken;

	/**
	 * A refresh token.
	 */
	protected String refreshToken;

	/**
	 * A Zimbra auth token.
	 */
	protected String zmAuthToken;

	/**
	 * A username.
	 */
	protected String username;

	/**
	 * A timestamp.
	 */
	protected long timestamp;

	/**
	 * An expiration timestamp.
	 */
	protected long expires;

	/**
	 * A refresh url.
	 */
	protected String refreshUrl;

	/**
	 * A map of parameters.
	 */
	protected Map<String, String> params;

	/**
	 * Constructor.
	 *
	 * @param params A map of parameters.
	 */
	public OAuthInfo(Map<String, String> params) {
		this.params = params;
	}

	/**
	 * Get the clientId.
	 *
	 * @return clientId A client id
	 */
	public String getClientId() {
		return clientId;
	}

	/**
	 * Set the clientId.
	 *
	 * @param clientId A client id
	 */
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	/**
	 * Get the client secret.
	 *
	 * @return clientSecret A client secret
	 */
	public String getClientSecret() {
		return clientSecret;
	}

	/**
	 * Set the client secret.
	 *
	 * @param clientSecret A client secret
	 */
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	/**
	 * Get a parameter value.
	 *
	 * @param key A key value
	 * @return The value associated with the provided key parameter
	 */
	public String getParam(String key) {
		return params.get(key);
	}

	/**
	 * Get the access token.
	 *
	 * @return accessToken The access token
	 */
	public String getAccessToken() {
		return accessToken;
	}

	/**
	 * Set the access token.
	 *
	 * @param An access token
	 */
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	/**
	 * Get the refresh token.
	 *
	 * @return The refresh token
	 */
	public String getRefreshToken() {
		return refreshToken;
	}

	/**
	 * Set the refresh token.
	 *
	 * @param refreshToken A refresh token
	 */
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	/**
	 * Get the Zimbra auth token.
	 *
	 * @return The Zimbra auth token
	 */
	public String getZmAuthToken() {
		return zmAuthToken;
	}

	/**
	 * Set the Zimbra auth token.
	 *
	 * @param zmAuthToken A Zimbra auth token
	 */
	public void setZmAuthToken(String zmAuthToken) {
		this.zmAuthToken = zmAuthToken;
	}

	/**
	 * Get the username.
	 *
	 * @return The username
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * Set the username.
	 *
	 * @param username The username
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * Get the timestamp.
	 *
	 * @return The timestamp
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * Set the timestamp.
	 *
	 * @param timestamp A timestamp
	 */
	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	/**
	 * Get the expires timestamp.
	 *
	 * @return The expires timestamp
	 */
	public long getExpires() {
		return expires;
	}

	/**
	 * Set an expires timestamp.
	 *
	 * @param expires An expires timestamp
	 */
	public void setExpires(long expires) {
		this.expires = expires;
	}

	/**
	 * Get the refresh url.
	 *
	 * @return The refresh url
	 */
	public String getRefreshUrl() {
		return refreshUrl;
	}

	/**
	 * Set the refresh url.
	 *
	 * @param refreshUrl A refresh url
	 */
	public void setRefreshUrl(String refreshUrl) {
		this.refreshUrl = refreshUrl;
	}

}
