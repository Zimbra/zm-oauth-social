package com.zimbra.oauth.models;

import java.util.Map;

public class OAuthInfo {

	protected String clientId;

	protected String clientSecret;

	protected String accessToken;

	protected String refreshToken;

	protected String zmAuthToken;

	protected String username;

	protected long timestamp;

	protected long expires;

	protected String refreshUrl;

	protected Map<String, String> params;

	public OAuthInfo(Map<String, String> params) {
		this.params = params;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getParam(String key) {
		return params.get(key);
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public String getZmAuthToken() {
		return zmAuthToken;
	}

	public void setZmAuthToken(String zmAuthToken) {
		this.zmAuthToken = zmAuthToken;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	public long getExpires() {
		return expires;
	}

	public void setExpires(long expires) {
		this.expires = expires;
	}

	public String getRefreshUrl() {
		return refreshUrl;
	}

	public void setRefreshUrl(String refreshUrl) {
		this.refreshUrl = refreshUrl;
	}

}
