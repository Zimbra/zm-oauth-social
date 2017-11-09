package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class ConfigurationException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public ConfigurationException(String message) {
		this(message, null);
	}

	public ConfigurationException(Throwable throwable) {
		this(null, throwable);
	}

	public ConfigurationException(String message, Throwable throwable) {
		super(message, throwable);
		setError(OAuth2Error.CONFIGURATION_ERROR);
		setStatus(Status.INTERNAL_SERVER_ERROR);
	}

}
