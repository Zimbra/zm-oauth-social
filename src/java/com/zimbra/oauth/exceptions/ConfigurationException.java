package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class ConfigurationException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public ConfigurationException(String message) {
		super(message);
		error = OAuth2Error.CONFIGURATION_ERROR;
		status = Status.INTERNAL_SERVER_ERROR;
	}

	public ConfigurationException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public ConfigurationException(Throwable throwable) {
		super(throwable);
	}
}
