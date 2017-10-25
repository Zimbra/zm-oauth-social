package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class ServiceNotAvailableException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public ServiceNotAvailableException(String message) {
		this(message, null);
	}

	public ServiceNotAvailableException(Throwable throwable) {
		this(null, throwable);
	}

	public ServiceNotAvailableException(String message, Throwable throwable) {
		super(message, throwable);
		setError(OAuth2Error.SERVICE_NOT_AVAILABLE_ERROR);
		setStatus(Status.SERVICE_UNAVAILABLE);
	}

}
