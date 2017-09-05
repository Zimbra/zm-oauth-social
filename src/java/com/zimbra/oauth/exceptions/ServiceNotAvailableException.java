package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class ServiceNotAvailableException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public ServiceNotAvailableException(String message) {
		super(message);
		error = OAuth2Error.SERVICE_NOT_AVAILABLE_ERROR;
		status = Status.SERVICE_UNAVAILABLE;
	}

	public ServiceNotAvailableException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public ServiceNotAvailableException(Throwable throwable) {
		super(throwable);
	}

}
