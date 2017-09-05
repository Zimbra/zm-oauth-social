package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class InvalidClientException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public InvalidClientException(String message) {
		super(message);
		error = OAuth2Error.INVALID_CLIENT_ERROR;
		status = Status.BAD_REQUEST;
	}

	public InvalidClientException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public InvalidClientException(Throwable throwable) {
		super(throwable);
	}

}
