package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class InvalidOperationException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public InvalidOperationException(String message) {
		this(message, null);
	}

	public InvalidOperationException(Throwable throwable) {
		this(null, throwable);
	}

	public InvalidOperationException(String message, Throwable throwable) {
		super(message, throwable);
		setError(OAuth2Error.INVALID_OPERATION_ERROR);
		setStatus(Status.BAD_REQUEST);
	}

}
