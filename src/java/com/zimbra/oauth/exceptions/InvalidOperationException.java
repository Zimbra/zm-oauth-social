package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class InvalidOperationException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public InvalidOperationException(String message) {
		super(message);
		error = OAuth2Error.INVALID_OPERATION_ERROR;
		status = Status.BAD_REQUEST;
	}

	public InvalidOperationException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public InvalidOperationException(Throwable throwable) {
		super(throwable);
	}

}
