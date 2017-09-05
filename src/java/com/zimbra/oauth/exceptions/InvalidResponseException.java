package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class InvalidResponseException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public InvalidResponseException(String message) {
		super(message);
		error = OAuth2Error.INVALID_RESPONSE_ERROR;
		status = Status.BAD_GATEWAY;
	}

	public InvalidResponseException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public InvalidResponseException(Throwable throwable) {
		super(throwable);
	}
}
