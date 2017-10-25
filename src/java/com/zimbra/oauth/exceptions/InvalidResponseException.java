package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class InvalidResponseException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public InvalidResponseException(String message) {
		this(message, null);
	}

	public InvalidResponseException(Throwable throwable) {
		this(null, throwable);
	}

	public InvalidResponseException(String message, Throwable throwable) {
		super(message, throwable);
		setError(OAuth2Error.INVALID_RESPONSE_ERROR);
		setStatus(Status.BAD_GATEWAY);
	}

}
