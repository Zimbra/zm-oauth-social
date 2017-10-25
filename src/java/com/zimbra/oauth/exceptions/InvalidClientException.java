package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class InvalidClientException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public InvalidClientException(String message) {
		this(message, null);
	}

	public InvalidClientException(Throwable throwable) {
		this(null, throwable);
	}

	public InvalidClientException(String message, Throwable throwable) {
		super(message, throwable);
		setError(OAuth2Error.INVALID_CLIENT_ERROR);
		setStatus(Status.BAD_REQUEST);
	}

}
