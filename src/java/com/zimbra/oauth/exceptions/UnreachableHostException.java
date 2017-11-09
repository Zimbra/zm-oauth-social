package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class UnreachableHostException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public UnreachableHostException(String message) {
		this(message, null);
	}

	public UnreachableHostException(Throwable throwable) {
		this(null, throwable);
	}

	public UnreachableHostException(String message, Throwable throwable) {
		super(message, throwable);
		setError(OAuth2Error.UNREACHABLE_HOST_ERROR);
		setStatus(Status.GATEWAY_TIMEOUT);
	}

}
