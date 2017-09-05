package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class UnreachableHostException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public UnreachableHostException(String message) {
		super(message);
		error = OAuth2Error.UNREACHABLE_HOST_ERROR;
		status = Status.GATEWAY_TIMEOUT;
	}

	public UnreachableHostException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public UnreachableHostException(Throwable throwable) {
		super(throwable);
	}

}
