package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import com.zimbra.oauth.models.ErrorObject;
import com.zimbra.oauth.models.ResponseObject;
import com.zimbra.oauth.utilities.OAuth2Error;
import com.zimbra.oauth.utilities.OAuth2Utilities;

@Provider
public class GenericOAuthException extends Exception implements ExceptionMapper<GenericOAuthException> {

	private static final long serialVersionUID = 1L;

	/**
	 * Error code of this exception.
	 */
	protected OAuth2Error error = OAuth2Error.GENERIC_OAUTH_ERROR;

	/**
	 * HTTP Status of this exception.
	 */
	protected Status status = Status.INTERNAL_SERVER_ERROR;

	public GenericOAuthException() {
		super();
	}

	public GenericOAuthException(String message) {
		super(message);
	}

	public GenericOAuthException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public GenericOAuthException(Throwable throwable) {
		super(throwable);
	}

	public OAuth2Error getError() {
		return error;
	}

	public void setError(OAuth2Error error) {
		this.error = error;
	}

	public Status getStatus() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	@Override
	public Response toResponse(GenericOAuthException e) {
		return OAuth2Utilities.buildResponse(new ResponseObject<ErrorObject>(new ErrorObject(e.getError(), e.getMessage())), e.getStatus(), null);
	}

}
