package com.zimbra.oauth.models;

import javax.xml.bind.annotation.XmlRootElement;

import com.zimbra.oauth.utilities.OAuth2Error;

@XmlRootElement
public class ErrorObject {

	protected String errorMessage;

	protected OAuth2Error errorCode;

	public ErrorObject(OAuth2Error code, String message) {
		errorCode = code;
		errorMessage = message;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	public OAuth2Error getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(OAuth2Error errorCode) {
		this.errorCode = errorCode;
	}

}
