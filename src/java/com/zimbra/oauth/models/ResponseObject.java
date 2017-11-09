package com.zimbra.oauth.models;

import javax.xml.bind.annotation.XmlRootElement;

import com.zimbra.oauth.utilities.OAuth2Constants;

@XmlRootElement
public class ResponseObject<E> {

	protected E data;

	protected Meta _meta = new Meta();

	public ResponseObject(E data) {
		this.data = data;
	}

	public E getData() {
		return data;
	}

	public void setData(E data) {
		this.data = data;
	}

	public Meta get_meta() {
		return _meta;
	}

	public void set_meta(Meta _meta) {
		this._meta = _meta;
	}

	@XmlRootElement
	protected class Meta {
		protected final String api = OAuth2Constants.API_NAME;

		public String getApi() {
			return api;
		}
	}
}
