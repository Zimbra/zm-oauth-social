package com.zimbra.oauth.utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Map.Entry;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.zimbra.oauth.models.ResponseObject;

public class OAuth2Utilities {

	public static byte[] decodeStream(InputStream input, long size) throws IOException {
		final long MIN_BUFFER_SIZE = 100;
		final long MAX_BUFFER_SIZE = 4080;
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		int lengthRead;
		// buffer size must be within our bounds
		if (size < MIN_BUFFER_SIZE || size > MAX_BUFFER_SIZE) {
			size = MAX_BUFFER_SIZE;
		}
		final byte[] data = new byte[(int) size];
		try {
			// read until the end
			while ((lengthRead = input.read(data, 0, data.length)) != -1) {
				buffer.write(data, 0, lengthRead);
			}
			buffer.flush();
		} finally {
			// always close the input
			input.close();
		}
		return buffer.toByteArray();
	}

	public static ObjectMapper createDefaultMapper() {
		final ObjectMapper mapper = new ObjectMapper();
		mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
		mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		mapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_CONTROL_CHARS, true);
		return mapper;
	}

	/**
	 * Builds an HTTP response object.
	 *
	 * @param entity Model to display
	 * @param status HTTP Status
	 * @param headers HTTP Headers
	 * @return HTTP response object
	 */
	public static Response buildResponse(ResponseObject<? extends Object> entity, Status status, Map<String, Object> headers) {
		// status
		if (status == null) {
			status = Status.OK;
		}
		final ResponseBuilder resBuilder = Response.status(status);
		// body
		if (entity != null) {
			resBuilder.entity(entity);
		}
		// headers
		if (headers != null && !headers.isEmpty()) {
			for(final Entry<String, Object> entry : headers.entrySet()) {
				resBuilder.header(entry.getKey(), entry.getValue());
			}
		}
		return resBuilder.build();
	}
}
