/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth Social Extension
 * Copyright (C) 2018 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.oauth.utilities;

import java.util.Base64;
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

/**
 * The OAuth2Utilities class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public class OAuth2Utilities {

    /**
     * Creates a mapper that can convert between Java <-> JSON objects.
     *
     * @return mapper A mapper object
     */
    public static ObjectMapper createDefaultMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_CONTROL_CHARS, true);
        return mapper;
    }

    /**
     * Creates a Basic authorization header.
     *
     * @param user The left param
     * @param pass The right param
     * @return Basic authorization header
     */
    public static String encodeBasicHeader(String user, String pass) {
        return Base64.getEncoder()
            .encodeToString(new String(user + ":" + pass).getBytes());
    }

    /**
     * Builds an HTTP response object.
     *
     * @param entity Model to display
     * @param status HTTP Status
     * @param headers HTTP Headers
     * @return HTTP response object
     */
    public static Response buildResponse(ResponseObject<? extends Object> entity, Status status,
        Map<String, Object> headers) {
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
            for (final Entry<String, Object> entry : headers.entrySet()) {
                resBuilder.header(entry.getKey(), entry.getValue());
            }
        }
        return resBuilder.build();
    }

}
