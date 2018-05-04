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
package com.zimbra.oauth.filters;

import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import javax.ws.rs.core.Response.Status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.models.ErrorObject;
import com.zimbra.oauth.models.ResponseObject;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2Error;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The OAuthExceptionFilter class.<br>
 * Filters exceptions for this project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.filters
 * @copyright Copyright © 2018
 */
public class OAuthExceptionFilter implements Filter {

    /**
     * JSON mapper.
     */
    protected static final ObjectMapper mapper = OAuth2Utilities.createDefaultMapper();

    /**
     * Rewrites uncaught exceptions to return the standard JSON error object.
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        final CharResponseWrapper responseWrapper = new CharResponseWrapper(
            (HttpServletResponse) response);
        try {
            chain.doFilter(request, responseWrapper);
        } catch (final ServletException e) {
            ZimbraLog.extensions.error(e);
            setServletResponse(response, Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                "Unexpected exception.");
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void destroy() {

    }

    /**
     * Sets response if it is http.
     *
     * @param originalResponse The non-wrapped response
     * @param status The status to set
     * @param errorMessage The error message to set
     * @throws IOException If there is an issue mapping the response object to
     *             JSON
     */
    private void setServletResponse(ServletResponse originalResponse, int status,
        String errorMessage) throws IOException {
        if (originalResponse instanceof HttpServletResponse) {
            if (errorMessage != null) {
                originalResponse.setContentType("application/json");
                originalResponse.setCharacterEncoding(OAuth2Constants.ENCODING);
                final String content = mapper.writeValueAsString(new ResponseObject<ErrorObject>(
                    new ErrorObject(OAuth2Error.GENERIC_OAUTH_ERROR, errorMessage)));
                originalResponse.setContentLength(content.length());
                ((HttpServletResponse) originalResponse).setStatus(status);
                originalResponse.getWriter().write(content);
            }
        }
    }

    /**
     * Wrapper for response. Used to delay sending response out during errors.
     */
    protected class CharResponseWrapper extends HttpServletResponseWrapper {

        /**
         * Character buffer object.
         */
        private final CharArrayWriter output;

        @Override
        public String toString() {
            return output.toString();
        }

        /**
         * Constructor.
         *
         * @param response A HttpServletResponse object
         */
        public CharResponseWrapper(HttpServletResponse response) {
            super(response);
            output = new CharArrayWriter();
        }

        @Override
        public PrintWriter getWriter() {
            return new PrintWriter(output);
        }

        @Override
        public void sendError(int sc, String msg) throws IOException {
            // don't send errors yet
        }
    }
}
