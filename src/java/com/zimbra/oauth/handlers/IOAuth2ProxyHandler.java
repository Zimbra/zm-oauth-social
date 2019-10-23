/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth Social Extension
 * Copyright (C) 2019 Synacor, Inc.
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
package com.zimbra.oauth.handlers;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Account;

/**
 * The IOAuth2ProxyHandler class.<br>
 * Interface for OAuth proxy operations in this project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers
 * @copyright Copyright © 2019
 */
public interface IOAuth2ProxyHandler {

    /**
     * Returns a map of headers to set before proxying a request.
     *
     * @param params request params
     * @param account The account to acquire configuration by access level
     * @return Map of headers to set before proxying
     * @throws ServiceException If there are issues determining the endpoint
     */
    public Map<String, String> headers(Map<String, String> params, Account account) throws ServiceException;

    /**
     * @param client The request client (may contain relevant data for path comparison)
     * @param method The request method
     * @param extraHeaders Contains authorization header
     * @param target The target to check
     * @param body The request body
     * @param account The account to acquire configuration by access level
     * @return True if the specified request is allowed
     */
    public boolean isProxyRequestAllowed(String client, String method,
        Map<String, String> extraHeaders, String target, InputStream body, Account account);

    /**
     * @return A list of keys expected by headers method
     */
    public List<String> getHeadersParamKeys();
}
