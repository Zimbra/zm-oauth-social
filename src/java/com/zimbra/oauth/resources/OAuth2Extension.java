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
package com.zimbra.oauth.resources;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.extension.ExtensionDispatcherServlet;
import com.zimbra.cs.extension.ExtensionException;
import com.zimbra.cs.extension.ZimbraExtension;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * The OAuth2Extension class.<br>
 * Registry point for the project's request handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.resources
 * @copyright Copyright © 2018
 */
public class OAuth2Extension implements ZimbraExtension {

	@Override
	public void destroy() {
		ExtensionDispatcherServlet.unregister(this);
	}

	@Override
	public String getName() {
		return OAuth2Constants.API_NAME;
	}

	@Override
	public void init() throws ExtensionException, ServiceException {
		ExtensionDispatcherServlet.register(this, new ZOAuth2Servlet());
	}

}
