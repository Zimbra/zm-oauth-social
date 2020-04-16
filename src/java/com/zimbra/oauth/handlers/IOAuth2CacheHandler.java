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

import com.zimbra.oauth.utilities.OAuth2CacheUtilities;

/**
 * The IOAuth2CacheHandler class.<br>
 * Interface for OAuth handlers that require cache functionality.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers
 * @copyright Copyright © 2019
 */
public interface IOAuth2CacheHandler {

    /**
     * @return True if available cache system can be used by handler for proxy auth requests
     */
    public default boolean isCacheValidForProxy() {
        return OAuth2CacheUtilities.isValidStorageType();
    }

    /**
     * @return True if available cache system can be used by handler for oauth requests
     */
    public default boolean isCacheValidForOAuth() {
        return true;
    }

}
