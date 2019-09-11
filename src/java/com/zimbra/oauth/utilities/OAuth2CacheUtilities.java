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
package com.zimbra.oauth.utilities;

import org.redisson.api.RBucket;
import org.redisson.api.RedissonClient;

import com.zimbra.cs.mailbox.RedissonClientHolder;

/**
 * The OAuth2CacheUtilities class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2019
 */
public class OAuth2CacheUtilities {

    /**
     * Cache client instance.
     */
    protected static final RedissonClient client = RedissonClientHolder.getInstance().getRedissonClient();

    public static String put(String key, String value) {
        getBucket(key).set(value);
        return value;
    }

    public static String remove(String key) {
        return getBucket(key).getAndDelete();
    }

    public static String get(String key) {
        return get(key, null);
    }

    public static String get(String key, String defValue) {
        String value = getBucket(key).get();
        if (value == null) {
            value = defValue;
        }
        return value;
    }

    private static RBucket<String> getBucket(String key) {
        return client.getBucket(key);
    }
}
