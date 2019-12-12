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
package com.zimbra.oauth.cache.ephemeral;

import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.ephemeral.EphemeralInput;
import com.zimbra.cs.ephemeral.EphemeralInput.RelativeExpiration;
import com.zimbra.cs.ephemeral.EphemeralKey;
import com.zimbra.cs.ephemeral.EphemeralStore;
import com.zimbra.oauth.cache.IOAuth2CacheHelper;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * The OAuth2CacheUtilities class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.cache.ephemeral
 * @copyright Copyright © 2019
 */
public class OAuth2EphemeralCacheHelper implements IOAuth2CacheHelper {

    /**
     * Cache client instance.
     */
    protected EphemeralStore client;

    public OAuth2EphemeralCacheHelper() {
        try {
            client = EphemeralStore.getFactory().getNewStore();
            if (client != null) {
                client.setAttributeEncoder(new OAuth2AttributeEncoder());
            }
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("Unable to load ephemeral store for oauth.", e);
        }
    }

    @Override
    public boolean isValidStorageType() {
        try {
            // ssdb allows ssdb, redis for formless storage. ensure we're only using this for caching
            final String backendUrl = Provisioning.getInstance().getConfig().getEphemeralBackendURL();
            return StringUtils.startsWith(backendUrl, OAuth2Constants.CACHE_BACKEND_URL_PREFIX.getValue());
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("Unable to load ephemeral store for oauth.", e);
        }
        return false;
    }

    @Override
    public String put(String key, String value) {
        final EphemeralInput input = new EphemeralInput(new EphemeralKey(key), value);
        try {
            client.set(input, new OAuth2EphemeralLocation());
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("Failed write to ephemeral store.", e);
        }
        return value;
    }

    @Override
    public String put(String key, String value, long expiry) {
        final EphemeralInput input = new EphemeralInput(new EphemeralKey(key), value,
            new RelativeExpiration(expiry, TimeUnit.SECONDS));
        try {
            client.set(input, new OAuth2EphemeralLocation());
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("Failed write to ephemeral store.", e);
        }
        return value;
    }

    @Override
    public void remove(String key) {
        try {
            client.delete(new EphemeralKey(key), null, new OAuth2EphemeralLocation());
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("Failed removal from ephemeral store.", e);
        }
    }

    @Override
    public String get(String key) {
        String result = null;
        try {
            result = client.get(new EphemeralKey(key), new OAuth2EphemeralLocation()).getValue();
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("Failed to read from ephemeral store.", e);
        }
        return result;
    }

}
