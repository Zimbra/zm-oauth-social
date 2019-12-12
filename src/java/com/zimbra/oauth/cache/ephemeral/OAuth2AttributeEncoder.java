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

import org.apache.commons.lang.StringUtils;

import com.zimbra.cs.ephemeral.AttributeEncoder;
import com.zimbra.cs.ephemeral.EphemeralKey;
import com.zimbra.cs.ephemeral.ExpirableEphemeralKeyValuePair;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * The OAuth2AttributeEncoder class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.cache.ephemeral
 * @copyright Copyright © 2019
 * @see SSDBAttributeEncoder
 */
public class OAuth2AttributeEncoder extends AttributeEncoder {

    public OAuth2AttributeEncoder() {
        setKeyEncoder(new OAuth2KeyEncoder());
        setValueEncoder(new OAuth2ValueEncoder());
    }

    @Override
    public ExpirableEphemeralKeyValuePair decode(String key, String value) {
        final String DELIMITER = OAuth2Constants.CACHE_VALUE_DELIMITER.getValue();
        final EphemeralKey eKey = new EphemeralKey(key);
        String decodedValue;
        Long expires = null;
        if (StringUtils.endsWith(value, DELIMITER)) {
            // no expiration encoded
            decodedValue = value.substring(0, value.length() - DELIMITER.length());
        } else {
            final int delimiterLastIndex = value.lastIndexOf(DELIMITER);
            decodedValue = value.substring(0, delimiterLastIndex);
            final String expiryStr = value.substring(delimiterLastIndex + DELIMITER.length());
            try {
                expires = Long.parseLong(expiryStr);
            } catch (final NumberFormatException e) {
                // fall back to the whole string being the value
                decodedValue = value;
            }
        }
        return new ExpirableEphemeralKeyValuePair(eKey, decodedValue, expires);
    }

}

