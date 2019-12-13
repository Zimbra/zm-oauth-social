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

import com.zimbra.cs.ephemeral.AttributeEncoder;
import com.zimbra.cs.ephemeral.EphemeralKey;
import com.zimbra.cs.ephemeral.EphemeralKeyValuePair;

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
    public EphemeralKeyValuePair decode(String key, String value) {
        return new EphemeralKeyValuePair(new EphemeralKey(key), value);
    }

}
