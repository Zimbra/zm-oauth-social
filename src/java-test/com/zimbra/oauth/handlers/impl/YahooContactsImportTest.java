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
package com.zimbra.oauth.handlers.impl;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.util.Pair;
import com.zimbra.cs.account.DataSource;
import com.zimbra.oauth.handlers.impl.YahooContactsImport.YahooContactsUtil;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;

/**
 * Test class for {@link YahooContactsImport}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ DataSource.class, YahooContactsImport.class, YahooContactsUtil.class })
public class YahooContactsImportTest {

    /**
     * Class under test.
     */
    protected YahooContactsImport importer;

    /**
     * Access token for testing.
     */
    protected final String accessToken = "test-access-token";

    /**
     * Guid for testing.
     */
    protected final String guid = "test-guid";

    /**
     * Mock configuration handler property.
     */
    protected Configuration mockConfig = EasyMock.createMock(Configuration.class);

    /**
     * Mock data source for testing.
     */
    protected DataSource mockSource;

    /**
     * Setup for tests.
     *
     * @throws Exception If there are issues mocking
     */
    @Before
    public void setUp() throws Exception {
        mockSource = EasyMock.createMock(DataSource.class);
        importer = PowerMock.createPartialMock(YahooContactsImport.class,
            new String[] { "refresh", "getContactsRequest" }, mockSource, mockConfig);

        PowerMock.mockStatic(YahooContactsUtil.class);
    }

    /**
     * Test method for {@link YahooContactsImport#importData}<br>
     * Validates that the method fetches contacts and passes along to parse utilites.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testImportData() throws Exception {
        expect(mockSource.getMultiAttr(anyObject())).andReturn(new String[] {});
        // expect a fetch for refresh token
        expect(importer.refresh()).andReturn(new Pair<String, String>(accessToken, guid));
        // expect a fetch for 2 fake contacts
        final String jsonData = "{\"contactsync\":{\"contacts\":[{\"categories\":[{\"created\":\"2018-05-24T22:59:24Z\",\"id\":-5555,\"updated\":\"2018-05-24T22:59:24Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid/contact/1/category/\"}],\"created\":\"2014-06-13T15:19:15Z\",\"error\":0,\"fields\":[{\"categories\":[],\"created\":\"2018-05-24T15:11:22Z\",\"editedBy\":\"OWNER\",\"flags\":[],\"id\":3,\"type\":\"name\",\"updated\":\"2018-05-24T15:11:22Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid/contact/1/name/3\",\"value\":{\"familyName\":\"Test\",\"familyNameSound\":\"\",\"givenName\":\"\",\"givenNameSound\":\"\",\"middleName\":\"\",\"prefix\":\"\",\"suffix\":\"\"}},{\"categories\":[],\"created\":\"2018-05-24T15:11:22Z\",\"editedBy\":\"OWNER\",\"flags\":[],\"id\":4,\"type\":\"jobTitle\",\"updated\":\"2018-05-24T15:11:22Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid/contact/1/jobTitle/4\",\"value\":\"Testing Role\"},{\"categories\":[],\"created\":\"2018-05-24T15:11:22Z\",\"editedBy\":\"OWNER\",\"flags\":[],\"id\":5,\"type\":\"company\",\"updated\":\"2018-05-24T15:11:22Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid/contact/1/company/5\",\"value\":\"Redacted\"},{\"categories\":[],\"created\":\"2014-06-13T15:19:15Z\",\"editedBy\":\"OWNER\",\"flags\":[],\"id\":1,\"type\":\"email\",\"updated\":\"2014-06-13T15:19:15Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid/contact/1/email/1\",\"value\":\"testuser1@yahoo.com\"}],\"id\":1,\"isConnection\":false,\"op\":\"add\",\"restoredId\":0,\"updated\":\"2018-05-24T15:11:22Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid/contact/1\"},{\"categories\":[{\"created\":\"2018-05-25T22:59:24Z\",\"id\":-5555,\"updated\":\"2018-05-24T22:59:24Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid2/contact/1/category/\"}],\"created\":\"2014-06-13T15:19:15Z\",\"error\":0,\"fields\":[{\"categories\":[],\"created\":\"2018-05-24T15:11:22Z\",\"editedBy\":\"OWNER\",\"flags\":[],\"id\":3,\"type\":\"name\",\"updated\":\"2018-05-24T15:11:22Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid2/contact/1/name/3\",\"value\":{\"familyName\":\"Test2\",\"familyNameSound\":\"\",\"givenName\":\"\",\"givenNameSound\":\"\",\"middleName\":\"\",\"prefix\":\"\",\"suffix\":\"\"}},{\"categories\":[],\"created\":\"2018-05-25T15:11:22Z\",\"editedBy\":\"OWNER\",\"flags\":[],\"id\":4,\"type\":\"jobTitle\",\"updated\":\"2018-05-25T15:11:22Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid2/contact/1/jobTitle/4\",\"value\":\"Testing Role\"},{\"categories\":[],\"created\":\"2018-05-25T15:11:22Z\",\"editedBy\":\"OWNER\",\"flags\":[],\"id\":5,\"type\":\"company\",\"updated\":\"2018-05-25T15:11:22Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid2/contact/1/company/5\",\"value\":\"Redacted\"},{\"categories\":[],\"created\":\"2014-06-13T15:19:15Z\",\"editedBy\":\"OWNER\",\"flags\":[],\"id\":1,\"type\":\"email\",\"updated\":\"2014-06-13T15:19:15Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid2/contact/1/email/1\",\"value\":\"testuser2@yahoo.com\"}],\"id\":1,\"isConnection\":false,\"op\":\"add\",\"restoredId\":0,\"updated\":\"2018-05-25T15:11:22Z\",\"uri\":\"http://social.yahooapis.com/v1/user/test-guid2/contact/1\"}]}}";
        final JsonNode jsonResponse = OAuth2JsonUtilities.stringToJson(jsonData);
        expect(importer.getContactsRequest(anyObject(), anyObject())).andReturn(jsonResponse);
        // expect 2 fake contacts to be parsed
        YahooContactsUtil.parseYContact(anyObject(), anyObject());
        PowerMock.expectLastCall().andReturn(null).times(2);

        replay(mockConfig);
        replay(mockSource);
        replay(importer);
        PowerMock.replay(YahooContactsUtil.class);

        importer.importData(null, true);

        verify(mockConfig);
        verify(mockSource);
        verify(importer);
        PowerMock.verify(YahooContactsUtil.class);
    }

}
