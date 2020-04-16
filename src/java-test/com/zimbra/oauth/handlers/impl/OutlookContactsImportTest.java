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
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.http.client.HttpClient;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.junit4.PowerMockRunner;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.util.Pair;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.mime.ParsedContact;
import com.zimbra.oauth.handlers.impl.OutlookContactsImport.OutlookContactsUtil;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * Test class for {@link OutlookContactsImport}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ DataSource.class, HttpClient.class, OAuth2Utilities.class, OutlookContactsImport.class, OutlookContactsUtil.class })
@SuppressStaticInitializationFor("org.apache.commons.httpclient.HttpClient")
public class OutlookContactsImportTest {

    /**
     * Class under test.
     */
    protected OutlookContactsImport importer;

    /**
     * Access token for testing.
     */
    protected final String accessToken = "test-access-token";

    /**
     * Folder id for testing.
     */
    protected final int folderId = 2002;

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
        importer = PowerMock.createPartialMock(OutlookContactsImport.class,
            new String[] { "refresh", "ensureFolder", "getContactFolders", "getContactsRequest",
                "getExistingContacts", "parseNewContacts" },
            mockSource, mockConfig);

        PowerMock.mockStatic(OutlookContactsUtil.class);
    }

    /**
     * Test method for {@link OutlookContactsImport#importData}<br>
     * Validates that the method fetches contacts and passes along to parse
     * utilities.
     *
     * @throws Exception If there are issues testing
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testImportData() throws Exception {
        final int childFolderId = folderId + 1;
        final List<Pair<String, String>> contactFolders = Arrays.asList(
            new Pair<String, String>(null, null),
            new Pair<String, String>("testId", "Test Folder"));
        expect(mockSource.getMailbox()).andReturn(null);
        expect(mockSource.getFolderId()).andReturn(folderId);
        // expect a fetch for refresh token
        expect(importer.refresh()).andReturn(accessToken);
        // expect getContactFolders to be called
        expect(importer.getContactFolders(matches("Bearer " + accessToken)))
            .andReturn(contactFolders);
        // expect ensureFolder to be called for the root folder
        expect(importer.ensureFolder(anyObject(), eq(folderId), EasyMock.isNull()))
            .andReturn(folderId);
        // expect ensureFolder to be called for the child folder
        expect(importer.ensureFolder(anyObject(), eq(folderId), matches("Test Folder")))
            .andReturn(childFolderId);
        // expect a fetch for existing contacts for the root folder
        expect(importer.getExistingContacts(anyObject(), eq(folderId)))
            .andReturn(new HashSet<String>());
        // expect a fetch for existing contacts for the child folder
        expect(importer.getExistingContacts(anyObject(), eq(childFolderId)))
            .andReturn(new HashSet<String>());
        final String jsonData = "{\"@odata.context\":\"https://outlook.office.com/api/v2.0/$metadata#Me/Contacts(EmailAddresses,GivenName,Surname)\",\"@odata.deltaLink\":\"https://outlook.office.com/api/v2.0/me/contacts/?%24select=EmailAddresses%2cGivenName%2cSurname&%24deltatoken=b_o5fakeToken\",\"value\":[{\"@odata.etag\":\"W/\\\"fake-tag\\\"\",\"@odata.id\":\"https://outlook.office.com/api/v2.0/Users('fake-id')/Contacts('fake-id')\",\"EmailAddresses\":[{\"Address\":\"test2@synacor.net\",\"Name\":\"test2@synacor.net\"},{\"Address\":\"test3@synacor.net\",\"Name\":\"test3@synacor.net\"}],\"GivenName\":\"Test\",\"Id\":\"fake-user-id=\",\"Surname\":\"User\"}]}";
        final JsonNode jsonResponse = OAuth2JsonUtilities.stringToJson(jsonData);
        // expect getContactsRequest to be called 4 times (twice for each folder)
        expect(importer.getContactsRequest(anyObject(), anyObject())).andReturn(jsonResponse).times(4);
        // expect parse new contacts to be called 4 times (twice for each folder)
        importer.parseNewContacts(anyObject(Set.class), anyObject(JsonNode.class),
            anyObject(List.class));
        PowerMock.expectLastCall().times(4);

        replay(mockConfig);
        replay(mockSource);
        replay(importer);

        importer.importData(null, true);

        verify(mockConfig);
        verify(mockSource);
        verify(importer);
    }

    /**
     * Test method for {@link OutlookContactsImport#parseNewContacts}<br>
     * Validates that the method adds a contact to the create list when it does
     * not already exist.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testParseNewContacts() throws Exception {
        final HttpClient mockClient = EasyMock.createMock(HttpClient.class);
        PowerMock.mockStaticPartial(OAuth2Utilities.class, "getHttpClient");
        OAuth2Utilities.getHttpClient();
        PowerMock.expectLastCall().andReturn(mockClient);
        final OutlookContactsImport localImporter = PowerMock
            .createPartialMockForAllMethodsExcept(OutlookContactsImport.class, "parseNewContacts");
        final Set<String> existingContacts = new HashSet<String>();
        existingContacts.add("some-different-id");
        final String jsonData = "{\"@odata.context\":\"https://outlook.office.com/api/v2.0/$metadata#Me/Contacts(EmailAddresses,GivenName,Surname)\",\"@odata.deltaLink\":\"https://outlook.office.com/api/v2.0/me/contacts/?%24select=EmailAddresses%2cGivenName%2cSurname&%24deltatoken=b_o5fakeToken\",\"value\":[{\"@odata.etag\":\"W/\\\"fake-tag\\\"\",\"@odata.id\":\"https://outlook.office.com/api/v2.0/Users('fake-id')/Contacts('fake-id')\",\"EmailAddresses\":[{\"Address\":\"test2@synacor.net\",\"Name\":\"test2@synacor.net\"},{\"Address\":\"test3@synacor.net\",\"Name\":\"test3@synacor.net\"}],\"GivenName\":\"Test\",\"Id\":\"fake-user-id=\",\"Surname\":\"User\"}]}";
        final JsonNode jsonResponse = OAuth2JsonUtilities.stringToJson(jsonData);
        final JsonNode jsonContacts = jsonResponse.get("value");
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();

        localImporter.parseNewContacts(existingContacts, jsonContacts, createList);

        assertEquals(1, createList.size());
    }

    /**
     * Test method for {@link OutlookContactsImport#parseNewContacts}<br>
     * Validates that the method does not add a contact to the create list when
     * it already exists.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testParseNewContactsWhenExists() throws Exception {
        final HttpClient mockClient = EasyMock.createMock(HttpClient.class);
        PowerMock.mockStaticPartial(OAuth2Utilities.class, "getHttpClient");
        OAuth2Utilities.getHttpClient();
        PowerMock.expectLastCall().andReturn(mockClient);
        final OutlookContactsImport localImporter = PowerMock
            .createPartialMockForAllMethodsExcept(OutlookContactsImport.class, "parseNewContacts");
        final Set<String> existingContacts = new HashSet<String>();
        existingContacts.add("fake-user-id=");
        final String jsonData = "{\"@odata.context\":\"https://outlook.office.com/api/v2.0/$metadata#Me/Contacts(EmailAddresses,GivenName,Surname)\",\"@odata.deltaLink\":\"https://outlook.office.com/api/v2.0/me/contacts/?%24select=EmailAddresses%2cGivenName%2cSurname&%24deltatoken=b_o5fakeToken\",\"value\":[{\"@odata.etag\":\"W/\\\"fake-tag\\\"\",\"@odata.id\":\"https://outlook.office.com/api/v2.0/Users('fake-id')/Contacts('fake-id')\",\"EmailAddresses\":[{\"Address\":\"test2@synacor.net\",\"Name\":\"test2@synacor.net\"},{\"Address\":\"test3@synacor.net\",\"Name\":\"test3@synacor.net\"}],\"GivenName\":\"Test\",\"Id\":\"fake-user-id=\",\"Surname\":\"User\"}]}";
        final JsonNode jsonResponse = OAuth2JsonUtilities.stringToJson(jsonData);
        final JsonNode jsonContacts = jsonResponse.get("value");
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();

        localImporter.parseNewContacts(existingContacts, jsonContacts, createList);

        assertEquals(0, createList.size());
    }

}
