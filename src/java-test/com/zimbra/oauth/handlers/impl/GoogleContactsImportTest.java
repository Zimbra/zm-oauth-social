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
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.mime.ParsedContact;
import com.zimbra.oauth.handlers.impl.GoogleContactsImport.GoogleContactsUtil;
import com.zimbra.oauth.handlers.impl.GoogleOAuth2Handler.GoogleContactConstants;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;

/**
 * Test class for {@link GoogleContactsImport}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ DataSource.class, GoogleContactsImport.class, GoogleContactsUtil.class })
public class GoogleContactsImportTest {

    /**
     * Class under test.
     */
    protected GoogleContactsImport importer;

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
        importer = PowerMock.createPartialMock(GoogleContactsImport.class, new String[] { "refresh",
            "buildContactsUrl", "getContactsRequest", "getExistingContacts", "parseNewContacts" },
            mockSource, mockConfig);

        PowerMock.mockStatic(GoogleContactsUtil.class);
    }

    /**
     * Test method for {@link GoogleContactsImport#importData}<br>
     * Validates that the method fetches contacts and passes along to parse
     * utilites.
     *
     * @throws Exception If there are issues testing
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testImportData() throws Exception {
        expect(mockSource.getMailbox()).andReturn(null);
        expect(mockSource.getFolderId()).andReturn(folderId);
        expect(mockSource.getMultiAttr(anyObject())).andReturn(new String[] {});
        // expect a fetch for existing contacts
        expect(importer.getExistingContacts(anyObject(), eq(folderId)))
            .andReturn(new HashSet<String>());
        // expect a fetch for refresh token
        expect(importer.refresh()).andReturn(accessToken);
        // expect buildContactsUrl to be called
        expect(importer.buildContactsUrl(anyObject(), anyObject(), anyObject()))
            .andReturn(GoogleContactConstants.CONTACTS_URI.getValue());
        final String jsonData = "{\"connections\":[{\"biographies\":[{\"contentType\":\"TEXT_PLAIN\",\"value\":\"lionnsss!\"}],\"emailAddresses\":[{\"value\":\"lionel@example.com\"}],\"etag\":\"fake-etag\",\"names\":[{\"displayName\":\"Lionel Ronkerts\",\"displayNameLastFirst\":\"Ronkerts, Lionel\",\"familyName\":\"Ronkerts\",\"givenName\":\"Lionel\",\"metadata\":{\"primary\":true,\"source\":{\"id\":\"fake-id\",\"type\":\"CONTACT\"}}}],\"organizations\":[{\"name\":\"Synacor\",\"title\":\"Tester\"}],\"photos\":[{\"default\":true,\"metadata\":{\"primary\":true,\"source\":{\"id\":\"fake-id\",\"type\":\"CONTACT\"}},\"url\":\"https://example.com/photo.jpg\"}],\"resourceName\":\"people/fake-people-id\"}],\"totalItems\":9,\"totalPeople\":9}";
        final JsonNode jsonResponse = OAuth2JsonUtilities.stringToJson(jsonData);
        expect(importer.getContactsRequest(anyObject(), anyObject())).andReturn(jsonResponse);
        // expect parse new contacts to be called
        importer.parseNewContacts(anyObject(Set.class), anyObject(JsonNode.class),
            anyObject(List.class));
        PowerMock.expectLastCall();

        replay(mockConfig);
        replay(mockSource);
        replay(importer);

        importer.importData(null, true);

        verify(mockConfig);
        verify(mockSource);
        verify(importer);
    }

    /**
     * Test method for {@link GoogleContactsImport#parseNewContacts}<br>
     * Validates that the method adds a contact to the create list when it does
     * not already exist.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testParseNewContacts() throws Exception {
        final GoogleContactsImport localImporter = PowerMock
            .createPartialMockForAllMethodsExcept(GoogleContactsImport.class, "parseNewContacts");
        final Set<String> existingContacts = new HashSet<String>();
        existingContacts.add("people/different-id");
        final String jsonData = "{\"connections\":[{\"biographies\":[{\"contentType\":\"TEXT_PLAIN\",\"value\":\"lionnsss!\"}],\"emailAddresses\":[{\"value\":\"lionel@example.com\"}],\"etag\":\"fake-etag\",\"names\":[{\"displayName\":\"Lionel Ronkerts\",\"displayNameLastFirst\":\"Ronkerts, Lionel\",\"familyName\":\"Ronkerts\",\"givenName\":\"Lionel\",\"metadata\":{\"primary\":true,\"source\":{\"id\":\"fake-id\",\"type\":\"CONTACT\"}}}],\"organizations\":[{\"name\":\"Synacor\",\"title\":\"Tester\"}],\"photos\":[{\"default\":true,\"metadata\":{\"primary\":true,\"source\":{\"id\":\"fake-id\",\"type\":\"CONTACT\"}},\"url\":\"https://example.com/photo.jpg\"}],\"resourceName\":\"people/fake-people-id\"}],\"totalItems\":9,\"totalPeople\":9}";
        final JsonNode jsonResponse = OAuth2JsonUtilities.stringToJson(jsonData);
        final JsonNode jsonContacts = jsonResponse.get("connections");
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();

        localImporter.parseNewContacts(existingContacts, jsonContacts, createList);

        assertEquals(1, createList.size());
    }

    /**
     * Test method for {@link GoogleContactsImport#parseNewContacts}<br>
     * Validates that the method does not add a contact to the create list when
     * it already exists.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testParseNewContactsWhenExists() throws Exception {
        final GoogleContactsImport localImporter = PowerMock
            .createPartialMockForAllMethodsExcept(GoogleContactsImport.class, "parseNewContacts");
        final Set<String> existingContacts = new HashSet<String>();
        existingContacts.add("people/fake-people-id");
        final String jsonData = "{\"connections\":[{\"biographies\":[{\"contentType\":\"TEXT_PLAIN\",\"value\":\"lionnsss!\"}],\"emailAddresses\":[{\"value\":\"lionel@example.com\"}],\"etag\":\"fake-etag\",\"names\":[{\"displayName\":\"Lionel Ronkerts\",\"displayNameLastFirst\":\"Ronkerts, Lionel\",\"familyName\":\"Ronkerts\",\"givenName\":\"Lionel\",\"metadata\":{\"primary\":true,\"source\":{\"id\":\"fake-id\",\"type\":\"CONTACT\"}}}],\"organizations\":[{\"name\":\"Synacor\",\"title\":\"Tester\"}],\"photos\":[{\"default\":true,\"metadata\":{\"primary\":true,\"source\":{\"id\":\"fake-id\",\"type\":\"CONTACT\"}},\"url\":\"https://example.com/photo.jpg\"}],\"resourceName\":\"people/fake-people-id\"}],\"totalItems\":9,\"totalPeople\":9}";
        final JsonNode jsonResponse = OAuth2JsonUtilities.stringToJson(jsonData);
        final JsonNode jsonContacts = jsonResponse.get("connections");
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();

        localImporter.parseNewContacts(existingContacts, jsonContacts, createList);

        assertEquals(0, createList.size());
    }

}
