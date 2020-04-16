# `zm-oauth-social`

> Zimbra OAuth2 Social Service

This service provides an interface for users to register for social service sync operations. (e.g. daily contacts import from non-zimbra accounts).

---

## Installation

**Pre-Requisites**

The `zm-mailbox` project must be built and deployed to the `.zcs-deps` folder.

The `zm-build` and `zm-zcs` projects should also reside in the same local parent folder as this project.


**Deploying the extension from CLI**

For testing purposes you can build and deploy the extension to `/opt/zimbra/lib/ext/zm-oauth-social` by running the following:

```sh
ant deploy
```

Afterwards, configure ldap and localconfig as necessary, then become the `zimbra` user, and perform a `zmmailboxdctl restart`.

**Testing from CLI**

```sh
ant test
```

---

## Usage

**API**

See the [documentation for api usage].

After a user completes the oauth2 flow, the credentials for their account will be stored as a data source with a configured folder created in the user's root mailbox during authentication. The import is triggered after successful completion of the OAuth flow. An import can also be triggered manually with a `zmsoap` import data request.

**Resources**

| Path | Description | Response Type |
| ---- | ----------- | ------------- |
| `/service/extension/oauth2/authorize/{client}` | Initiates the oauth2 flow with a redirect response. | HTTP Redirect |
| `/service/extension/oauth2/authenticate/{client}` | Callback url for the social service in the oauth2 flow | HTTP Redirect |
| `/service/extension/oauth2/refresh/{client}/{identifier}` | Acquires and returns a new access token for the identified social account (limited support) | JSON |
| `/service/extension/oauth2/info/{client}` | Returns info for the specified client | JSON |
| `/service/extension/oauth2/event/{client}` | This is currently only used by Zoom for deauthorization | 202 Accepted |
| `/service/extension/oauth2-proxy/{client}?target={target}` | Similar to the Zimlet ProxyServlet, attaches configured Authorization header for the specified client. | Varies, JSON on error |

---

## Configuration

This service's configuration for OAuth clients are setup in Ldap attributes on a global or domain level.

**Ldap Properties**

See the [client setup wiki].

| Key | Description | Required By | Template |
| --- | ----------- | ----------- | -------- |
| zimbraOAuthConsumerCredentials | OAuth credentials for a client, set at global config or domain level. | All | `<client-id>:<client-secret>:<client>` |
| zimbraOAuthConsumerRedirectUri | The callback where the client returns the user too. | All | `http[s]://<domain[:port]>/service/extension/oauth2/authenticate/<client>:<client>` |
| zimbraOAuthConsumerAPIScope | The scopes required to access user data. Types: `contact`, `caldav` | Google, Facebook | `<scope1>+<scope2>+...:<client>_<type>` |

***Client specific scopes to use with the zimbraOAuthConsumerAPIScope config***

| Client | Required scopes string |
| ------ | ---------------------- |
| Google Contact | `https://www.googleapis.com/auth/contacts.readonly+profile:google_contact` |
| Google CalDav | `https://www.googleapis.com/auth/calendar:google_caldav` |
| Facebook | `user_friends,read_custom_friendlists,email,user_location,public_profile,user_about_me,user_birthday,groups_access_member_info:facebook_contact` |
| Outlook | `profile+User.Read+Files.ReadWrite.All:outlook_noop` |
| Outlook Contact | `https%3A%2F%2Foutlook.office.com%2Fcontacts.read:outlook_contact` |
| Slack | `groups:write,team:read,users:read,users:read.email,chat:write,mpim:write:slack_noop` |
| Zoom | `meeting:write:zoom_noop` |

Note: Delimiters can vary across clients.

**Localconfig General Properties**

| Key | Description | Optional | Example Options |
| --- | ----------- | -------- | --------------- |
| zm_oauth_classes_handlers_twitter<sup>1</sup> | The handler implementation class for the client | Yes | `com.zimbra.oauth.handlers.impl.TwitterOAuth2Handler` |

<sup>1</sup>Replace the `twitter` part of the key name with the name of the client (e.g. `yahoo`, `google`, `outlook`).

Localconfig can be found in Zimbra's `localconfig.xml` file (usually located at `/opt/zimbra/conf/localconfig.xml`)

[documentation for api usage]: http://tools.email.dev.opal.synacor.com/zm-oauth-social-docs-latest/
[client setup wiki]: http://wiki.eng.zimbra.com/index.php/Zimbra_OAuth_Social