# `zm-oauth-social`

> Zimbra OAuth2 Social Service

This service provides an interface for users to register for social service sync operations. (e.g. daily contacts import from non-zimbra accounts).

---

## Installation

**Pre-Requisites**

The `zm-mailbox` project must be built and deployed to the `.zcs-deps` folder.

The `zm-build` and `zm-zcs` projects should also reside in the same local parent folder as this project.


**Deploying the extension from CLI**

For testing purposes you can build and and deploy the extension to `/opt/zimbra/lib/ext/zm-oauth-social` by running the following:

```sh
ant deploy
```

Afterwards, add the necessary configuration to the `/opt/zimbra/conf/localconfig.xml` file, then become the `zimbra` user, and perform a `zmmailboxdctl restart`.

**Testing from CLI**

```sh
ant test
```

---

## Usage

**API**

See the [documentation for api usage].

After a user completes the oauth2 flow, the credentials for their account will be stored as a data source with a configured folder created in the user's root mailbox during authentication. If an import class is associated, it can be triggered manually with a `zmsoap` import data request.

---

## Configuration

This service's configuration can all be found in Zimbra's `localconfig.xml` file (usually located at `/opt/zimbra/conf/localconfig.xml`)

**Localconfig General Properties**


| Key | Description | Optional | Example Options |
| --- | ----------- | -------- | --------------- |
| zm_oauth_classes_handlers_yahoo<sup>1</sup> | The handler implementation class for the client | | `com.zimbra.oauth.handlers.impl.YahooOAuth2Handler` |

<sup>1</sup>Replace the `yahoo` part of the key name with the name of the client (e.g. `yahoo`, `google`, `outlook`).


**Localconfig Client Specific Properties**

**Yahoo Implementation Properties**

| Key | Description | Optional | Example Options |
| --- | ----------- | -------- | --------------- |
| zm_oauth_yahoo_client_id | The Yahoo app's client id | | |
| zm_oauth_yahoo_client_secret | The Yahoo app's client secret | | |
| zm_oauth_yahoo_client_redirect_uri | The callback Yahoo returns the user to | | `https://this.service.host.com/service/extension/oauth2/authenticate/yahoo` |


**Google Implementation Properties**

| Key | Description | Optional | Example Options |
| --- | ----------- | -------- | --------------- |
| zm_oauth_google_client_id | The Google app's client id | | |
| zm_oauth_google_client_secret | The Google app's client secret | | |
| zm_oauth_google_client_redirect_uri | The callback Google returns the user to | | `https://this.service.host.com/service/extension/oauth2/authenticate/google` |
| zm_oauth_google_scope | The token scope to request | | `profile` |


**Facebook Implementation Properties**

| Key | Description | Optional | Example Options |
| --- | ----------- | -------- | --------------- |
| zm_oauth_facebook_client_id | The Facebook app's client id | | |
| zm_oauth_facebook_client_secret | The Facebook app's client secret | | |
| zm_oauth_facebook_client_redirect_uri | The callback Facebook returns the user to | | `https://this.service.host.com/service/extension/oauth2/authenticate/facebook` |
| zm_oauth_facebook_scope | The token scope to request | | `profile` |


[documentation for api usage]: http://tools.email.dev.opal.synacor.com/zm-oauth-social-docs-latest/