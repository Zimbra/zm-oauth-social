# `zm-oauth2`

> Zimbra OAuth2 Service

This service provides an interface for users to provide credentials for storage and use by other Zimbra products. (e.g. daily contacts import from non-zimbra accounts).

---

## Installation

**Pre-Requisites**

The `zm-mailbox` project must be built and deployed to the `.zcs-deps` folder.

The `zm-build` and `zm-zcs` projects should also reside in the same local parent folder as this project.


**Running from CLI**

After building `zm-mailbox` run the following:

```sh
ant run
```


**Building a Tar from CLI**

For testing purposes you can build a tar of this project inependent of the `zm-build` scripts by running the following:

```sh
ant tar
```


**Testing from CLI**

```sh
ant test
```

---

## Usage

**API**

See the [documentation for api usage].

After a user completes the oauth2 flow, the credentials for their account will be stored as a data source in a configured folder, or a default Contact subfolder - which will be created in the user's mailbox, if necessary, during authentication.

---

## Configuration

This service's configuration can all be found in Zimbra's `localconfig.xml` file (usually located at `/opt/zimbra/conf/localconfig.xml`)

**Localconfig General Properties**


| Key | Description | Optional | Example Options |
| --- | ----------- | -------- | --------------- |
| zm_oauth_log_level | The log level for this service |  | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| zm_oauth_server_port | The port to run this service |  | `4040` |
| zm_oauth_server_context_path | The base path of this service |  | `/` |
| host_uri_template | The host uri to connect via ZMailbox | Yes | `https://%s:443` |
| zm_oauth_source_folder_id | The id of the folder to store the user's oauth info | Yes | `247` |
| zm_oauth_classes_handlers_yahoo<sup>1</sup> | The handler implementation class for the client | | `com.zimbra.oauth.handlers.impl.YahooOAuth2Handler` |

<sup>1</sup>Replace the `yahoo` part of the key name with the name of the client (e.g. `yahoo`, `google`, `outlook`).


**Localconfig Client Specific Properties**

**Yahoo Implementation Properties**

| Key | Description | Optional | Example Options |
| --- | ----------- | -------- | --------------- |
| zm_oauth_yahoo_authorize_uri_template | Yahoo's authorize uri template | | `https://api.login.yahoo.com/oauth2/request_auth?client_id=%s&amp;redirect_uri=%s&amp;response_type=%s` |
| zm_oauth_yahoo_profile_uri_template | Yahoo's profile uri template | | `https://social.yahooapis.com/v1/user/%s/profile` |
| zm_oauth_yahoo_authenticate_uri | Yahoo's authenticate uri | | `https://api.login.yahoo.com/oauth2/get_token` |
| zm_oauth_yahoo_client_id | The Yahoo app's client id | | |
| zm_oauth_yahoo_client_secret | The Yahoo app's client secret | | |
| zm_oauth_yahoo_client_redirect_uri | The callback Yahoo returns the user to | | `https://this.service.host.com/oauth2/authenticate/yahoo` |
| zm_oauth_yahoo_relay_key | Yahoo's relay key name | | `state` |


**Google Implementation Properties**

| Key | Description | Optional | Example Options |
| --- | ----------- | -------- | --------------- |
| zm_oauth_google_authorize_uri_template | Google's authorize uri template | | `https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&amp;redirect_uri=%s&amp;response_type=%s&amp;scope=%s` |
| zm_oauth_google_profile_uri_template | Google's profile uri | | `https://www.googleapis.com/auth/userinfo.email` |
| zm_oauth_google_authenticate_uri | Google's authenticate uri | | `https://www.googleapis.com/oauth2/v4/token` |
| zm_oauth_google_client_id | The Google app's client id | | |
| zm_oauth_google_client_secret | The Google app's client secret | | |
| zm_oauth_google_client_redirect_uri | The callback Google returns the user to | | `https://this.service.host.com/oauth2/authenticate/google` |
| zm_oauth_google_scope | The token scope to request | | `profile` |
| zm_oauth_google_relay_key | Google's relay key name | | `state` |


[documentation for api usage]: http://tools.email.dev.opal.synacor.com/zm-oauth2-docs-latest/