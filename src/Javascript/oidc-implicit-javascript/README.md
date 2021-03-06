# Safewhere-Identify-samples/OAuth 2.0/oidc-implicit-javascript
This is an SPA (single page application) sample which works against Identify OAuth 2.0 service. 
It aims to illustrate how a SPA could negotiate token from Identify OAuth 2.0 using implicit grant type on OpenId Connect flow.

# Configuration
## Client configuration
All the settings are placed on config.js as follows
- client_id
- redirect_uri
- providerInfo
- scope: it must include the 'openid' scope. Default ones are 'read', 'write' and 'openid'.

Assumed that SPA sample is deployed at https://spa.safewhere.local, and Identify OAuth is at https://develop.safewhere.local/runtime/ the above settings will be
- client_id: [a client id]
- redirect_uri: https://spa.safewhere.local/login-callback.html
- providerInfo: https://develop.safewhere.local/runtime/
- scope: specify scopes needed, default value is 'openid' ('openid' is required)

If you are in NodeJS development environment, you could use built-in self hosting: open command promt and navigate to oidc-implicit-javascript folder and type 'npm start' to start web server listening on https://localhost:44307. Identify OAuth is at https://develop.safewhere.local/runtime/ the above settings will be
- client_id: [a client id]
- redirect_uri: https://localhost:44307/login-callback.html
- providerInfo: https://develop.safewhere.local/runtime/
- scope: specify scopes needed, default value is 'openid' ('openid' is required)

## Identify configuration
There must be an OAuth 2.0 protocol configuration. More details about Identify OAuth 2.0 protocol connection can be found on https://docs.safewhere.com
To be more specific in this sample, OAuth 2.0 protocol configuration needs follows
- client_id, redirect_uri: as specified on the above spa's configuration
- client_secret: input the dummy value.
- Enable options: Allow implicit flow and Use as OpenID Connect
- Scope:  with the default settings configured on client side, those scopes: 'read', 'write', 'openid' neeeds to be added.

An noticiable point is that CORS support must be enabled in Identify's system setup to enable cross-site requests between Identify and SPA sample.
That means the SPA's address must be put on setting "Allowed domains in CORS origins header" of Identify system setup
* Notice that this setting is only available from Identify 5.4++ 

# Execute
After the client finished his setup, he can try to access https://spa.safewhere.local/implicit-test.html or https://localhost:44307/implicit-test.html to verify its run.

