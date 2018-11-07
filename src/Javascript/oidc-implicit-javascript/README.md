# Safewhere-Identify-samples/OAuth 2.0/oidc-implicit-javascript
This is an SPA (single page application) sample which works against Identify OAuth 2.0 service. 
It aims to illustrate how a SPA could negotiate token from Identify OAuth 2.0 using implicit grant type on OpenId Connect flow.

# Configuration
## Client configuration
All the settings are placed on implicit-test.html as follows
- client_id
- redirect_uri
- providerInfo
- scope

Assumed that SPA sample is deployed at https://spa.safewhere.local, and Identify OAuth is at https://develop.safewhere.local/runtime/ the above settings will be
- client_id: [a client id]
- redirect_uri: https://spa.safewhere.local/login-callback.html
- providerInfo: https://develop.safewhere.local/runtime/
- scope: it depends, plus 'openid' scope. Default ones are 'read', 'write' and 'openid'.

## Identify configuration
There must be an OAuth 2.0 protocol configuration. More details about Identify OAuth 2.0 protocol connection can be found on https://docs.safewhere.com
To be more specific in this sample, OAuth 2.0 protocol configuration needs follows
+ client_id, redirect_uri: as specified on the above spa's configuration
+ client_secret: input the dummy value.
+ user needs to enable the settings: Allow implicit flow  and Use as OpenID Connect 
+ its scope: must include the ones specified on the above spa's configuration. Default values are "read", "write" and "Openid".

An noticiable point is that CORS support must be enabled in Identify's system setup to enable cross-site requests between Identify and SPA sample.
That means the SPA's address must be put on setting "Allowed domains in CORS origins header" of Identify system setup

# Execute
After the client finished his setup, he can try to access https://spa.safewhere.local/implicit-test.html to verify its run

