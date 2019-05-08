var clientInfo = {
    client_id: 'client id _ eWv5RHdwedI=',
    redirect_uri: 'https://spa.safewhere.local/login-callback.html',
  };

  var providerInfo = OIDC.discover('https://dev55.safewhere.local/runtime/');
  OIDC.setClientInfo(clientInfo);
  OIDC.setProviderInfo(providerInfo);
  OIDC.storeInfo(providerInfo, clientInfo);
  // Remove State and Nonce from previous session
  sessionStorage.removeItem('state');
  sessionStorage.removeItem('nonce');
  loginRequest = OIDC.generateLoginRequest({ response_type: 'token' });