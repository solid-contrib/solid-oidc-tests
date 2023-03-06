export const CONFIG = {
  clientId: 'https://solid-contrib.github.io/solid-oidc-tests/data/tester.jsonld',
  redirectUri: 'https://solid-contrib.github.io/solid-oidc-tests/callback.html',
  specificationData: 'https://solid-contrib.github.io/solid-oidc-tests/data/solid-oidc.jsonld',
  pkceMethod: 'S256',
  algorithm: {name: 'ECDSA', namedCurve: 'P-256'},
  windowName: '_blank',
  windowFeatures: 'resizable,scrollbars,status,width=600px,height=600px'
};
