"use strict";

const MUST = 'MUST';
const MAY = 'MAY';
const SHOULD = 'SHOULD';

const SOLID = 'Solid';
const OPENID = 'OpenID';
const OAUTH2 = 'OAuth 2.0';

/** A class for representing link headers. */
class Link {
  constructor(uri, params) {
    this.uri = uri;
    this.params = params;
  }

  get rel() {
    return this.params['rel'];
  }

  static parse(value) {
    const parts = value.split(/;\s*/, 2);
    const uri = parts[0].trim().replace(/^</, '').replace(/>$/, '');
    const params = {}
    parts.slice(1).map(x => x.split('=', 2)).filter(x => x.length === 2)
      .forEach(x => params[x[0]] = x[1].replace(/^"/, '').replace(/"$/, ''));
    return new Link(uri, params);
  }
}

/** Base test suite class */
class TestSuite {

  constructor(spec) {
    this.spec = spec;
  }

  run() {
    Reflect.ownKeys(Reflect.getPrototypeOf(this))
      .filter(name => name !== 'constructor')
      .forEach(name => this[name]());
  }

  report(id, status, message) {
    const item = this.spec[id];
    if (item) {
      const data = {
        label: item.label,
        level: item.requirementLevel,
        status: TestSuite.statusClass(status),
        description: item.comment,
        message: message,
        uri: item.requirementReference };

      window.top.postMessage(data, window.location.origin);
    } else {
      throw `Invalid identifier: [${id}]`;
    }
  }

  static statusClass(status) {
    switch(status) {
      case true:
        return 'pass';
      case false:
        return 'fail';
      default:
        return 'skip';
    }
  }
}

/** ID Token test suite */
class IDTokenSuite extends TestSuite {
  constructor(spec, clientId, issuer, token) {
    super(spec);
    this.clientId = clientId;
    this.issuer = issuer;
    this.token = token;
  }

  tokenType() {
    this.report('TokenType', this.token.token_type === 'DPoP',
      'Verify that the token_type value equals "DPoP".');
  }

  tokenIdIssuer() {
    const idToken = JOSE.parse(this.token.id_token);
    this.report('IdTokenIssuerClaim', idToken.body.iss === this.issuer,
      'Verify that the token "iss" claim equals the "issuer" field in the server metadata.');
  }

  tokenValidation() {
    JOSE.validate(this.token.id_token).then(status =>
      this.report('IdTokenValidation', status,
        'Verify that the token passes JWT validation.'));
  }

  tokenAudience() {
    const idToken = JOSE.parse(this.token.id_token);
    this.report('IdTokenAudienceClaim', idToken.body.aud === this.clientId,
      'Verify that the "aud" claim includes the client_id.');
  }

  tokenWebId() {
    const idToken = JOSE.parse(this.token.id_token);
    this.report('IdTokenWebidClaim', idToken.body.webid?.startsWith('https://'),
      'Verify that the "webid" claim is present in the ID Token.');
  }

  tokenDerefWebIdHeaders() {
    const idToken = JOSE.parse(this.token.id_token);
    fetch(idToken.body.webid).then(res => res.headers.get('Link')).then(links =>
      this.report('WebidHeaderDiscovery',
        links?.split(/,\s*(?:<)/).map(l => Link.parse(l))
          .filter(l => l.rel === 'http://www.w3.org/ns/solid/terms#oidcIssuer')
          .map(l => l.uri).includes(idToken.body.iss),
        `Verify that the solid:oidcIssuer relation is present in the response link headers: [${links || 'n/a'}].`));
  }

  tokenIatClaim() {
    const idToken = JOSE.parse(this.token.id_token);
    this.report('IdTokenIatClaim', idToken.body.iat < Date.now() / 1000 + 60,
      `Verify that the "iat" value is not in the future: ${idToken.body.iat}.`);
  }

  tokenExpClaim() {
    const idToken = JOSE.parse(this.token.id_token);
    this.report('IdTokenExpClaim', idToken.body.exp > Date.now() / 1000,
      `Verify that the 'exp' value is not in the past: ${idToken.body.exp}.`);
  }
}

/** Discovery Test Suite */
class DiscoverySuite extends TestSuite {

  constructor(spec, metadata) {
    super(spec);
    this.metadata = metadata;
  }

  discoveryIssuer() {
    this.report('MetadataIssuer', this.metadata.issuer?.startsWith('http'),
      'Verify that the "issuer" field is present.');
  }

  discoveryClaimSupport() {
    this.report('MetadataWebidClaim',
      this.metadata.claims_supported?.includes('webid'),
      'Verify that "webid" is included in the "claims_supported" field.');
  }

  discoveryPkceSupport() {
    this.report('MetadataProofKeyCodeExchange',
      this.metadata.code_challenge_methods_supported?.includes('S256'),
      'Verify that the "S256" algorithm is included in the "code_challenge_methods_supported" field.');
  }

  discoveryGrantTypeSupport() {
    this.report('MetadataAuthorizationCodeGrant',
      this.metadata.grant_types_supported?.includes('authorization_code'),
      'Verify that the "authorization_code" flow is included in the "grant_types_supported" field.');
  }

  discoveryDpopSupport() {
    this.report('MetadataDpopAlgorithm',
      this.metadata.dpop_signing_alg_values_supported?.some(alg => ['ES256', 'RS256'].includes(alg)),
      'Verify that the "dpop_signing_alg_values_supported" field includes either "ES256" or "RS256".');
  }

  discoverySigningAlgSupport() {
    this.report('MetadataSigningAlgorithm',
      this.metadata.id_token_signing_alg_values_supported?.includes('RS256'),
      'Verify that the "RS256" algorithm is included in the "id_token_signing_alg_values_supported" field.');
  }

  discoveryDynamicRegistrationSupport() {
    this.report('MetadataDynamicRegistration',
      this.metadata.registration_endpoint != null,
      'Verify whether dynamic client registration is supported.');
  }

  discoveryLogoutSupport() {
    this.report('MetadataLogout',
      this.metadata.end_session_endpoint != null,
      'Verify whether client-initiated logout is supported.');
  }

  discoveryResponseTypeSupport() {
    this.report('MetadataResponseType',
      this.metadata.response_types_supported?.includes('code'),
      'Verify that the "code" response is included in the "response_types_supported" field.');
  }

  discoveryScopeSupport() {
    this.report('MetadataWebidScope',
      this.metadata.scopes_supported?.includes('webid'),
      'Verity that the "webid" scope is included in the "scopes_supported" field');
  }
}
