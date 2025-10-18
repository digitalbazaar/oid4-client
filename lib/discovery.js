/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {assert, fetchJSON} from './util.js';

const WELL_KNOWN_REGEX = /\/\.well-known\/([^\/]+)/;

export async function discoverIssuer({issuerConfigUrl, agent} = {}) {
  try {
    assert(issuerConfigUrl, 'issuerConfigUrl', 'string');

    const response = await fetchJSON({url: issuerConfigUrl, agent});
    if(!response.data) {
      const error = new Error('Issuer configuration format is not JSON.');
      error.name = 'DataError';
      throw error;
    }
    const {data: issuerMetaData} = response;
    const {issuer, authorization_server} = issuerMetaData;

    if(authorization_server && authorization_server !== issuer) {
      // not yet implemented
      throw new Error('Separate authorization server not yet implemented.');
    }

    // validate `issuer`
    if(!(typeof issuer === 'string' && issuer.startsWith('https://'))) {
      const error = new Error('"issuer" is not an HTTPS URL.');
      error.name = 'DataError';
      throw error;
    }

    // ensure `credential_issuer` matches `issuer`, if present
    const {credential_issuer} = issuerMetaData;
    if(credential_issuer !== undefined && credential_issuer !== issuer) {
      const error = new Error('"credential_issuer" must match "issuer".');
      error.name = 'DataError';
      throw error;
    }

    /* Validate `issuer` value against `issuerConfigUrl` (per RFC 8414):

    The `origin` and `path` element must be parsed from `issuer` and checked
    against `issuerConfigUrl` like so:

    For issuer `<origin>` (no path), `issuerConfigUrl` must match:
    `<origin>/.well-known/<any-path-segment>`

    For issuer `<origin><path>`, `issuerConfigUrl` must be:
    `<origin>/.well-known/<any-path-segment><path>` */
    const {pathname: wellKnownPath} = new URL(issuerConfigUrl);
    const anyPathSegment = wellKnownPath.match(WELL_KNOWN_REGEX)[1];
    const {origin, pathname} = new URL(issuer);
    let expectedConfigUrl = `${origin}/.well-known/${anyPathSegment}`;
    if(pathname !== '/') {
      expectedConfigUrl += pathname;
    }
    if(issuerConfigUrl !== expectedConfigUrl) {
      // alternatively, against RFC 8414, but according to OID4VCI, make sure
      // the issuer config URL matches:
      // <origin><path>/.well-known/<any-path-segment>
      expectedConfigUrl = origin;
      if(pathname !== '/') {
        expectedConfigUrl += pathname;
      }
      expectedConfigUrl += `/.well-known/${anyPathSegment}`;
      if(issuerConfigUrl !== expectedConfigUrl) {
        const error = new Error('"issuer" does not match configuration URL.');
        error.name = 'DataError';
        throw error;
      }
    }

    // fetch AS meta data
    const asMetaDataUrl =
      `${origin}/.well-known/oauth-authorization-server${pathname}`;
    const asMetaDataResponse = await fetchJSON({url: asMetaDataUrl, agent});
    if(!asMetaDataResponse.data) {
      const error = new Error('Authorization server meta data is not JSON.');
      error.name = 'DataError';
      throw error;
    }

    const {data: asMetaData} = response;
    // merge AS meta data into total issuer config
    const issuerConfig = {...issuerMetaData, ...asMetaData};

    // ensure `token_endpoint` is valid
    const {token_endpoint} = asMetaData;
    assert(token_endpoint, 'token_endpoint', 'string');

    // return merged config and separate issuer and AS configs
    const metadata = {issuer: issuerMetaData, authorizationServer: asMetaData};
    return {issuerConfig, metadata};
  } catch(cause) {
    const error = new Error('Could not get OpenID issuer configuration.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}

export async function robustDiscoverIssuer({issuer, agent} = {}) {
  // try issuer config URLs based on OID4VCI (first) and RFC 8414 (second)
  const parsedIssuer = new URL(issuer);
  const {origin} = parsedIssuer;
  const path = parsedIssuer.pathname === '/' ? '' : parsedIssuer.pathname;

  const issuerConfigUrls = [
    // OID4VCI
    `${origin}${path}/.well-known/openid-credential-issuer`,
    // RFC 8414
    `${origin}/.well-known/openid-credential-issuer${path}`
  ];

  let error;
  for(const issuerConfigUrl of issuerConfigUrls) {
    try {
      const config = await discoverIssuer({issuerConfigUrl, agent});
      return config;
    } catch(e) {
      error = e;
    }
  }
  throw error;
}
