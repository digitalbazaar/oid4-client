/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {httpClient} from '@digitalbazaar/http-client';

const TEXT_ENCODER = new TextEncoder();
const ENCODED_PERIOD = TEXT_ENCODER.encode('.');
const WELL_KNOWN_REGEX = /\/\.well-known\/([^\/]+)/;

export async function discoverIssuer({issuerConfigUrl, agent} = {}) {
  try {
    _assert(issuerConfigUrl, 'issuerConfigUrl', 'string');

    const response = await _fetchJSON({url: issuerConfigUrl, agent});
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
      const error = new Error('"issuer" does not match configuration URL.');
      error.name = 'DataError';
      throw error;
    }

    // fetch AS meta data
    const asMetaDataUrl =
      `${origin}/.well-known/oauth-authorization-server${pathname}`;
    const asMetaDataResponse = await _fetchJSON({url: asMetaDataUrl, agent});
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
    _assert(token_endpoint, 'token_endpoint', 'string');

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

export async function generateDIDProofJWT({
  signer, nonce, iss, aud, exp, nbf
} = {}) {
  /* Example:
  {
    "alg": "ES256",
    "kid":"did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1"
  }.
  {
    "iss": "s6BhdRkqt3",
    "aud": "https://server.example.com",
    "iat": 1659145924,
    "nonce": "tZignsnFbp"
  }
  */

  if(exp === undefined) {
    // default to 5 minute expiration time
    exp = Math.floor(Date.now() / 1000) + 60 * 5;
  }
  if(nbf === undefined) {
    // default to now
    nbf = Math.floor(Date.now() / 1000);
  }

  const {id: kid} = signer;
  const alg = _curveToAlg(signer.algorithm);
  const payload = {nonce, iss, aud, exp, nbf};
  const protectedHeader = {alg, kid};

  return signJWT({payload, protectedHeader, signer});
}

// get an authorization request from a verifier
export async function getAuthorizationRequest({
  url, agent, documentLoader
} = {}) {
  try {
    _assert(url, 'url', 'string');
    _assertOptional(documentLoader, 'documentLoader', 'function');

    const response = await _fetchJSON({url, agent});
    if(!response.data) {
      const error = new Error('Authorization request format is not JSON.');
      error.name = 'DataError';
      throw error;
    }

    // parse payload from response data...
    let payload;
    const contentType = response.headers.get('content-type');

    // verify authorization request to get payload if is JWT
    if(contentType.includes('application/oauth-authz-req+jwt')) {
      // FIXME: implement RFC 9101
      payload = {
        presentation_definition: {}
      };
      if(!documentLoader) {
        throw new TypeError(
          '"documentLoader" is required to process JWT-Secured Authorization ' +
          'Request (JAR).');
      }
      const error = new Error(
        'JWT-Secured Authorization Request (JAR) not implemented.');
      error.name = 'NotSupportedError';
      throw error;
    } else {
      payload = response.data;
    }

    // validate payload (expected authorization request)
    const {
      client_id,
      client_id_scheme,
      client_metadata,
      client_metadata_uri,
      nonce,
      presentation_definition,
      presentation_definition_uri,
      response_mode,
      scope
    } = payload;
    _assert(client_id, 'client_id', 'string');
    _assert(nonce, 'nonce', 'string');
    _assertOptional(client_id_scheme, 'client_id_scheme', 'string');
    _assertOptional(client_metadata, 'client_metadata', 'object');
    _assertOptional(client_metadata_uri, 'client_metadata_uri', 'string');
    _assertOptional(
      presentation_definition, 'presentation_definition', 'object');
    _assertOptional(
      presentation_definition_uri, 'presentation_definition_uri', 'string');
    _assertOptional(response_mode, 'response_mode', 'string');
    _assertOptional(scope, 'scope', 'string');
    if(client_metadata && client_metadata_uri) {
      const error = new Error(
        'Only one of "client_metadata" and ' +
        '"client_metadata_uri" must be present.');
      error.name = 'DataError';
      throw error;
    }
    if(presentation_definition && presentation_definition_uri) {
      const error = new Error(
        'Only one of "presentation_definition" and ' +
        '"presentation_definition_uri" must be present.');
      error.name = 'DataError';
      throw error;
    }
    // Note: This implementation requires `response_mode` to be `direct_post`,
    // no other modes are supported.
    if(response_mode !== 'direct_post') {
      const error = new Error(
        'Only "direct_post" response mode is supported.');
      error.name = 'NotSupportedError';
      throw error;
    }

    // build merged authorization request
    const authorizationRequest = {...payload};

    // get client meta data from URL if specified
    if(client_metadata_uri) {
      const response = await _fetchJSON({url: client_metadata_uri, agent});
      if(!response.data) {
        const error = new Error('Client meta data format is not JSON.');
        error.name = 'DataError';
        throw error;
      }
      // FIXME: can `data` be a JWT and require verification as well?
      delete authorizationRequest.client_metadata_uri;
      authorizationRequest.client_metadata = response.data;
    }

    // get presentation definition from URL if not embedded
    if(presentation_definition_uri) {
      const response = await _fetchJSON(
        {url: presentation_definition_uri, agent});
      if(!response.data) {
        const error = new Error('Presentation definition format is not JSON.');
        error.name = 'DataError';
        throw error;
      }
      // FIXME: can `data` be a JWT and require verification as well?
      delete authorizationRequest.presentation_definition_uri;
      authorizationRequest.presentation_definition = response.data;
    }

    // FIXME: validate `authorizationRequest.presentation_definition`

    // return merged authorization request and original response
    return {authorizationRequest, response};
  } catch(cause) {
    const error = new Error('Could not get authorization request.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}

export function parseCredentialOfferUrl({url} = {}) {
  _assert(url, 'url', 'string');

  /* Parse URL, e.g.:

  'openid-credential-offer://?' +
    'credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2F' +
    'localhost%3A18443%2Fexchangers%2Fz19t8xb568tNRD1zVm9R5diXR%2F' +
    'exchanges%2Fz1ADs3ur2s9tm6JUW6CnTiyn3%22%2C%22credentials' +
    '%22%3A%5B%7B%22format%22%3A%22ldp_vc%22%2C%22credential_definition' +
    '%22%3A%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2F' +
    'credentials%2Fv1%22%2C%22https%3A%2F%2Fwww.w3.org%2F2018%2F' +
    'credentials%2Fexamples%2Fv1%22%5D%2C%22type%22%3A%5B%22' +
    'VerifiableCredential%22%2C%22UniversityDegreeCredential' +
    '%22%5D%7D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams' +
    '%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22' +
    'pre-authorized_code%22%3A%22z1AEvnk2cqeRM1Mfv75vzHSUo%22%7D%7D%7D';
  */
  const {protocol, searchParams} = new URL(url);
  if(protocol !== 'openid-credential-offer:') {
    throw new SyntaxError(
      '"url" must express a URL with the ' +
      '"openid-credential-offer" protocol.');
  }
  return JSON.parse(searchParams.get('credential_offer'));
}

export async function signJWT({payload, protectedHeader, signer} = {}) {
  // encode payload and protected header
  const b64Payload = base64url.encode(JSON.stringify(payload));
  const b64ProtectedHeader = base64url.encode(JSON.stringify(protectedHeader));
  payload = TEXT_ENCODER.encode(b64Payload);
  protectedHeader = TEXT_ENCODER.encode(b64ProtectedHeader);

  // concatenate
  const data = new Uint8Array(
    protectedHeader.length + ENCODED_PERIOD.length + payload.length);
  data.set(protectedHeader);
  data.set(ENCODED_PERIOD, protectedHeader.length);
  data.set(payload, protectedHeader.length + ENCODED_PERIOD.length);

  // sign
  const signature = await signer.sign({data});

  // create JWS
  const jws = {
    signature: base64url.encode(signature),
    payload: b64Payload,
    protected: b64ProtectedHeader
  };

  // create compact JWT
  return `${jws.protected}.${jws.payload}.${jws.signature}`;
}

function _curveToAlg(crv) {
  if(crv === 'Ed25519' || crv === 'Ed448') {
    return 'EdDSA';
  }
  if(crv?.startsWith('P-')) {
    return `ES${crv.slice(2)}`;
  }
  if(crv === 'secp256k1') {
    return 'ES256K';
  }
  return crv;
}

function _fetchJSON({url, agent}) {
  // allow these params to be passed / configured
  const fetchOptions = {
    // max size for issuer config related responses (in bytes, ~4 KiB)
    size: 4096,
    // timeout in ms for fetching an issuer config
    timeout: 5000,
    agent
  };

  return httpClient.get(url, fetchOptions);
}

function _assert(x, name, type, optional = false) {
  const article = type === 'object' ? 'an' : 'a';
  if(x !== undefined && typeof x !== type) {
    throw new TypeError(
      `${optional ? 'When present, ' : ''} ` +
      `"${name}" must be ${article} ${type}.`);
  }
}

function _assertOptional(x, name, type) {
  return _assert(x, name, type, true);
}
