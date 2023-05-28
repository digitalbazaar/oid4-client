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
    if(!(issuerConfigUrl && typeof issuerConfigUrl === 'string')) {
      throw new TypeError('"issuerConfigUrl" must be a string.');
    }

    // allow these params to be passed / configured
    const fetchOptions = {
      // max size for issuer config related responses (in bytes, ~4 KiB)
      size: 4096,
      // timeout in ms for fetching an issuer config
      timeout: 5000,
      agent
    };

    const response = await httpClient.get(issuerConfigUrl, fetchOptions);
    if(!response.data) {
      const error = new Error('Issuer configuration format is not JSON.');
      error.name = 'DataError';
      throw error;
    }

    const {data: config} = response;
    const {issuer, token_endpoint} = config;

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

    // ensure `token_endpoint` is valid
    if(!(token_endpoint && typeof token_endpoint === 'string')) {
      const error = new TypeError('"token_endpoint" must be a string.');
      error.name = 'DataError';
      throw error;
    }

    return config;
  } catch(cause) {
    const error = new Error('Could not get OAuth2 issuer configuration.');
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

export function parseInitiateIssuanceUrl({url} = {}) {
  if(!(url && typeof url === 'string')) {
    throw new TypeError('"url" must be a string.');
  }

  /* Parse URL, e.g.:

  'openid-initiate-issuance://?' +
      'issuer=https%3A%2F%2Fserver%2Eexample%2Ecom' +
      '&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard' +
      '&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA' +
      '&user_pin_required=true';
  */
  const {protocol, searchParams} = new URL(url);
  if(protocol !== 'openid-initiate-issuance:') {
    throw new SyntaxError(
      '"url" must express a URL with the ' +
      '"openid-initiate-issuance" protocol.');
  }

  const issuer = searchParams.get('issuer');
  const credentialType = searchParams.get('credential_type');
  const preAuthorizedCode = searchParams.get('pre-authorized_code');
  const userPinRequired = searchParams.get('user_pin_required') === 'true';
  return {issuer, credentialType, preAuthorizedCode, userPinRequired};
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
  if(crv === 'Ed25519') {
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
