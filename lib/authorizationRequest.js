/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  assert, assertOptional, base64Encode, createNamedError, fetchJSON, selectJwk
} from './util.js';
import {decodeJwt, importX509, jwtVerify} from 'jose';
import {
  hasDomainSubjectAltName, parseCertificateChain, verifyCertificateChain
} from './x509.js';

const SUPPORTED_CLIENT_ID_SCHEMES = new Set([
  'redirect_uri',
  'x509_san_dns', 'x509_hash', 'did', 'decentralized_identifier'
]);

// get an authorization request from a verifier
export async function get({url, getVerificationKey, agent} = {}) {
  try {
    assert(url, 'url', 'string');

    let authorizationRequest;
    let requestUrl;
    let expectedClientId;
    if(url.startsWith('https://')) {
      // the request must be retrieved via HTTP
      requestUrl = url;
    } else {
      // parse the request from the given URL
      ({authorizationRequest} = _parseOID4VPUrl({url}));
      expectedClientId = authorizationRequest.client_id;
      if(authorizationRequest.request_uri) {
        requestUrl = authorizationRequest.request_uri;
      }
      // if whole request is passed by reference, then it MUST be a signed JWT
      if(authorizationRequest.request) {
        authorizationRequest = await _parseJwt({
          jwt: authorizationRequest.request,
          getVerificationKey,
          signatureRequired: true
        });
      }
    }

    // fetch request if necessary...
    let fetched = false;
    let response;
    let jwt;
    if(requestUrl) {
      fetched = true;
      ({
        payload: authorizationRequest, response, jwt
      } = await _fetch({requestUrl, getVerificationKey, agent}));
    }

    // ensure authorization request is valid
    validate({authorizationRequest, expectedClientId});

    return {authorizationRequest, fetched, requestUrl, response, jwt};
  } catch(cause) {
    const message = cause.data?.error_description ?? cause.message;
    throw createNamedError({
      message: `Could not get authorization request: ${message}`,
      name: 'OperationError',
      cause
    });
  }
}

export function getClientIdScheme({authorizationRequest} = {}) {
  return authorizationRequest.client_id_scheme ??
    authorizationRequest.client_id?.split(':')[0];
}

export function requestsFormat({authorizationRequest, format} = {}) {
  /* e.g. presentation definition requesting an mdoc:
  {
    id: 'mdl-test-age-over-21',
    input_descriptors: [{
      id: 'org.iso.18013.5.1.mDL',
      format: {
        mso_mdoc: {
          alg: ['ES256']
        }
      }
    }]
  }
  */
  return authorizationRequest.presentation_definition?.input_descriptors?.some(
    e => e?.format?.[format]);
}

export function usesClientIdScheme({authorizationRequest, scheme} = {}) {
  if(Array.isArray(scheme)) {
    return scheme.some(
      scheme => usesClientIdScheme({authorizationRequest, scheme}));
  }
  return authorizationRequest?.client_id_scheme === scheme ||
    authorizationRequest?.client_id?.startsWith(`${scheme}:`);
}

export async function validate({authorizationRequest, expectedClientId}) {
  // validate payload (expected authorization request)
  const {
    client_id,
    client_id_scheme,
    client_metadata,
    nonce,
    presentation_definition,
    response_mode,
    scope
  } = authorizationRequest;
  assert(client_id, 'client_id', 'string');
  // ensure `client_id` matches expected client ID
  if(expectedClientId !== undefined && client_id !== expectedClientId) {
    throw createNamedError({
      message: '"client_id" in fetched request does not match authorization ' +
        'request URL parameter.',
      name: 'DataError'
    });
  }
  assert(nonce, 'nonce', 'string');
  assertOptional(client_id_scheme, 'client_id_scheme', 'string');
  assertOptional(client_metadata, 'client_metadata', 'object');
  assertOptional(
    presentation_definition, 'presentation_definition', 'object');
  assertOptional(response_mode, 'response_mode', 'string');
  assertOptional(scope, 'scope', 'string');
  // FIXME: further validate `presentation_definition`
  // FIXME: further validate `client_metadata`

  // Note: This implementation requires client ID scheme to be one of:
  // `redirect_uri`, `x509_san_dns`, `x509_hash`, `did`, or
  // `decentralized_identifier`
  const scheme = getClientIdScheme({authorizationRequest});
  if(!SUPPORTED_CLIENT_ID_SCHEMES.has(scheme)) {
    const schemes = [...SUPPORTED_CLIENT_ID_SCHEMES].join(', ');
    throw createNamedError({
      message: `Unsupported client ID scheme "${scheme}"; ` +
        `supported schemes are: ${schemes}.'`,
      name: 'NotSupportedError'
    });
  }

  // Note: This implementation requires `response_mode` to be `direct_post`
  // or `direct_post.jwt`; no other modes are supported.
  if(!(response_mode === 'direct_post' ||
    response_mode === 'direct_post.jwt')) {
    throw createNamedError({
      message: 'Only "direct_post" and "direct_post.jwt" ' +
        'response modes are supported.',
      name: 'NotSupportedError'
    });
  }

  // `direct_post.jwt` response mode requires encryption; ensure the client
  // meta data has the necessary parameters
  if(response_mode === 'direct_post.jwt') {
    const {
      authorization_encrypted_response_alg = 'ECDH-ES',
      authorization_encrypted_response_enc = 'A256GCM',
      jwks
    } = client_metadata;
    if(authorization_encrypted_response_alg !== 'ECDH-ES') {
      throw createNamedError({
        message: `"${authorization_encrypted_response_alg}" is not ` +
          'supported; only "ECDH-ES" is supported.',
        name: 'NotSupportedError'
      });
    }
    if(authorization_encrypted_response_enc !== 'A256GCM') {
      throw createNamedError({
        message: `"${authorization_encrypted_response_enc}" is not ` +
          'supported; only "A256GCM" is supported.',
        name: 'NotSupportedError'
      });
    }
    if(!selectJwk({
      keys: jwks?.keys, alg: 'ECDH-ES', kty: 'EC', crv: 'P-256', use: 'enc'
    })) {
      throw createNamedError({
        message: 'No matching key found for "ECDH-ES" in client meta data ' +
          'JWK key set.',
        name: 'NotFoundError'
      });
    }
  }
}

async function _checkClientIdSchemeRequirements({
  authorizationRequest, protectedHeader,
  certificatePublicKey, getTrustedCertificates
}) {
  // apply scheme-specific validation rules to signed request
  const scheme = getClientIdScheme({authorizationRequest});

  // if `x509_san_dns` or `x509_hash`...
  if(scheme.startsWith('x509_')) {
    // `x5c` MUST be present where the public key is in the leaf cert (which is
    // the first in the chain per RFC 7515:
    // https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6)
    if(!certificatePublicKey) {
      throw createNamedError({
        message:
          'Client ID schemes starting with "x509_" must use the "x5c" header ' +
          'to provide an X.509 certificate with the public key for verifying ' +
          'the request.',
        name: 'DataError'
      });
    }

    // get trusted certificates for `x5c` and verify chain
    const {x5c} = protectedHeader;
    const chain = parseCertificateChain({x5c});
    const trustedCertificates = await getTrustedCertificates({
      x5c, chain, authorizationRequest
    });
    const verifyResult = await verifyCertificateChain({
      chain, trustedCertificates
    });
    if(!verifyResult.result) {
      throw createNamedError({
        message:
          'Signed authorization request "x5c" certificate chain is invalid: ' +
          verifyResult.resultMessage,
        name: 'DataError'
      });
    }

    let {clientId} = authorizationRequest;
    clientId = clientId.startsWith(`${scheme}:`) ?
      clientId.slice(scheme.length + 2) : clientId;

    if(scheme === 'x509_san_dns') {
      // `x509_san_dns` requires leaf cert to have a dNSName ("domain" type) in
      // a subject alternative name field that matches the client_id
      if(!hasDomainSubjectAltName({certificate: chain[0], name: clientId})) {
        throw createNamedError({
          message:
            `Signed authorization request header "x5c" parameter's leaf ` +
            'certificate does not have a DNS subject alternative name that ' +
            'matches the client ID as required by the used "x509_san_dns" ' +
            'client ID scheme.',
          name: 'DataError'
        });
      }
      /* Note: The current implementation does not support `redirect_uri` as
      a `response_mode`. If a future revision adds support for this, then
      when `x509_san_dns` is used, the `redirect_uri` value must match the
      FQDN of the `client_id` unless an allow list for overrides is passed
      and it includes the client ID. */
    } else if(scheme === 'x509_hash') {
      // `x509_hash:<base64url sha256-hash of DER leaf cert>`
      const hash = base64Encode(await _sha256(chain[0].toBER()));
      if(clientId !== hash) {
        throw createNamedError({
          message:
            `The signed authorization request header "x5c" parameter's leaf ` +
            `certificate's SHA-256 hash digest not match the client ID as ` +
            'required by the used "x509_hash" client ID scheme.',
          name: 'DataError'
        });
      }
    }
  } else if(scheme === 'did' || scheme === 'decentralized_identifier') {
    // "kid" header must reference a verification method controlled by the
    // DID expressed in client ID; this is checked by default when a proper
    // DID resolver is used in `getVerificationKey` but this check provides
    // a partial additional sanity check
    let {clientId} = authorizationRequest;
    clientId = clientId.startsWith('decentralized_identifier:did:') ?
      clientId.slice('decentralized_identifier:'.length + 1) : clientId;
    if(!protectedHeader?.kid?.startsWith(clientId + '#')) {
      throw createNamedError({
        message:
          `The signed authorization request header "kid" parameter's value ` +
          'does not reference a verification method controlled by the DID ' +
          'identified in the client ID as required by the used ' +
          '"did"/"decentralized_identifier" client ID scheme.',
        name: 'DataError'
      });
    }
  }
}

async function _fetch({requestUrl, getVerificationKey, agent}) {
  // FIXME: every `fetchJSON` call needs to use a block list or other
  // protections to prevent a confused deputy attack where the `requestUrl`
  // accesses a location it should not, e.g., a URL `localhost` is used when
  // it shouldn't be
  const response = await fetchJSON({url: requestUrl, agent});

  // parse payload from response data...
  const contentType = response.headers.get('content-type');
  const jwt = await response.text();

  // verify response is a JWT-secured authorization request
  if(!(contentType.includes('application/oauth-authz-req+jwt') &&
    typeof jwt === 'string')) {
    throw createNamedError({
      message: 'Authorization request content-type must be ' +
        '"application/oauth-authz-req+jwt".',
      name: 'DataError'
    });
  }

  // return parsed payload and original response
  const payload = await _parseJwt({jwt, getVerificationKey});
  return {payload, response, jwt};
}

function _get(sp, name) {
  const value = sp.get(name);
  return value === null ? undefined : value;
}

async function _parseJwt({
  jwt, getTrustedCertificates, getVerificationKey, signatureRequired
}) {
  const payload = decodeJwt(jwt);

  // check if a signature on the JWT is required:
  // - `client_metadata.require_signed_request_object` is `true`, OR
  // - `client_id_scheme` requires the JWT to be signed
  signatureRequired = signatureRequired ||
    payload.client_metadata?.require_signed_request_object === true ||
    usesClientIdScheme({
      authorizationRequest: payload,
      // each of these schemes requires a signed request
      scheme: [
        'x509_san_dns', 'x509_hash', 'did', 'decentralized_identifier'
      ]
    });
  if(!signatureRequired) {
    // no signature required, just use the decoded payload
    return payload;
  }

  // create callback function to handle key lookup; `getVerificationKey` may
  // return a promise
  let certificatePublicKey;
  const getKey = async protectedHeader => {
    // parse any `x5c` to get certificate public key and include that in
    // `getVerificationKey` params
    const {x5c} = protectedHeader;
    certificatePublicKey = x5c ? await importX509(x5c, 'ES256') : undefined;
    if(getVerificationKey) {
      return getVerificationKey({protectedHeader, certificatePublicKey});
    }
    // FIXME: when `getVerificationKey` is not present:
    // FIXME: if `x5c` is present, use the public key in the `x5c`
    // FIXME: if `kid` starts with `did:` and has a supported method, resolve
    // the DID verification method
    _throwKeyNotFound(protectedHeader);
  };

  // verify the JWT
  const verifyResult = await jwtVerify(jwt, getKey, {alg: 'ES256'});
  const {payload: authorizationRequest, protectedHeader} = verifyResult;

  // ensure all client ID scheme requirements are met
  await _checkClientIdSchemeRequirements({
    authorizationRequest, protectedHeader,
    certificatePublicKey, getTrustedCertificates
  });

  return verifyResult.payload;
}

function _parseOID4VPUrl({url}) {
  const {searchParams} = new URL(url);
  const request = _get(searchParams, 'request');
  const request_uri = _get(searchParams, 'request_uri');
  const response_type = _get(searchParams, 'response_type');
  const response_mode = _get(searchParams, 'response_mode');
  const presentation_definition = _get(
    searchParams, 'presentation_definition');
  const client_id = _get(searchParams, 'client_id');
  const client_id_scheme = _get(searchParams, 'client_id_scheme');
  const client_metadata = _get(searchParams, 'client_metadata');
  const nonce = _get(searchParams, 'nonce');
  const response_uri = _get(searchParams, 'response_uri');
  const state = _get(searchParams, 'state');
  if(request && request_uri) {
    const error = createNamedError({
      message: 'Only one of "request" and "request_uri" may be present.',
      name: 'DataError'
    });
    error.url = url;
    throw error;
  }
  if(!(request || request_uri)) {
    if(response_type !== 'vp_token') {
      throw new Error(`Unsupported "response_type", "${response_type}".`);
    }
    if(!(response_mode === 'direct_post' ||
      response_mode === 'direct_post.jwt')) {
      throw new Error(`Unsupported "response_type", "${response_type}".`);
    }
  }
  const authorizationRequest = {
    request,
    request_uri,
    response_type,
    response_mode,
    presentation_definition: presentation_definition &&
      JSON.parse(presentation_definition),
    client_id,
    client_id_scheme,
    client_metadata: client_metadata && JSON.parse(client_metadata),
    response_uri,
    nonce,
    state
  };
  return {authorizationRequest};
}

async function _sha256(data) {
  if(typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  const algorithm = {name: 'SHA-256'};
  return new Uint8Array(await crypto.subtle.digest(algorithm, data));
}

function _throwKeyNotFound(protectedHeader) {
  const error = new Error(
    'Could not verify signed authorization request; ' +
    `public key "${protectedHeader.kid}" not found.`);
  error.name = 'NotFoundError';
  throw error;
}
