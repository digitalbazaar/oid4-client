/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  assert, assertOptional, createNamedError, fetchJSON, selectJwk
} from './util.js';
import {decodeJwt} from 'jose';

// get an authorization request from a verifier
export async function get({url, agent} = {}) {
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
          jwt: authorizationRequest.request, signatureRequired: true
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
      } = await _fetch({requestUrl, agent}));
    }

    // ensure authorization request is valid
    validate({authorizationRequest, expectedClientId});

    // resolve and validate any additional parameters in the request
    authorizationRequest = await resolveParams({authorizationRequest, agent});

    return {authorizationRequest, fetched, requestUrl, response, jwt};
  } catch(cause) {
    throw createNamedError({
      message: `Could not get authorization request: ${cause.message}`,
      name: 'OperationError',
      cause
    });
  }
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

// FIXME: in a major release, remove support for params requiring resolution
export async function resolveParams({authorizationRequest, agent}) {
  const {
    client_metadata_uri,
    presentation_definition_uri,
    ...resolved
  } = {...authorizationRequest};

  // get client meta data from URL if specified
  if(client_metadata_uri) {
    const response = await fetchJSON({url: client_metadata_uri, agent});
    if(!response.data) {
      throw createNamedError({
        message: 'Client meta data format is not JSON.',
        name: 'DataError'
      });
    }
    resolved.client_metadata = response.data;
  }

  // get presentation definition from URL if not embedded
  if(presentation_definition_uri) {
    const response = await fetchJSON(
      {url: presentation_definition_uri, agent});
    if(!response.data) {
      throw createNamedError({
        message: 'Presentation definition format is not JSON.',
        name: 'DataError'
      });
    }
    resolved.presentation_definition = response.data;
  }

  assert(resolved.presentation_definition, 'presentation_definition', 'object');
  assert(
    resolved.presentation_definition?.id,
    'presentation_definition.id', 'string');

  // FIXME: further validate `authorizationRequest.presentation_definition`
  // FIXME: further validate `authorizationRequest.client_metadata`

  // `direct_post.jwt` response mode requires encryption; ensure the client
  // meta data has the necessary parameters
  if(resolved.response_mode === 'direct_post.jwt') {
    const {
      authorization_encrypted_response_alg = 'ECDH-ES',
      authorization_encrypted_response_enc = 'A256GCM',
      jwks
    } = resolved.client_metadata;
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

  return resolved;
}

export function usesClientIdScheme({authorizationRequest, scheme} = {}) {
  return authorizationRequest?.client_id_scheme === scheme ||
    authorizationRequest?.client_id?.startsWith(`${scheme}:`);
}

export async function validate({authorizationRequest, expectedClientId}) {
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
  // FIXME: remove `client_metadata_uri` in a future revision, it is not
  // supported in the latest OID4VP, bad practice, and rarely used
  assertOptional(client_metadata_uri, 'client_metadata_uri', 'string');
  assertOptional(
    presentation_definition, 'presentation_definition', 'object');
  // FIXME: remove `presentation_definition_uri` in a future revision, it is
  // not supported in the latest OID4VP, bad practice, and rarely used
  assertOptional(
    presentation_definition_uri, 'presentation_definition_uri', 'string');
  assertOptional(response_mode, 'response_mode', 'string');
  assertOptional(scope, 'scope', 'string');
  if(client_metadata && client_metadata_uri) {
    throw createNamedError({
      message: 'Only one of "client_metadata" and ' +
        '"client_metadata_uri" must be present.',
      name: 'DataError'
    });
  }
  if(presentation_definition && presentation_definition_uri) {
    throw createNamedError({
      message: 'Only one of "presentation_definition" and ' +
        '"presentation_definition_uri" must be present.',
      name: 'DataError'
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
}

async function _fetch({requestUrl, agent}) {
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
  const payload = await _parseJwt({jwt});
  return {payload, response, jwt};
}

function _get(sp, name) {
  const value = sp.get(name);
  return value === null ? undefined : value;
}

async function _parseJwt({jwt, signatureRequired}) {
  const payload = decodeJwt(jwt);

  // check if a signature on the JWT is required:
  // - `client_metadata.require_signed_request_object` is `true`, OR
  // - `client_id_scheme` requires the JWT to be signed
  signatureRequired = signatureRequired ||
    payload.client_metadata?.require_signed_request_object === true ||
    usesClientIdScheme({authorizationRequest: payload, scheme: 'x509_san_dns'});
  if(!signatureRequired) {
    // no signature required, just use the decoded payload
    return payload;
  }

  // verify the JWT (`jwtVerify()`); ensure an async callback function can be
  // used to provide the trust / key lookup mechanism
  // FIXME: jwtVerify()

  return payload;
}

function _parseOID4VPUrl({url}) {
  const {searchParams} = new URL(url);
  const request = _get(searchParams, 'request');
  const request_uri = _get(searchParams, 'request_uri');
  const response_type = _get(searchParams, 'response_type');
  const response_mode = _get(searchParams, 'response_mode');
  const presentation_definition = _get(
    searchParams, 'presentation_definition');
  const presentation_definition_uri = _get(
    searchParams, 'presentation_definition_uri');
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
    presentation_definition_uri,
    client_id,
    client_id_scheme,
    client_metadata: client_metadata && JSON.parse(client_metadata),
    response_uri,
    nonce,
    state
  };
  return {authorizationRequest};
}
