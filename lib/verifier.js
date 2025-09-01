/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {createNamedError, selectJwk} from './util.js';
import {importJWK, jwtDecrypt} from 'jose';

// parses (and decrypts) an authz response from a response body object
export async function parseAuthorizationResponse({
  body = {},
  supportedResponseModes = ['direct_post.jwt', 'direct_post'],
  getDecryptParameters
}) {
  let responseMode;
  const parsed = {};
  let payload;
  let protectedHeader;

  supportedResponseModes = new Set(supportedResponseModes);

  if(body.response) {
    // `body.response` is present which must contain an encrypted JWT
    responseMode = 'direct_post.jwt';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    const jwt = body.response;
    ({
      payload,
      protectedHeader
    } = await _decrypt({jwt, getDecryptParameters}));
    parsed.presentationSubmission = payload.presentation_submission;
  } else {
    responseMode = 'direct_post';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    payload = body;
    parsed.presentationSubmission = _jsonParse(
      payload.presentation_submission, 'presentation_submission');
  }

  // `vp_token` is either:
  // 1. a JSON object (a VP)
  // 2. a JSON array (of something)
  // 3. a JSON string (a quoted JWT: "<JWT>")
  // 4. a JWT
  // 5. a base64url-encoded mDL device response
  // 6. unknown
  const {vp_token} = payload;
  if(typeof vp_token === 'string' &&
    (vp_token.startsWith('{') || vp_token.startsWith('[') ||
    vp_token.startsWith('"'))) {
    parsed.vpToken = _jsonParse(vp_token, 'vp_token');
  } else {
    parsed.vpToken = vp_token;
  }

  return {responseMode, parsed, payload, protectedHeader};
}

function _assertSupportedResponseMode({
  responseMode, supportedResponseModes
}) {
  if(!supportedResponseModes.has(responseMode)) {
    throw createNamedError({
      message: `Unsupported response mode "${responseMode}".`,
      name: 'NotSupportedError'
    });
  }
}

async function _decrypt({jwt, getDecryptParameters}) {
  if(typeof getDecryptParameters !== 'function') {
    throw new TypeError(
      '"getDecryptParameters" is required for "direct_post.jwt" ' +
      'response mode.');
  }

  const params = await getDecryptParameters({jwt});
  const {keys} = params;
  let {getKey} = params;
  if(!getKey) {
    // note: `jose` lib's JWK key set feature cannot be used and passed to
    // `jwtDecrypt()` as the second parameter because the expected `alg`
    // "ECDH-ES" is not a unsupported algorithm for selecting a key from a set
    getKey = protectedHeader => {
      if(protectedHeader.alg !== 'ECDH-ES') {
        const error = createNamedError({
          message: `Unsupported algorithm "${protectedHeader.alg}"; ` +
            'algorithm must be "ECDH-ES".',
          name: 'NotSupportedError',
          details: {httpStatusCode: 400, public: true}
        });
        throw error;
      }
      const jwk = selectJwk({keys, kid: protectedHeader.kid});
      return importJWK(jwk, 'ECDH-ES');
    };
  }

  return jwtDecrypt(jwt, getKey, {
    // only supported algorithms at this time:
    contentEncryptionAlgorithms: ['A256GCM'],
    keyManagementAlgorithms: ['ECDH-ES']
  });
}

function _jsonParse(x, name) {
  try {
    return JSON.parse(x);
  } catch(cause) {
    throw createNamedError({
      message: `Could not parse "${name}".`,
      name: 'DataError',
      details: {httpStatusCode: 400, public: true},
      cause
    });
  }
}
