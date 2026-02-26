/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {calculateJwkThumbprint, importJWK, jwtDecrypt} from 'jose';
import {createNamedError, parseJSON, selectJwk} from '../util.js';

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
  let recipientPublicJwk;

  supportedResponseModes = new Set(supportedResponseModes);

  if(body.response) {
    // `body.response` is present which must contain an encrypted JWT
    responseMode = 'direct_post.jwt';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    const jwt = body.response;
    ({
      payload,
      protectedHeader,
      recipientPublicJwk
    } = await _decrypt({jwt, getDecryptParameters}));
    parsed.presentationSubmission = payload.presentation_submission;
  } else {
    responseMode = 'direct_post';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    payload = body;
    parsed.presentationSubmission = parseJSON(
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
    parsed.vpToken = parseJSON(vp_token, 'vp_token');
  } else {
    parsed.vpToken = vp_token;
  }

  // calculate JWK thumbprint for recipient public key, if any
  let recipientPublicJwkThumbprint;
  if(recipientPublicJwkThumbprint) {
    recipientPublicJwkThumbprint = await calculateJwkThumbprint(
      recipientPublicJwk);
  }

  return {
    responseMode, parsed, payload, protectedHeader,
    recipientPublicJwk, recipientPublicJwkThumbprint
  };
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
  let recipientPublicJwk;
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
      recipientPublicJwk = selectJwk({keys, kid: protectedHeader.kid});
      return importJWK(recipientPublicJwk, 'ECDH-ES');
    };
  }

  const {payload, protectedHeader} = await jwtDecrypt(jwt, getKey, {
    // only supported algorithms at this time:
    contentEncryptionAlgorithms: ['A256GCM', 'A128GCM'],
    keyManagementAlgorithms: ['ECDH-ES']
  });

  return {payload, protectedHeader, recipientPublicJwk};
}
