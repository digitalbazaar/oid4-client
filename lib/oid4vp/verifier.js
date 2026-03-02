/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {createNamedError, parseJSON} from '../util.js';
import {calculateJwkThumbprint} from 'jose';
import {decode as cborDecode} from 'cborg';
import {decrypt as hpkeDecrypt} from './hpke.js';
import {decrypt as jwtDecrypt} from './jwt.js';

// parses (and decrypts) an authz response from a response body object
export async function parseAuthorizationResponse({
  body = {},
  supportedResponseModes = [
    'direct_post.jwt', 'direct_post', 'dc_api.jwt', 'dc_api'
  ],
  getDecryptParameters
}) {
  let responseMode;
  const parsed = {};
  let payload;
  let protectedHeader;
  let recipientPublicJwk;

  supportedResponseModes = new Set(supportedResponseModes);

  if(body.response) {
    // FIXME: support `dc_api.jwt` here as well

    // `body.response` is present which must contain an encrypted JWT
    responseMode = 'direct_post.jwt';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    const jwt = body.response;
    ({
      payload,
      protectedHeader,
      recipientPublicJwk
    } = await jwtDecrypt({jwt, getDecryptParameters}));
    parsed.presentationSubmission = payload.presentation_submission;
  } else if(body.Response) {
    // ISO 18013-7 Annex C, with hpke-encrypted payload
    responseMode = 'dc_api';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    const EncryptedResponse = cborDecode(base64url.decode(body.Response));
    const [protocol] = EncryptedResponse;
    if(protocol !== 'dcapi') {
      throw createNamedError({
        message: `Unsupported encryption protocol "${protocol}".`,
        name: 'NotSupportedError'
      });
    }
    const [, {enc, cipherText: ct}] = EncryptedResponse;
    ({
      payload,
      // FIXME:
      //protectedHeader,
      recipientPublicJwk
    } = await hpkeDecrypt({enc, ct, getDecryptParameters}));
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
