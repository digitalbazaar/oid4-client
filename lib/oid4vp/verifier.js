/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {createNamedError, parseJSON} from '../util.js';
import {calculateJwkThumbprint} from 'jose';
import {decryptAnnexCResponse} from './mdl.js';
import {decrypt as jwtDecrypt} from './jwt.js';

// start of JSON object, array, or string
const VP_TOKEN_JSON_PREFIXES = new Set(['{', '[', '"']);

// parses (and decrypts) an authz response from a response body object
export async function parseAuthorizationResponse({
  body = {},
  getDecryptParameters,
  authorizationRequest,
  // only used if `authorizationRequest.response_mode` is not set, otherwise
  // the response must match the authz request's response mode
  supportedResponseModes = [
    'direct_post.jwt', 'direct_post', 'dc_api.jwt', 'dc_api'
  ]
}) {
  let responseMode;
  const parsed = {};
  let vpTokenMediaType;
  let payload;
  let protectedHeader;
  let recipientPublicJwk;

  supportedResponseModes = new Set(authorizationRequest?.response_mode ?
    [authorizationRequest.response_mode] : supportedResponseModes);

  if(body.response) {
    // `body.response` is present which must contain an encrypted JWT;
    // response mode can also be `dc_api.jwt` here, but distinction can only
    // be made if `authorizationRequest` was passed
    responseMode = authorizationRequest?.response_mode === 'dc_api.jwt' ?
      'dc_api.jwt' : 'direct_post.jwt';
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
    const base64urlEncryptedResponse = body.Response;
    ({pt: payload, recipientPublicJwk} = await decryptAnnexCResponse({
      base64urlEncryptedResponse, getDecryptParameters
    }));
    // normalize payload to base64url-encoded mDL device response
    parsed.vpToken = base64url.encode(payload);
    vpTokenMediaType = 'application/mdl-vp-token';
  } else {
    responseMode = 'direct_post';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    payload = body;
    if(payload.presentation_submission) {
      parsed.presentationSubmission = parseJSON(
        payload.presentation_submission, 'presentation_submission');
    }
  }

  // if payload is set but not a Uint8Array (ISO 18013-7 Annex C case)...
  if(payload && !(payload instanceof Uint8Array)) {
    // `vp_token` is either:
    // 1. a JSON object (a VP)
    // 2. a JSON array (of something; unknown media type)
    // 3. a JSON string (a quoted JWT: "<JWT>")
    // 4. a JWT (starts with 'ey'...)
    // 5. a base64url-encoded mDL device response
    // 6. unknown
    const {vp_token} = payload;
    if(typeof vp_token === 'string') {
      if(VP_TOKEN_JSON_PREFIXES.has(vp_token[0])) {
        // cases: 1-3 - JSON
        parsed.vpToken = parseJSON(vp_token, 'vp_token');
        if(typeof parsed.vpToken === 'string') {
          vpTokenMediaType = 'application/jwt';
        } else if(!Array.isArray(parsed.vpToken)) {
          vpTokenMediaType = 'application/vp';
        }
      } else {
        // cases 4-5: JWT or mDL device response
        parsed.vpToken = vp_token;
        // if does not look like a JWT, assume mDL device response
        vpTokenMediaType = vp_token.startsWith('ey') ?
          'application/jwt' : 'application/mdl-vp-token';
      }
    } else {
      // unknown case
      parsed.vpToken = vp_token;
    }
  }

  // calculate JWK thumbprint for recipient public key, if any
  let recipientPublicJwkThumbprint;
  if(recipientPublicJwk) {
    recipientPublicJwkThumbprint = await calculateJwkThumbprint(
      recipientPublicJwk);
  }

  return {
    responseMode, parsed, payload, protectedHeader,
    recipientPublicJwk, recipientPublicJwkThumbprint,
    vpTokenMediaType
  };
}

function _assertSupportedResponseMode({
  responseMode, supportedResponseModes
}) {
  if(!supportedResponseModes.has(responseMode)) {
    throw createNamedError({
      message: `Unsupported response mode "${responseMode}".`,
      name: 'NotSupportedError',
      details: {httpStatusCode: 400, public: true}
    });
  }
}
