/*!
 * Copyright (c) 2023-2026 Digital Bazaar, Inc.
 */
import * as base64url from 'base64url-universal';
import {createNamedError, parseJSON} from '../util.js';
import {decryptAnnexCResponse, encodeSessionTranscript} from './mdl.js';
import {calculateJwkThumbprint} from 'jose';
import {isObject} from '../query/util.js';
import {decrypt as jwtDecrypt} from './jwt.js';

const VC_CONTEXT_2 = 'https://www.w3.org/ns/credentials/v2';

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
  supportedResponseModes = new Set(authorizationRequest?.response_mode ?
    [authorizationRequest.response_mode] : supportedResponseModes);

  // compute `mdocOptions` if given `authorizationRequest`
  let mdocOptions;
  if(authorizationRequest) {
    // generate expected mdoc `handover`
    let handover;

    // common `handover` parameters:
    const origin = authorizationRequest.expected_origins?.[0] ??
      URL.parse(authorizationRequest.response_uri)?.origin;
    const nonce = authorizationRequest.nonce;

    // `direct_post.jwt` => ISO18013-7 Annex B
    // FIXME: same response mode is also used for OID4VP 1.0 with
    // `OpenID4VPHandover` for non-Annex-B; this is not yet supported
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-invocation-via-redirects
    if(authorizationRequest.response_mode === 'direct_post.jwt') {
      handover = {
        type: 'AnnexBHandover',
        // must be populated during/after decryption
        mdocGeneratedNonce: undefined,
        clientId: authorizationRequest.client_id,
        responseUri: authorizationRequest.response_uri,
        verifierGeneratedNonce: nonce
      };
    } else if(authorizationRequest.response_mode === 'dc_api') {
      // `dc_api` => ISO18013-7 Annex C
      handover = {
        type: 'dcapi',
        origin,
        nonce,
        // must be populated during/after decryption
        recipientPublicJwk: undefined
      };
    } else if(authorizationRequest.response_mode === 'dc_api.jwt') {
      // `dc_api.jwt` => ISO18013-7 Annex D
      handover = {
        type: 'OpenID4VPDCAPIHandover',
        origin,
        nonce,
        // must be populated during/after decryption
        jwkThumbprint: undefined
      };
    }

    mdocOptions = {expectedHandover: handover};
  }

  const parsed = {};
  let vpTokenMediaType = 'application/octet-stream';
  let payload;
  let protectedHeader;
  let recipientPublicJwk;
  let responseMode;
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
    } = await jwtDecrypt({jwt, mdocOptions, getDecryptParameters}));
    parsed.presentationSubmission = payload.presentation_submission;
  } else if(body.Response) {
    // ISO 18013-7 Annex C, with hpke-encrypted payload
    responseMode = 'dc_api';
    _assertSupportedResponseMode({responseMode, supportedResponseModes});
    const base64urlEncryptedResponse = body.Response;
    ({pt: payload, recipientPublicJwk} = await decryptAnnexCResponse({
      base64urlEncryptedResponse, mdocOptions, getDecryptParameters
    }));
    // normalize payload to base64url-encoded mDL device response
    parsed.vpToken = base64url.encode(payload);
    // FIXME: future breaking change might be to rename this to
    // `application/mdoc-vp-token` since it isn't mDL specific
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

  // calculate JWK thumbprint for recipient public key, if any
  let recipientPublicJwkThumbprint;
  if(recipientPublicJwk) {
    recipientPublicJwkThumbprint = await calculateJwkThumbprint(
      recipientPublicJwk);
  }

  // if payload is set but not a Uint8Array (ISO 18013-7 Annex C case)...
  if(payload && !(payload instanceof Uint8Array)) {
    // `vp_token` may be an already parsed object with keys that identify
    // credential response query IDs and values that are arrays with one
    // or more corresponding presentations; in this case we remove this wrapper
    // and we presently assume a single query was responded to with a single
    // presentation
    const {vp_token} = payload;
    let vpToken;
    if(isObject(vp_token)) {
      const keys = Object.keys(vp_token);
      if(keys.length > 0) {
        vpToken = vp_token[keys[0]]?.[0];
      }
    } else {
      vpToken = vp_token;
    }

    // `vpToken` is either:
    // 1. a JSON object (a VP)
    // 2. a JSON array (of something; unknown media type)
    // 3. a JSON string (a quoted JWT: "<JWT>")
    // 4. a JWT (starts with 'ey'...)
    // 5. a base64url-encoded mDL device response
    // 6. unknown
    if(typeof vpToken === 'string') {
      if(VP_TOKEN_JSON_PREFIXES.has(vpToken[0])) {
        // cases: 1-3 - JSON
        parsed.vpToken = parseJSON(vpToken, 'vp_token');
        if(typeof parsed.vpToken === 'string') {
          vpTokenMediaType = 'application/jwt';
        } else if(!Array.isArray(parsed.vpToken)) {
          vpTokenMediaType = 'application/vp';
        }
      } else {
        // cases 4-5: JWT or mdoc device response
        parsed.vpToken = vpToken;
        // if does not look like a JWT, assume mdoc mDL device response
        // FIXME: future breaking change might be to rename this to
        // `application/mdoc-vp-token` since it isn't mDL specific
        vpTokenMediaType = vpToken.startsWith('ey') ?
          'application/jwt' : 'application/mdl-vp-token';
      }
    } else {
      // unknown case
      parsed.vpToken = vpToken;
    }
  }

  // obtain `presentation` and optional `envelope` from parsed `vpToken`
  const {vpToken} = parsed;
  let presentation;
  let envelope;
  if(vpTokenMediaType !== 'application/vp') {
    // `vp_token` contains some enveloped format
    presentation = {
      '@context': VC_CONTEXT_2,
      id: `data:${vpTokenMediaType},${vpToken}`,
      type: 'EnvelopedVerifiablePresentation'
    };
    envelope = {mediaType: vpTokenMediaType};
  } else {
    // simplest case: `vpToken` is a VP
    presentation = vpToken;
  }

  // post-process `mdocOptions` based on now available information
  if(mdocOptions) {
    // clear `mdocOptions` unless an mdoc response was given
    if(!(envelope?.mediaType === 'application/mdoc-vp-token' ||
      // deprecated
      envelope?.mediaType === 'application/mdl-vp-token')) {
      mdocOptions = undefined;
    } else {
      const {expectedHandover} = mdocOptions;
      if(expectedHandover.type === 'AnnexBHandover') {
        if(!expectedHandover.mdocGeneratedNonce) {
          // now that `protectedHeader` is available, update Annex B handover
          // per ISO 18013-7 B the `mdocGeneratedNonce` is base64url-encoded
          // and put into the `apu` protected header parameter, so parse that
          // here and convert it to a UTF-8 string instead
          expectedHandover.mdocGeneratedNonce = Buffer
            .from(protectedHeader?.apu ?? '', 'base64url')
            .toString('utf8');
        }
      } else if(expectedHandover.type === 'dcapi') {
        if(!expectedHandover.recipientPublicJwk) {
          expectedHandover.recipientPublicJwk = recipientPublicJwk;
        }
      } else if(expectedHandover.type === 'OpenID4VPDCAPIHandover') {
        if(!expectedHandover.jwkThumbprint) {
          expectedHandover.jwkThumbprint = recipientPublicJwkThumbprint;
        }
      }

      // create encoded expected mdoc session transcript
      mdocOptions.expectedSessionTranscript = Buffer
        .from(await encodeSessionTranscript({handover: expectedHandover}))
        .toString('base64url');
    }
  }

  return {
    responseMode, parsed, payload, protectedHeader,
    recipientPublicJwk, recipientPublicJwkThumbprint,
    vpTokenMediaType,
    envelope, presentation, mdocOptions
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
