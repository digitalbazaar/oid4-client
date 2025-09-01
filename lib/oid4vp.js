/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
export * as authzRequest from './authorizationRequest.js';
export * as authzResponse from './authorizationResponse.js';
export * as convert from './convert.js';
export * as verifier from './verifier.js';

// backwards compatibility APIs
export {
  get as getAuthorizationRequest
} from './authorizationRequest.js';
export {
  createPresentationSubmission,
  send as sendAuthorizationResponse
} from './authorizationResponse.js';
export {
  fromVpr, toVpr,
  // exported for testing purposes only
  _fromQueryByExampleQuery
} from './convert.js';

// Note: for examples of presentation request and responses, see:
// eslint-disable-next-line max-len
// https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#appendix-A.1.2.2
