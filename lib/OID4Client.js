/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc.
 */
import {
  createAuthorizationDetailsFromOffer, createCredentialRequestsFromOffer
} from './oid4vci/credentialOffer.js';
import {generateDIDProofDIVP, generateDIDProofJWT} from './oid4vci/proofs.js';
import {createNamedError} from './util.js';
import {httpClient} from '@digitalbazaar/http-client';
import {robustDiscoverIssuer} from './oid4vci/discovery.js';

const GRANT_TYPES = new Map([
  ['preAuthorizedCode', 'urn:ietf:params:oauth:grant-type:pre-authorized_code']
]);
const HEADERS = {accept: 'application/json'};

export class OID4Client {
  constructor({
    accessToken = null, agent, authorizationDetails,
    issuerConfig, metadata, offer,
    // default to "compatible" versions where the client will attempt to
    // detect and work with whatever version the server supports, for the
    // versions presently supported by this library
    oid4vciVersion = 'detect',
    oid4vpVersion = 'detect'
  } = {}) {
    this.accessToken = accessToken;
    this.agent = agent;
    this.authorizationDetails = authorizationDetails;
    this.metadata = metadata;
    this.issuerConfig = issuerConfig;
    this.offer = offer;
    this.oid4vciVersion = oid4vciVersion;
    this.oid4vpVersion = oid4vpVersion;
  }

  async getNonce({agent, headers = HEADERS} = {}) {
    let response;
    try {
      // get nonce endpoint
      const {nonce_endpoint: url} = this.issuerConfig;
      if(url === undefined) {
        throw createNamedError({
          message: 'Credential issuer has no "nonce_endpoint".',
          name: 'DataError'
        });
      }
      if(!url?.startsWith('https://')) {
        throw createNamedError({
          message: `Nonce endpoint "${url}" does not start with "https://".`,
          name: 'DataError'
        });
      }

      // get nonce
      response = await httpClient.post(url, {agent, headers});
      if(!response.data) {
        throw createNamedError({
          message: 'Nonce response format is not JSON.',
          name: 'DataError'
        });
      }
      if(response.data.c_nonce === undefined) {
        throw createNamedError({
          message: 'Nonce not provided in response.',
          name: 'DataError'
        });
      }
    } catch(cause) {
      throw createNamedError({
        message: 'Could not get nonce.',
        name: 'DataError',
        cause
      });
    }

    const {c_nonce: nonce} = response.data;
    return {nonce, response};
  }

  // deprecated; always call `requestCredentials()` instead
  async requestCredential({
    credentialDefinition, did, didProofSigner, nonce, agent, format = 'ldp_vc'
  } = {}) {
    const {authorizationDetails, issuerConfig, offer, oid4vciVersion} = this;
    let requests;
    if(credentialDefinition === undefined) {
      if(!offer) {
        throw new TypeError('"offer" must be an object.');
      }
      requests = createCredentialRequestsFromOffer({
        issuerConfig, offer, format, authorizationDetails, oid4vciVersion
      });
    } else {
      // OID4VCI Draft 13 only
      requests = [{
        format,
        credential_definition: credentialDefinition
      }];
    }
    return this.requestCredentials({
      requests, did, didProofSigner, nonce, agent
    });
  }

  async requestCredentials({
    requests, did, didProofSigner, agent, nonce, format = 'ldp_vc',
    alwaysUseBatchEndpoint = false
  } = {}) {
    // if `nonce` is given, then `did` and `didProofSigner` must also be
    if(nonce !== undefined && !(did && didProofSigner)) {
      throw createNamedError({
        message:
          'If "nonce" is given then "did" and "didProofSigner" are required.',
        name: 'DataError'
      });
    }

    const {authorizationDetails, issuerConfig, offer, oid4vciVersion} = this;
    if(requests === undefined && offer) {
      requests = createCredentialRequestsFromOffer({
        issuerConfig, offer, format, authorizationDetails, oid4vciVersion
      });
    } else if(!(Array.isArray(requests) && requests.length > 0)) {
      throw new TypeError('"requests" must be an array of length >= 1.');
    }
    requests.forEach(_assertRequest);

    // determine if OID4VCI 1.0+ is to be used
    const version1Plus = requests.some(r => r.credential_identifier);

    if(!version1Plus) {
      // set default `format` for requests with `credential_definition`
      // (OID4VCI Draft 13 only)
      requests = requests.map(
        r => r.credential_definition ? {format, ...r} : r);
    }

    try {
      let result;
      const {accessToken} = this;
      if(version1Plus) {
        // OID4VCI 1.0+ ... make N-many requests in parallel, with each one
        // adding a DID proof, if requested and N-many nonces might be required
        // FIXME: use p-queue to manage work
        const {credential_endpoint: url} = issuerConfig;
        const results = await Promise.all(requests.map(async request => {
          const json = {...request};
          return _requestCredential({
            accessToken, issuerConfig,
            url, json, nonce, did, didProofSigner, agent
          });
        }));
        // for backwards compatibility, return all results independently,
        // combined, and singular (if applicable)
        const credentials = results
          .map(r => r?.credentials?.map(e => e.credential))
          .flat();
        result = {credential_responses: results, credentials};
        // backwards compatibility with common draft 13 credential calls
        if(credentials.length === 1) {
          result.credential = credentials[0];
        }
        if(credentials.every(c => c?.['@context'])) {
          result.format = 'ldp_vc';
        }
      } else {
        // draft 13...
        let url;
        let json;
        if(requests.length > 1 || alwaysUseBatchEndpoint) {
          ({batch_credential_endpoint: url} = issuerConfig);
          json = {credential_requests: requests};
        } else {
          ({credential_endpoint: url} = issuerConfig);
          json = {...requests[0]};
        }
        result = await _requestCredential({
          accessToken, issuerConfig,
          url, json, nonce, did, didProofSigner, agent
        });
      }
      return result;
    } catch(cause) {
      throw createNamedError({
        message: 'Could not receive credentials.',
        name: 'OperationError',
        cause
      });
    }
  }

  // create a client from a credential offer
  static async fromCredentialOffer({
    offer, supportedFormats = ['ldp_vc'],
    oid4vciVersion = 'detect', oid4vpVersion = 'detect',
    agent
  } = {}) {
    // parse offer
    const {issuer, preAuthorizedCode} = _parseOffer({offer});

    try {
      // discover issuer info
      const {issuerConfig, metadata} = await robustDiscoverIssuer({
        issuer, agent
      });

      // get access token from AS (Authorization Server)
      const {accessToken, authorizationDetails} = await _getAccessToken({
        issuerConfig, preAuthorizedCode,
        // request authz details if the server supports it
        authorizationDetails: createAuthorizationDetailsFromOffer({
          issuerConfig, offer, supportedFormats, oid4vciVersion
        }),
        agent
      });

      // create client w/access token
      return new OID4Client({
        accessToken, agent, authorizationDetails,
        issuerConfig, metadata, offer,
        oid4vciVersion, oid4vpVersion
      });
    } catch(cause) {
      throw createNamedError({
        message: 'Could not create OID4 client.',
        name: 'OperationError',
        cause
      });
    }
  }
}

async function _addDIDProof({
  issuerConfig, json, nonce, did, didProofSigner
}) {
  // FIXME: allow these to combine; and choose just one based on
  // `proof_types_supported`, defaulting to `jwt` if nothing is specified
  await _addDIDProofDIVP({issuerConfig, json, nonce, did, didProofSigner});
  // add DID proof `jwt` to json
  await _addDIDProofJWT({issuerConfig, json, nonce, did, didProofSigner});
}

async function _addDIDProofDIVP({
  issuerConfig, json, nonce, did, didProofSigner
}) {
  // generate a DID proof DI VP
  const {issuer: domain} = issuerConfig;
  const di_vp = [await generateDIDProofDIVP({
    did,
    signer: didProofSigner,
    domain,
    challenge: nonce
  })];

  // add proof to body to be posted and loop to retry
  const proof = {proof_type: 'di_vp', di_vp};
  if(json.credential_requests) {
    // OID4VCI Draft 13 only
    json.credential_requests = json.credential_requests.map(
      cr => ({...cr, proof}));
  } else if(json.credential_definition) {
    // OID4VCI Draft 13 only
    json.proof = proof;
  } else {
    // OID4VCI 1.0+
    json.proofs = {
      ...proof,
      di_vp: [proof.di_vp]
    };
  }
}

async function _addDIDProofJWT({
  issuerConfig, json, nonce, did, didProofSigner
}) {
  // generate a DID proof JWT
  const {issuer: aud} = issuerConfig;
  const jwt = await generateDIDProofJWT({
    signer: didProofSigner,
    nonce,
    // the entity identified by the DID is issuing this JWT
    iss: did,
    // audience MUST be the target issuer per the OID4VCI spec
    aud
  });

  // add proof to body to be posted and loop to retry
  const proof = {proof_type: 'jwt', jwt};
  if(json.credential_requests) {
    // OID4VCI Draft 13 only
    json.credential_requests = json.credential_requests.map(
      cr => ({...cr, proof}));
  } else if(json.credential_definition) {
    // OID4VCI Draft 13 only
    json.proof = proof;
  } else {
    // OID4VCI 1.0+
    json.proofs = {
      ...proof,
      jwt: [proof.jwt]
    };
  }
}

async function _requestCredential({
  accessToken, issuerConfig, url, json, nonce, did, didProofSigner, agent
}) {
  /* First send credential request(s) to DS without DID proof JWT (unless
  `nonce` is given) e.g.:

  POST /credential HTTP/1.1
  Host: server.example.com
  Content-Type: application/json
  Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

  {
    "format": "ldp_vc",
    "credential_definition": {...},
    // only present on retry after server requests it or if nonce is given
    // v1.0 format:
    "proofs": {
      "di_vp": [VP1, VP2, ...],
      "jwt": [JWT1, JWT2, ...]
    }
    // draft 13 format:
    "proof": {
      "proof_type": "jwt",
      "jwt": "eyJraW..."
    }
  }
  OR
  {
    "credential_identifier": "foo",
    ...
  }
  OR
  {
    "credential_configuration_id": "bar",
    ...
  }

  OR (if multiple `requests` were given w/ Draft 13)

  POST /batch_credential HTTP/1.1
  Host: server.example.com
  Content-Type: application/json
  Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

  {
    "credential_requests": [{
      "format": "ldp_vc",
      "credential_definition": {...},
      // only present on retry after server requests it
      // v1.0 format:
      "proofs": {
        "di_vp": [VP1, VP2, ...],
        "jwt": [JWT1, JWT2, ...]
      }
      // draft 13 format:
      "proof": {
        "proof_type": "jwt",
        "jwt": "eyJraW..."
      }
    }, {
      ...
    }]
  }

  OR (if multiple `requests` were given w/1.0+), N-many requests will be
  repeated to `/credential`

  */
  if(nonce !== undefined) {
    // add DID proof to json
    await _addDIDProof({issuerConfig, json, nonce, did, didProofSigner});
  }

  let result;
  const headers = {
    ...HEADERS,
    authorization: `Bearer ${accessToken}`
  };
  for(let retries = 0; retries <= 1; ++retries) {
    try {
      const response = await httpClient.post(url, {agent, headers, json});
      result = response.data;
      if(!result) {
        throw createNamedError({
          message: 'Credential response format is not JSON.',
          name: 'DataError'
        });
      }
      break;
    } catch(cause) {
      // presentation is required to continue issuance
      if(_isPresentationRequired(cause)) {
        throw createNamedError({
          message: 'Presentation is required.',
          name: 'NotAllowedError',
          cause,
          details: cause.data
        });
      }

      if(!_isMissingProofError(cause)) {
        // other non-specific error case
        throw cause;
      }

      // if `didProofSigner` is not provided, throw error
      if(!(did && didProofSigner)) {
        throw createNamedError({
          message: 'DID authentication is required.',
          name: 'NotAllowedError',
          cause,
          details: cause.data
        });
      }

      // validate that `result` has a nonce
      let {data: {c_nonce: nonce}} = cause;
      if(!(nonce && typeof nonce === 'string')) {
        // try to get a nonce
        ({nonce} = await this.getNonce({agent}));
      }

      // add DID proof to json
      await _addDIDProof({issuerConfig, json, nonce, did, didProofSigner});
    }
  }

  // wallet / client receives credential(s):
  /* Note: The credential is not wrapped here in a VP in the current spec:

  HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

  {
    "format": "ldp_vc",
    "credential" : {...}
  }

  OR (if multiple VCs *of the same type* were issued)

  {
    "format": "ldp_vc",
    "credentials" : {...}
  }

  OR (if multiple `requests` were given)

  {
    "credential_responses": [{
      "format": "ldp_vc",
      "credential": {...}
    }]
  }
  */
  return result;
}

function _assertRequest(request) {
  // all current versions of OID4VCI require `request` to be an object
  if(!(request && typeof request === 'object')) {
    throw new TypeError('"request" must be an object.');
  }

  // OID4VCI 1.0+ request format
  if(request.credential_configuration_id) {
    if(typeof request.credential_configuration_id !== 'string') {
      throw new TypeError(
        'Credential request "credential_configuration_id" must be a string.');
    }
    return;
  }

  // OID4VCI 1.0+ request format
  if(request.credential_identifier) {
    if(typeof request.credential_identifier !== 'string') {
      throw new TypeError(
        'Credential request "credential_identifier" must be a string.');
    }
    return;
  }

  // OID4VCI Draft 13 format
  const {credential_definition} = request;
  if(!(credential_definition && typeof credential_definition === 'object')) {
    throw new TypeError(
      'Credential request "credential_definition" must be an object.');
  }
  const {type: type} = credential_definition;
  if(!(Array.isArray(type) && type.length > 0)) {
    throw new TypeError(
      'Credential definition "type" must be an array of length > 0.');
  }
}

async function _getAccessToken({
  issuerConfig, preAuthorizedCode, authorizationDetails, agent
}) {
  /* First get access token from AS (Authorization Server), e.g.:

  POST /token HTTP/1.1
    Host: server.example.com
    Content-Type: application/x-www-form-urlencoded
    grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
    &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
    &user_pin=493536
    &authorization_details=<URI-component-encoded JSON array>

  Note a bad response would look like:

  /*
  HTTP/1.1 400 Bad Request
  Content-Type: application/json
  Cache-Control: no-store
  {
    "error": "invalid_request"
  }
  */
  const body = new URLSearchParams();
  body.set('grant_type', GRANT_TYPES.get('preAuthorizedCode'));
  body.set('pre-authorized_code', preAuthorizedCode);
  if(authorizationDetails) {
    body.set('authorization_details', JSON.stringify(authorizationDetails));
  }
  const {token_endpoint} = issuerConfig;
  const response = await httpClient.post(token_endpoint, {
    agent, body, headers: HEADERS
  });
  const {data: result} = response;
  if(!result) {
    throw createNamedError({
      message: 'Could not get access token; response is not JSON.',
      name: 'DataError'
    });
  }

  /* Validate response body (Note: Do not check or use `c_nonce*` here
  because it conflates AS with DS (Delivery Server)), e.g.:

  HTTP/1.1 200 OK
    Content-Type: application/json
    Cache-Control: no-store

    {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
      "token_type": "bearer",
      "expires_in": 86400
    }
  */
  const {access_token: accessToken, token_type} = result;
  ({authorization_details: authorizationDetails} = result);
  if(!(accessToken && typeof accessToken === 'string')) {
    throw createNamedError({
      message:
        'Invalid access token response; "access_token" must be a string.',
      name: 'DataError'
    });
  }
  if(token_type !== 'bearer') {
    throw createNamedError({
      message:
        'Invalid access token response; "token_type" must be a "bearer".',
      name: 'DataError'
    });
  }
  if(authorizationDetails !== undefined &&
    !Array.isArray(authorizationDetails)) {
    throw createNamedError({
      message:
        'Invalid access token response; ' +
        '"authorization_details" must be an array.',
      name: 'DataError'
    });
  }

  return {accessToken, authorizationDetails};
}

function _isMissingProofError(error) {
  /* If DID authn is required, delivery server sends, e.g.:

  HTTP/1.1 400 Bad Request
    Content-Type: application/json
    Cache-Control: no-store

  {
    "error": "invalid_or_missing_proof", // or "invalid_proof"
    "error_description":
        "Credential issuer requires proof element in Credential Request"
    "c_nonce": "8YE9hCnyV2",
    "c_nonce_expires_in": 86400
  }
  */
  // `invalid_proof` OID4VCI draft 13+, `invalid_or_missing_proof` earlier
  const errorType = error.data?.error;
  return error.status === 400 &&
    (errorType === 'invalid_proof' ||
    errorType === 'invalid_or_missing_proof');
}

function _isPresentationRequired(error) {
  /* If OID4VP is required, delivery server sends, e.g.:

  HTTP/1.1 400 Bad Request
    Content-Type: application/json
    Cache-Control: no-store

  {
    "error": "presentation_required",
    "error_description":
        "Credential issuer requires presentation before Credential Request"
    "authorization_request": {...}
  }
  */
  const errorType = error.data?.error;
  return error.status === 400 && errorType === 'presentation_required';
}

function _parseOffer({offer}) {
  // relevant fields to validate
  const {
    credential_issuer,
    credentials,
    credential_configuration_ids,
    grants = {}
  } = offer;

  // ensure issuer is a valid URL
  let parsedIssuer;
  try {
    parsedIssuer = new URL(credential_issuer);
    if(parsedIssuer.protocol !== 'https:') {
      throw createNamedError({
        message: 'Only "https" credential issuer URLs are supported.',
        name: 'NotSupportedError'
      });
    }
  } catch(cause) {
    throw createNamedError({
      message: '"offer.credential_issuer" is not valid.',
      name: 'DataError',
      cause
    });
  }

  // OID4VCI Draft 13 used `credentials`
  // 1.0+ uses `credential_configuration_ids`
  if(credentials === undefined && credential_configuration_ids === undefined) {
    throw createNamedError({
      message:
        'Either "offer.credential_configuration_ids" or ' +
        '"offer.credentials" is required.',
      name: 'DataError'
    });
  }
  if(credential_configuration_ids !== undefined &&
    !Array.isArray(credential_configuration_ids)) {
    throw createNamedError({
      message: '"offer.credential_configuration_ids" is not valid.',
      name: 'DataError'
    });
  }
  if(credentials !== undefined &&
    !(Array.isArray(credentials) && credentials.length > 0 &&
    credentials.every(c => c && (
      typeof c === 'object' || typeof c === 'string')))) {
    throw createNamedError({
      message: '"offer.credentials" is not valid.',
      name: 'DataError'
    });
  }

  // validate grant
  const grant = grants?.[GRANT_TYPES.get('preAuthorizedCode')];
  if(!grant) {
    throw createNamedError({
      message: 'Only "pre-authorized_code" grant type is supported.',
      name: 'NotSupportedError'
    });
  }
  const {
    'pre-authorized_code': preAuthorizedCode
    // note: `tx_code` is presently ignored/not supported; if required an
    // error will be thrown by the appropriate software
  } = grant;
  if(!preAuthorizedCode) {
    throw createNamedError({
      message: '"offer.grant" is missing "pre-authorized_code".',
      name: 'DataError'
    });
  }

  return {issuer: credential_issuer, preAuthorizedCode};
}
