/*!
 * Copyright (c) 2022-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {discoverIssuer, generateDIDProofJWT} from './util.js';
import {httpClient} from '@digitalbazaar/http-client';

const GRANT_TYPES = new Map([
  ['preAuthorizedCode', 'urn:ietf:params:oauth:grant-type:pre-authorized_code']
]);
const HEADERS = {accept: 'application/json'};

export class OID4Client {
  constructor({accessToken = null, agent, issuerConfig, metadata, offer} = {}) {
    this.accessToken = accessToken;
    this.agent = agent;
    this.metadata = metadata;
    this.issuerConfig = issuerConfig;
    this.offer = offer;
  }

  async requestCredential({
    credentialDefinition, did, didProofSigner, agent, format = 'ldp_vc'
  } = {}) {
    const {issuerConfig, offer} = this;
    let requests;
    if(credentialDefinition === undefined) {
      if(!offer) {
        throw new TypeError('"credentialDefinition" must be an object.');
      }
      requests = _createCredentialRequestsFromOffer({issuerConfig, offer});
      if(requests.length > 1) {
        throw new Error(
          'More than one credential is offered; ' +
          'use "requestCredentials()" instead.');
      }
    } else {
      requests = [{
        format,
        credential_definition: credentialDefinition
      }];
    }
    return this.requestCredentials({requests, did, didProofSigner, agent});
  }

  async requestCredentials({
    requests, did, didProofSigner, agent, format = 'ldp_vc',
    alwaysUseBatchEndpoint = false
  } = {}) {
    const {issuerConfig, offer} = this;
    if(requests === undefined && offer) {
      requests = _createCredentialRequestsFromOffer({issuerConfig, offer});
    } else if(!(Array.isArray(requests) && requests.length > 0)) {
      throw new TypeError('"requests" must be an array of length >= 1.');
    }
    requests.forEach(_assertRequest);
    // set default `format`
    requests = requests.map(r => ({format, ...r}));

    try {
      /* First send credential request(s) to DS without DID proof JWT, e.g.:

      POST /credential HTTP/1.1
      Host: server.example.com
      Content-Type: application/json
      Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

      {
        "format": "ldp_vc",
        "credential_definition": {...},
        // only present on retry after server requests it
        "proof": {
          "proof_type": "jwt",
          "jwt": "eyJraW..."
        }
      }

      OR (if multiple `requests` were given)

      POST /batch_credential HTTP/1.1
      Host: server.example.com
      Content-Type: application/json
      Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

      {
        "credential_requests": [{
          "format": "ldp_vc",
          "credential_definition": {...},
          // only present on retry after server requests it
          "proof": {
            "proof_type": "jwt",
            "jwt": "eyJraW..."
          }
        }, {
          ...
        }]
      }
      */
      let url;
      let json;
      if(requests.length > 1 || alwaysUseBatchEndpoint) {
        ({batch_credential_endpoint: url} = this.issuerConfig);
        json = {credential_requests: requests};
      } else {
        ({credential_endpoint: url} = this.issuerConfig);
        json = {...requests[0]};
      }

      let result;
      const headers = {
        ...HEADERS,
        authorization: `Bearer ${this.accessToken}`
      };
      for(let retries = 0; retries <= 1; ++retries) {
        try {
          const response = await httpClient.post(url, {agent, headers, json});
          result = response.data;
          if(!result) {
            const error = new Error('Credential response format is not JSON.');
            error.name = 'DataError';
            throw error;
          }
          break;
        } catch(cause) {
          if(!_isMissingProofError(cause)) {
            // non-specific error case
            throw cause;
          }

          // if `didProofSigner` is not provided, throw error
          if(!(did && didProofSigner)) {
            const {data: details} = cause;
            const error = new Error('DID authentication is required.', {cause});
            error.name = 'NotAllowedError';
            error.details = details;
            throw error;
          }

          // validate that `result` has
          const {data: {c_nonce: nonce}} = cause;
          if(!(nonce && typeof nonce === 'string')) {
            const error = new Error('No DID proof challenge specified.');
            error.name = 'DataError';
            throw error;
          }

          // generate a DID proof JWT
          const {issuer: aud} = this.issuerConfig;
          const jwt = await generateDIDProofJWT({
            signer: didProofSigner,
            nonce,
            // the entity identified by the DID is issuing this JWT
            iss: did,
            // audience MUST be the target issuer per the OID4VC spec
            aud
          });

          // add proof to body to be posted and loop to retry
          const proof = {proof_type: 'jwt', jwt};
          if(json.credential_requests) {
            json.credential_requests = json.credential_requests.map(
              cr => ({...cr, proof}));
          } else {
            json.proof = proof;
          }
        }
      }

      // wallet / client receives credential:
      /* Note: The credential is not wrapped here in a VP in the current spec:

      HTTP/1.1 200 OK
        Content-Type: application/json
        Cache-Control: no-store

      {
        "format": "ldp_vc"
        "credential" : {...}
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
    } catch(cause) {
      const error = new Error('Could not receive credentials.', {cause});
      error.name = 'OperationError';
      throw error;
    }
  }

  // create a client from a credential offer
  static async fromCredentialOffer({offer, agent} = {}) {
    // validate offer
    const {credential_issuer, credentials, grants = {}} = offer;
    let parsedIssuer;
    try {
      parsedIssuer = new URL(credential_issuer);
      if(parsedIssuer.protocol !== 'https:') {
        throw new Error('Only "https" credential issuer URLs are supported.');
      }
    } catch(cause) {
      throw new Error('"offer.credential_issuer" is not valid.', {cause});
    }
    if(!(Array.isArray(credentials) && credentials.length > 0 &&
      credentials.every(c => c && typeof c === 'object'))) {
      throw new Error('"offer.credentials" is not valid.');
    }
    const grant = grants[GRANT_TYPES.get('preAuthorizedCode')];
    if(!grant) {
      // FIXME: implement `authorization_code` grant type as well
      throw new Error('Only "pre-authorized_code" grant type is implemented.');
    }
    const {
      'pre-authorized_code': preAuthorizedCode,
      user_pin_required: userPinRequired
    } = grant;
    if(!preAuthorizedCode) {
      throw new Error('"offer.grant" is missing "pre-authorized_code".');
    }
    if(userPinRequired) {
      throw new Error('User pin is not implemented.');
    }

    try {
      // discover issuer info
      const issuerConfigUrl =
        `${parsedIssuer.origin}/.well-known/openid-credential-issuer` +
        parsedIssuer.pathname;
      const {issuerConfig, metadata} = await discoverIssuer(
        {issuerConfigUrl, agent});

      /* First get access token from AS (Authorization Server), e.g.:

      POST /token HTTP/1.1
        Host: server.example.com
        Content-Type: application/x-www-form-urlencoded
        grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
        &pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA
        &user_pin=493536

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
      const {token_endpoint} = issuerConfig;
      const response = await httpClient.post(token_endpoint, {
        agent, body, headers: HEADERS
      });
      const {data: result} = response;
      if(!result) {
        const error = new Error(
          'Could not get access token; response is not JSON.');
        error.name = 'DataError';
        throw error;
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
      if(!(accessToken && typeof accessToken === 'string')) {
        const error = new Error(
          'Invalid access token response; "access_token" must be a string.');
        error.name = 'DataError';
        throw error;
      }
      if(token_type !== 'bearer') {
        const error = new Error(
          'Invalid access token response; "token_type" must be a "bearer".');
        error.name = 'DataError';
        throw error;
      }

      // create client w/access token
      return new OID4Client(
        {accessToken, agent, issuerConfig, metadata, offer});
    } catch(cause) {
      const error = new Error('Could not create OID4 client.', {cause});
      error.name = 'OperationError';
      throw error;
    }
  }
}

function _assertRequest(request) {
  if(!(request && typeof request === 'object')) {
    throw new TypeError('"request" must be an object.');
  }
  const {credential_definition} = request;
  if(!(credential_definition && typeof credential_definition === 'object')) {
    throw new TypeError(
      'Credential request "credential_definition" must be an object.');
  }
  const {'@context': context, type: type} = credential_definition;
  if(!(Array.isArray(context) && context.length > 0)) {
    throw new TypeError(
      'Credential definition "@context" must be an array of length >= 1.');
  }
  if(!(Array.isArray(type) && type.length > 0)) {
    throw new TypeError(
      'Credential definition "type" must be an array of length >= 2.');
  }
}

function _isMissingProofError(error) {
  /* If DID authn is required, delivery server sends, e.g.:

  HTTP/1.1 400 Bad Request
    Content-Type: application/json
    Cache-Control: no-store

  {
    "error": "invalid_or_missing_proof" // or "invalid_proof"
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

function _createCredentialRequestFromId({id, issuerConfig}) {
  const {credentials_supported: supported = []} = issuerConfig;
  const meta = supported.find(d => d.id === id);
  if(!meta) {
    throw new Error(`No supported credential "${id}" found.`);
  }
  const {format, credential_definition} = meta;
  if(typeof format !== 'string') {
    throw new Error(
      `Invalid supported credential "${id}"; "format" not specified.`);
  }
  if(!(Array.isArray(credential_definition?.['@context']) &&
    Array.isArray(credential_definition?.types))) {
    throw new Error(
      `Invalid supported credential "${id}"; "credential_definition" not ` +
      'fully specified.');
  }
  return {format, credential_definition};
}

function _createCredentialRequestsFromOffer({issuerConfig, offer}) {
  // build requests from `offer`
  return offer.credentials.map(c => {
    if(typeof c === 'string') {
      // use issuer config metadata to dereference string
      return _createCredentialRequestFromId({id: c, issuerConfig});
    }
    return c;
  });
}
