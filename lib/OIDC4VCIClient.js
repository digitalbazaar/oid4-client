/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {discoverIssuer, generateDIDProofJWT} from './util.js';
import {httpClient} from '@digitalbazaar/http-client';

const GRANT_TYPES = new Map([
  ['preAuthorizedCode', 'urn:ietf:params:oauth:grant-type:pre-authorized_code']
]);
const HEADERS = {accept: 'application/json'};

export class OIDC4VCIClient {
  constructor({accessToken = null, agent, issuerConfig} = {}) {
    this.accessToken = accessToken;
    this.agent = agent;
    this.issuerConfig = issuerConfig;
  }

  async requestDelivery({did, didProofSigner, agent} = {}) {
    try {
      /* First send credential request to DS without DID proof JWT, e.g.:

      POST /credential HTTP/1.1
      Host: server.example.com
      Content-Type: application/json
      Authorization: BEARER czZCaGRSa3F0MzpnWDFmQmF0M2JW

      {
        "type": "https://did.example.org/healthCard"
        "format": "ldp_vc",
        // only present on retry after server requests it
        "proof": {
          "proof_type": "jwt",
          "jwt": "eyJraW..."
        }
      }
      */
      const {credential_endpoint: url} = this.issuerConfig;
      let result;
      // FIXME: pass as function params:
      const json = {
        type: 'https://did.example.org/healthCard',
        format: 'ldp_vc'
      };
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
            const error = new Error('DID authentication is required.');
            error.name = 'NotAllowedError';
            error.cause = cause;
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
            // audience MUST be the target issuer per the OIDC4VCI spec
            aud
          });

          // add proof to body to be posted and loop to retry
          json.proof = {proof_type: 'jwt', jwt};
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
      */
      return result;
    } catch(cause) {
      const error = new Error('Could not receive credentials.');
      error.name = 'OperationError';
      error.cause = cause;
      throw error;
    }
  }

  // create a client from a pre-authorized code
  // FIXME: consolidate implementation in another helper that can be
  // called in both `fromPreAuthorizedCode` and `fromAuthorizationCode`
  static async fromPreAuthorizedCode({
    issuer, preAuthorizedCode, userPin, agent
  } = {}) {
    try {
      // discover issuer info
      const parsedIssuer = new URL(issuer);
      const issuerConfigUrl =
        `${parsedIssuer.origin}/.well-known/oauth-authorization-server` +
        parsedIssuer.pathname;
      const issuerConfig = await discoverIssuer({issuerConfigUrl, agent});

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
      // `user_pin` is optional
      if(userPin !== undefined) {
        body.set('user_pin', userPin);
      }
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
      return new OIDC4VCIClient({accessToken, agent, issuerConfig});
    } catch(cause) {
      const error = new Error('Could not create OIDC4VCI client.');
      error.name = 'OperationError';
      error.cause = cause;
      throw error;
    }
  }

  static async fromAuthorizationCode({/*url, agent*/} = {}) {
    /* First get access token from AS:

    POST /token HTTP/1.1
      Host: server.example.com
      Content-Type: application/x-www-form-urlencoded
      grant_type=authorization_code
      &code=SplxlOBeZQQYbYS6WxSbIA
      &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
      &redirect_uri=https%3A%2F%2FWallet.example.org%2Fcb
    */

    // FIXME: token response (success); note `c_nonce*` probably doesn't make
    // sense to send here because it presumes authz server and issuance server
    // (delivery server) are the same; instead send those (if DID authn is
    // required) from the delivery server
    /*
    HTTP/1.1 200 OK
      Content-Type: application/json
      Cache-Control: no-store

      {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ",
        "token_type": "bearer",
        "expires_in": 86400,
        "c_nonce": "tZignsnFbp",
        "c_nonce_expires_in": 86400
      }
    */

    // FIXME: token response (failure)
    /*
    HTTP/1.1 400 Bad Request
    Content-Type: application/json
    Cache-Control: no-store
    {
      "error": "invalid_request"
    }
    */

    throw new Error('Not implemented');
  }
}

function _isMissingProofError(error) {
  /* If DID authn is required, delivery server sends, e.g.:

  HTTP/1.1 400 Bad Request
    Content-Type: application/json
    Cache-Control: no-store

  {
    "error": "invalid_or_missing_proof"
    "error_description":
        "Credential issuer requires proof element in Credential Request"
    "c_nonce": "8YE9hCnyV2",
    "c_nonce_expires_in": 86400
  }
  */
  return error.status === 400 &&
    error?.data?.error === 'invalid_or_missing_proof';
}
