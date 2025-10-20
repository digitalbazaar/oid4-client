/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  presentationDefinitionToQueryByExample,
  queryByExampleToPresentationDefinition
} from '../query/presentationExchange.js';
import {
  validate as validateAuthorizationRequest
} from '../oid4vp/authorizationRequest.js';

// backwards compatible exports
export {
  pathsToVerifiableCredentialPointers
} from '../query/presentationExchange.js';

// FIXME: update `fromVpr()` to support both PE and DCQL

// converts a VPR to partial "authorization request"
export function fromVpr({
  verifiablePresentationRequest, strict = false, prefixJwtVcPath
} = {}) {
  try {
    let {query} = verifiablePresentationRequest;
    if(!Array.isArray(query)) {
      query = [query];
    }

    // convert any `QueryByExample` queries
    const queryByExample = query.filter(({type}) => type === 'QueryByExample');
    if(queryByExample.length > 0) {
      if(queryByExample.length > 1 && strict) {
        const error = new Error(
          'Multiple "QueryByExample" VPR queries are not supported.');
        error.name = 'NotSupportedError';
        throw error;
      }
    }
    const authorizationRequest = {
      response_type: 'vp_token',
      presentation_definition: queryByExampleToPresentationDefinition({
        queryByExample, strict, prefixJwtVcPath
      }),
      // default to `direct_post`; caller can override
      response_mode: 'direct_post'
    };

    // convert any `DIDAuthentication` queries
    const didAuthnQuery = query.filter(
      ({type}) => type === 'DIDAuthentication');
    if(didAuthnQuery.length > 0) {
      if(didAuthnQuery.length > 1 && strict) {
        const error = new Error(
          'Multiple "DIDAuthentication" VPR queries are not supported.');
        error.name = 'NotSupportedError';
        throw error;
      }
      const [query] = didAuthnQuery;
      const client_metadata = _fromDIDAuthenticationQuery({query, strict});
      authorizationRequest.client_metadata = client_metadata;
    }

    if(queryByExample.length === 0 && didAuthnQuery.length === 0 && strict) {
      const error = new Error(
        'Only "DIDAuthentication" and "QueryByExample" VPR queries are ' +
        'supported.');
      error.name = 'NotSupportedError';
      throw error;
    }

    // include requested authn params
    if(verifiablePresentationRequest.domain) {
      // since a `domain` was provided, set these defaults:
      authorizationRequest.client_id = verifiablePresentationRequest.domain;
      authorizationRequest.client_id_scheme = 'redirect_uri';
      authorizationRequest.response_uri = authorizationRequest.client_id;
    }
    if(verifiablePresentationRequest.challenge) {
      authorizationRequest.nonce = verifiablePresentationRequest.challenge;
    }

    return authorizationRequest;
  } catch(cause) {
    const error = new Error(
      'Could not convert verifiable presentation request to ' +
      'an OID4VP authorization request.', {cause});
    error.name = 'OperationError';
    throw error;
  }
}

// converts an OID4VP authorization request (including its
// "presentation definition") to a VPR
export async function toVpr({authorizationRequest, strict = false} = {}) {
  try {
    // ensure authorization request is valid
    validateAuthorizationRequest({authorizationRequest});

    const {
      client_id,
      client_metadata,
      nonce,
      presentation_definition,
      response_uri
    } = authorizationRequest;

    // disallow unsupported `submission_requirements` in strict mode
    if(strict && presentation_definition.submission_requirements) {
      const error = new Error('"submission_requirements" is not supported.');
      error.name = 'NotSupportedError';
      throw error;
    }

    // generate base VPR from presentation definition
    const verifiablePresentationRequest = {
      // map `presentation_definition` value to a `QueryByExample` query
      query: [presentationDefinitionToQueryByExample({
        presentation_definition, strict
      })]
    };

    // add `DIDAuthentication` query based on client_metadata
    if(client_metadata) {
      const query = _toDIDAuthenticationQuery({client_metadata, strict});
      if(query !== undefined) {
        verifiablePresentationRequest.query.unshift(query);
      }
    }

    // map `response_uri` or `client_id` to `domain`
    if(response_uri !== undefined || client_id !== undefined) {
      verifiablePresentationRequest.domain = response_uri ?? client_id;
    }

    // map `nonce` to `challenge`
    if(nonce !== undefined) {
      verifiablePresentationRequest.challenge = nonce;
    }

    return {verifiablePresentationRequest};
  } catch(cause) {
    const error = new Error(
      'Could not convert OID4VP authorization request to ' +
      'verifiable presentation request.', {cause});
    error.name = 'OperationError';
    throw error;
  }
}

function _fromDIDAuthenticationQuery({query, strict = false}) {
  const cryptosuites = query.acceptedCryptosuites?.map(
    ({cryptosuite}) => cryptosuite);
  if(!(cryptosuites && cryptosuites.length > 0)) {
    if(strict) {
      const error = new Error(
        '"query.acceptedCryptosuites" must be a non-array with specified ' +
        'cryptosuites to convert from a DIDAuthentication query.');
      error.name = 'NotSupportedError';
      throw error;
    }
    return;
  }
  return {
    require_signed_request_object: false,
    vp_formats: {
      ldp_vp: {
        proof_type: cryptosuites
      }
    }
  };
}

function _toDIDAuthenticationQuery({client_metadata, strict = false}) {
  const {vp_formats} = client_metadata;
  const proofTypes = vp_formats?.ldp_vp?.proof_type;
  if(!Array.isArray(proofTypes)) {
    if(strict) {
      const error = new Error(
        '"client_metadata.vp_formats.ldp_vp.proof_type" must be an array to ' +
        'convert to DIDAuthentication query.');
      error.name = 'NotSupportedError';
      throw error;
    }
    return;
  }
  return {
    type: 'DIDAuthentication',
    acceptedCryptosuites: proofTypes.map(cryptosuite => ({cryptosuite}))
  };
}
