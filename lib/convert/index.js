/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {dcqlQueryToVprGroups, vprGroupsToDcqlQuery} from '../query/dcql.js';
import {
  presentationDefinitionToVprGroups,
  vprGroupsToPresentationDefinition
} from '../query/presentationExchange.js';
import {
  validate as validateAuthorizationRequest
} from '../oid4vp/authorizationRequest.js';

// backwards compatible exports
export {
  pathsToVerifiableCredentialPointers
} from '../query/presentationExchange.js';

// currently supported VPR query types for conversion
const DID_AUTHENTICATION = 'DIDAuthentication';
const QUERY_BY_EXAMPLE = 'QueryByExample';
const DCQL = 'DigitalCredentialQueryLanguage';
const CONVERTIBLE_QUERY_TYPES = new Set([
  QUERY_BY_EXAMPLE, DID_AUTHENTICATION, DCQL
]);

// converts a VPR to partial "authorization request"
export function fromVpr({
  verifiablePresentationRequest,
  strict = false,
  queryFormats = {
    // can replace `true` with options:
    // e.g., dcql options: {nullifyArrayIndices: true}
    dcql: true,
    presentationExchange: true
  },
  // presentation exchange (deprecated) options:
  prefixJwtVcPath,
  // authorization request options (`false` for backwards compatibility, use
  // `true` for OID4VP 1.0+)
  useClientIdPrefix = false
} = {}) {
  try {
    if(!(queryFormats?.dcql || queryFormats?.presentationExchange)) {
      throw new Error(
        'At least one of "queryFormats.dcql" or ' +
        '"queryFormats.presentationExchange" is required.');
    }

    // convert to query groups structure for processing
    const groupMap = _vprQueryToGroups({verifiablePresentationRequest});
    if(strict) {
      _strictCheckVprGroups({groupMap, queryFormats});
    }

    // core authz request
    const authorizationRequest = {
      response_type: 'vp_token',
      // default to `direct_post`; caller can override
      response_mode: 'direct_post'
    };
    // include requested authn params
    if(verifiablePresentationRequest.domain) {
      // since a `domain` was provided, set these defaults:
      authorizationRequest.client_id = verifiablePresentationRequest.domain;
      authorizationRequest.response_uri = authorizationRequest.client_id;
      if(useClientIdPrefix) {
        authorizationRequest.client_id =
          `redirect_uri:${authorizationRequest.client_id}`;
      } else {
        authorizationRequest.client_id_scheme = 'redirect_uri';
      }
    }
    if(verifiablePresentationRequest.challenge) {
      authorizationRequest.nonce = verifiablePresentationRequest.challenge;
    }
    // any DID authentication queries must be merged to a single set of
    // supported values for compatibility purposes
    const didAuthnQuery = [...groupMap.values()]
      .filter(g => g.has(DID_AUTHENTICATION))
      .map(g => g.get(DID_AUTHENTICATION))
      .flat();
    if(didAuthnQuery.length > 0) {
      // merge the accepted envelopes and cryptosuites across DID authn queries
      const cryptosuites = new Set();
      const envelopes = new Set();
      for(const query of didAuthnQuery) {
        query.acceptedCryptosuites?.forEach(
          ({cryptosuite}) => cryptosuites.add(cryptosuite));
        query.acceptedEnvelopes?.forEach(envelope => envelopes.add(envelope));
      }
      // convert last DID authn query w/merged cryptosuites and envelopes
      const query = structuredClone(didAuthnQuery.at(-1));
      query.acceptedCryptosuites = [...cryptosuites].map(
        cryptosuite => ({cryptosuite}));
      query.acceptedEnvelopes = [...envelopes];
      const client_metadata = _fromDIDAuthenticationQuery({query, strict});
      if(client_metadata) {
        authorizationRequest.client_metadata = client_metadata;
      }
    }

    // add credential queries
    if(queryFormats?.dcql) {
      const dcql_query = vprGroupsToDcqlQuery({
        groupMap, options: queryFormats.dcql === true ? {} : queryFormats.dcql
      });
      if(dcql_query?.credentials) {
        authorizationRequest.dcql_query = dcql_query;
      }
    }
    if(queryFormats?.presentationExchange) {
      const presentation_definition = vprGroupsToPresentationDefinition({
        groupMap, prefixJwtVcPath
      });
      if(presentation_definition) {
        authorizationRequest.presentation_definition = presentation_definition;
      }
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
export function toVpr({authorizationRequest, strict = false} = {}) {
  try {
    // ensure authorization request is valid
    validateAuthorizationRequest({authorizationRequest});

    const {
      client_id,
      client_metadata,
      dcql_query,
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
    const verifiablePresentationRequest = {};

    let didAuthnQuery;
    if(client_metadata) {
      didAuthnQuery = _toDIDAuthenticationQuery({client_metadata, strict});
    }

    // prefer conversion from DCQL query over presentation exchange
    let groupMap;
    if(dcql_query) {
      groupMap = dcqlQueryToVprGroups({dcql_query});
    } else if(presentation_definition) {
      groupMap = presentationDefinitionToVprGroups({
        presentation_definition, strict
      });
    }
    if(groupMap?.size > 0) {
      verifiablePresentationRequest.query = _vprGroupsToQuery({groupMap});

      // clone `DIDAuthentication` query for every query group
      if(didAuthnQuery) {
        for(const groupId of groupMap.keys()) {
          verifiablePresentationRequest.query.push(groupId === undefined ?
            didAuthnQuery : {
              ...structuredClone(didAuthnQuery),
              group: groupId
            });
        }
      }
    } else if(didAuthnQuery) {
      // add `DIDAuthentication` query once
      verifiablePresentationRequest.query = [didAuthnQuery];
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

function _strictCheckVprGroups({groupMap, queryFormats}) {
  const groups = [...groupMap.values()];
  let didAuthenticationCount = 0;
  let queryByExampleCount = 0;
  let dcqlCount = 0;
  for(const group of groups) {
    for(const type of group.keys()) {
      if(!CONVERTIBLE_QUERY_TYPES.has(type)) {
        const error = new Error(
          'Query type not convertible at this time; supported query types ' +
          `are: ${[...CONVERTIBLE_QUERY_TYPES].join(', ')}`);
        error.name = 'NotSupportedError';
        throw error;
      }
      if(type === DID_AUTHENTICATION) {
        didAuthenticationCount++;
      } else if(type === QUERY_BY_EXAMPLE) {
        queryByExampleCount++;
      } else if(type === DCQL) {
        dcqlCount++;
      }
    }
  }

  // multiple DCQL queries are not supported; there should be a single group ID
  // with a single DCQL query (or none at all)
  if(dcqlCount > 1) {
    const error = new Error(
      `Multiple VPR "${DCQL}" queries are not supported.`);
    error.name = 'NotSupportedError';
    throw error;
  }

  // if presentation exchange output is expected, then only one
  // `QueryByExample` is supported
  if(queryFormats?.presentationExchange && queryByExampleCount > 1) {
    const error = new Error(
      `Multiple VPR "${QUERY_BY_EXAMPLE}" queries are not supported when ` +
      'strictly converting to presentation exchange.');
    error.name = 'NotSupportedError';
    throw error;
  }

  // only one `DIDAuthentication` query is supported
  if(didAuthenticationCount > 1) {
    const error = new Error(
      `Multiple VPR "${DID_AUTHENTICATION}" queries are not supported when ` +
      'strictly converting to an OID4VP Authorization Request.');
    error.name = 'NotSupportedError';
    throw error;
  }

  // there must be at least one convertible type; DCQL is only acceptable
  const convertibleCount = queryByExampleCount + didAuthenticationCount +
    (queryFormats.dcql ? dcqlCount : 0);

  // there must be at least one convertible type
  if(convertibleCount === 0) {
    const error = new Error(`No convertible query types found.`);
    error.name = 'NotSupportedError';
    throw error;
  }
}

function _fromDIDAuthenticationQuery({query, strict = false}) {
  const vp_formats_supported = {};
  const client_metadata = {
    require_signed_request_object: false,
    vp_formats: {},
    vp_formats_supported
  };

  const cryptosuites = query.acceptedCryptosuites?.map(
    ({cryptosuite}) => cryptosuite);
  if(cryptosuites?.length > 0) {
    // legacy (before OID4VP 1.0)
    client_metadata.vp_formats.ldp_vp = {
      proof_type: cryptosuites
    };
    // OID4VP 1.0+
    vp_formats_supported.ldp_vc = {
      proof_type_values: ['DataIntegrityProof'],
      cryptosuite_values: cryptosuites
    };
    // compatibility with legacy cryptosuite
    if(cryptosuites.includes('Ed25519Signature2020')) {
      vp_formats_supported.ldp_vc
        .proof_type_values.push('Ed25519Signature2020');
    }
  }

  if(query.acceptedEnvelopes?.length > 0) {
    for(const envelope of query.acceptedEnvelopes) {
      if(envelope === 'application/jwt') {
        // legacy (before OID4VP 1.0)
        vp_formats_supported.jwt_vp_json = {};
        // OID4VP 1.0+
        vp_formats_supported.jwt_vc_json = {};
      } else if(envelope === 'application/mdl' ||
        envelope === 'application/mdoc') {
        vp_formats_supported.mso_mdoc = {};
      } else if(envelope === 'application/dc+sd-jwt') {
        vp_formats_supported['dc+sd-jwt'] = {};
      }
      // ignore unknown envelope format
    }
  }

  if(Object.keys(vp_formats_supported) === 0) {
    if(strict) {
      const error = new Error(
        '"query.acceptedCryptosuites" or "query.acceptedEnvelopes" must be a ' +
        'non-array with specified cryptosuites (or envelopes, respectively) ' +
        `to convert from a "${DID_AUTHENTICATION}" query.`);
      error.name = 'NotSupportedError';
      throw error;
    }
    return;
  }

  return client_metadata;
}

function _toDIDAuthenticationQuery({client_metadata, strict = false}) {
  const {vp_formats_supported, vp_formats} = client_metadata;
  const proofTypes = vp_formats_supported?.ldp_vc?.cryptosuite_values ??
    vp_formats?.ldp_vp?.proof_type;
  const envelopes = [];
  if(vp_formats_supported?.jwt_vc_json || vp_formats_supported?.jwt_vp_json) {
    envelopes.push('application/jwt');
  }
  if(vp_formats_supported?.mso_mdoc) {
    envelopes.push('application/mdoc');
  }
  if(vp_formats_supported?.['dc+sd-jwt']) {
    envelopes.push('application/dc+sd-jwt');
  }
  if(!(Array.isArray(proofTypes) || envelopes.length > 0)) {
    if(strict) {
      const error = new Error(
        '"client_metadata.vp_formats_supported.ldp_vc.cryptosuite_values" or ' +
        '"client_metadata.vp_formats.ldp_vp.proof_type" must be an array to ' +
        `convert to "${DID_AUTHENTICATION}" query.`);
      error.name = 'NotSupportedError';
      throw error;
    }
    return;
  }
  const query = {type: DID_AUTHENTICATION};
  if(proofTypes) {
    query.acceptedCryptosuites = proofTypes.map(cryptosuite => ({cryptosuite}));
  }
  if(envelopes.length > 0) {
    query.acceptedEnvelopes = envelopes;
  }
  return query;
}

function _vprGroupsToQuery({groupMap}) {
  const query = [];
  for(const group of groupMap.values()) {
    query.push(...[...group.values()].flat());
  }
  return query;
}

function _vprQueryToGroups({verifiablePresentationRequest}) {
  // normalize queries into groups, each group ID defines a different "OR"
  // condition, the same group ID defines an "AND" group; the group ID
  // `undefined` is used when no group is present (every `undefined` group is
  // the same "AND" group)
  const groups = new Map();
  let {query} = verifiablePresentationRequest;
  if(!Array.isArray(query)) {
    query = [query];
  }
  for(const q of query) {
    // each group is a map of query type => queries
    let group = groups.get(q?.group);
    if(!group) {
      group = new Map();
      groups.set(q?.group, group);
    }
    const queries = group.get(q?.type);
    if(queries) {
      queries.push(q);
    } else {
      group.set(q?.type, [q]);
    }
  }
  return groups;
}
