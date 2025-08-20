/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {assert, assertOptional, fetchJSON} from './util.js';
import {JSONPath} from 'jsonpath-plus';
import jsonpointer from 'jsonpointer';

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
    let credentialQuery = [];
    if(queryByExample.length > 0) {
      if(queryByExample.length > 1 && strict) {
        const error = new Error(
          'Multiple "QueryByExample" VPR queries are not supported.');
        error.name = 'NotSupportedError';
        throw error;
      }
      ([{credentialQuery = []}] = queryByExample);
      if(!Array.isArray(credentialQuery)) {
        credentialQuery = [credentialQuery];
      }
    }
    const authorizationRequest = {
      response_type: 'vp_token',
      presentation_definition: {
        id: crypto.randomUUID(),
        input_descriptors: credentialQuery.map(q => _fromQueryByExampleQuery({
          credentialQuery: q,
          prefixJwtVcPath
        }))
      },
      // FIXME: this could be computed from a flag in the VPR that indicates
      // an encrypted response is required -- or, if an mDL is requested; a
      // flag `{responseMode}` could be explicitly given as well -- or it could
      // be left to be overwritten by the caller
      // response_mode: 'direct_post.jwt'
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

export function pathsToVerifiableCredentialPointers({paths} = {}) {
  // get only the paths inside a verifiable credential
  paths = Array.isArray(paths) ? paths : [paths];
  paths = _getVerifiableCredentialPaths(paths);
  // convert each JSON path to a JSON pointer
  return paths.map(_jsonPathToJsonPointer);
}

// converts an OID4VP authorization request (including its
// "presentation definition") to a VPR
export async function toVpr({
  authorizationRequest, strict = false, agent
} = {}) {
  try {
    const {
      client_id,
      client_metadata_uri,
      nonce,
      presentation_definition_uri,
    } = authorizationRequest;
    let {
      client_metadata,
      presentation_definition
    } = authorizationRequest;
    if(client_metadata && client_metadata_uri) {
      const error = new Error(
        'Only one of "client_metadata" and ' +
        '"client_metadata_uri" must be present.');
      error.name = 'DataError';
      throw error;
    }
    if(presentation_definition && presentation_definition_uri) {
      const error = new Error(
        'Only one of "presentation_definition" and ' +
        '"presentation_definition_uri" must be present.');
      error.name = 'DataError';
      throw error;
    }

    // FIXME: call `authorizationRequest.resolveParams()`

    // apply constraints for currently supported subset of AR data
    if(client_metadata_uri) {
      const response = await fetchJSON({url: client_metadata_uri, agent});
      if(!response.data) {
        const error = new Error('Client metadata format is not JSON.');
        error.name = 'DataError';
        throw error;
      }
      client_metadata = response.data;
    }
    assertOptional(client_metadata, 'client_metadata', 'object');
    if(presentation_definition_uri) {
      const response = await fetchJSON(
        {url: presentation_definition_uri, agent});
      if(!response.data) {
        const error = new Error('Presentation definition format is not JSON.');
        error.name = 'DataError';
        throw error;
      }
      presentation_definition = response.data;
    }
    assert(presentation_definition, 'presentation_definition', 'object');
    assert(presentation_definition?.id, 'presentation_definition.id', 'string');
    if(presentation_definition.submission_requirements && strict) {
      const error = new Error('"submission_requirements" is not supported.');
      error.name = 'NotSupportedError';
      throw error;
    }

    // generate base VPR from presentation definition
    const verifiablePresentationRequest = {
      // map each `input_descriptors` value to a `QueryByExample` query
      query: [{
        type: 'QueryByExample',
        credentialQuery: presentation_definition.input_descriptors.map(
          inputDescriptor => _toQueryByExampleQuery({inputDescriptor, strict}))
      }]
    };

    // add `DIDAuthentication` query based on client_metadata
    if(client_metadata) {
      const query = _toDIDAuthenticationQuery({client_metadata, strict});
      if(query !== undefined) {
        verifiablePresentationRequest.query.unshift(query);
      }
    }

    // map `client_id` to `domain`
    if(client_id !== undefined) {
      verifiablePresentationRequest.domain = client_id;
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

function _filterToValue({filter, strict = false}) {
  /* Each `filter` has a JSON Schema object. In recognition of the fact that
  a query must be usable by common database engines (including perhaps
  encrypted cloud databases) and of the fact that each JSON Schema object will
  come from an untrusted source (and could have malicious regexes, etc.), only
  simple JSON Schema types are supported:

  `string`: with `const` or `enum`, `format` is not supported and `pattern` has
    partial support as it will be treated as a simple string not a regex; regex
    is a DoS attack vector

  `array`: with `contains` where uses a `string` filter

  `allOf`: supported only with the above schemas present in it.

  */
  let value;

  const {type} = filter;
  if(type === 'array') {
    if(filter.contains) {
      if(Array.isArray(filter.contains)) {
        return filter.contains.map(filter => _filterToValue({filter, strict}));
      }
      return _filterToValue({filter: filter.contains, strict});
    }
    if(Array.isArray(filter.allOf) && filter.allOf.every(f => f.contains)) {
      return filter.allOf.map(
        f => _filterToValue({filter: f.contains, strict}));
    }
    if(strict) {
      throw new Error(
        'Unsupported filter; array filters must use "allOf" and/or ' +
        '"contains" with a string filter.');
    }
    return value;
  }
  if(type === 'string' || type === undefined) {
    if(filter.const !== undefined) {
      value = filter.const;
    } else if(filter.pattern) {
      value = filter.pattern;
    } else if(filter.enum) {
      value = filter.enum.slice();
    } else if(strict) {
      throw new Error(
        'Unsupported filter; string filters must use "const" or "pattern".');
    }
    return value;
  }
  if(strict) {
    throw new Error(`Unsupported filter type "${type}".`);
  }
}

// exported for testing purposes only
export function _fromQueryByExampleQuery({credentialQuery, prefixJwtVcPath}) {
  // determine `prefixJwtVcPath` default:
  // if `credentialQuery` specifies `acceptedEnvelopes: ['application/jwt']`,
  // then default `prefixJwtVcPath` to `true`
  if(prefixJwtVcPath === undefined &&
    (Array.isArray(credentialQuery.acceptedEnvelopes) &&
    credentialQuery.acceptedEnvelopes.includes?.('application/jwt'))) {
    prefixJwtVcPath = true;
  }

  const fields = [];
  const inputDescriptor = {
    id: crypto.randomUUID(),
    constraints: {fields}
  };
  if(credentialQuery?.reason) {
    inputDescriptor.purpose = credentialQuery?.reason;
  }
  // FIXME: current implementation only supports top-level string/array
  // properties and presumes strings
  const path = ['$'];
  const {example = {}} = credentialQuery || {};
  for(const key in example) {
    const value = example[key];
    path.push(key);

    const filter = {};
    if(Array.isArray(value)) {
      filter.type = 'array';
      filter.allOf = value.map(v => ({
        contains: {
          type: 'string',
          const: v
        }
      }));
    } else if(key === 'type') {
      // special provision for array/string for `type`
      filter.type = 'array',
      filter.contains = {
        type: 'string',
        const: value
      };
    } else {
      filter.type = 'string',
      filter.const = value;
    }
    const fieldsPath = [JSONPath.toPathString(path)];
    // include 'vc' path for queries against JWT payloads instead of VCs
    if(prefixJwtVcPath) {
      const vcPath = [...path];
      vcPath.splice(1, 0, 'vc');
      fieldsPath.push(JSONPath.toPathString(vcPath));
    }
    fields.push({
      path: fieldsPath,
      filter
    });

    path.pop();
  }

  return inputDescriptor;
}

function _getVerifiableCredentialPaths(paths) {
  // remove any paths that start with what would be present in a
  // presentation submission and adjust any paths that would be part of a
  // JWT-secured VC, such that only actual VC paths remain
  const removed = paths.filter(p => !_isPresentationSubmissionPath(p));
  return [...new Set(removed.map(p => {
    if(_isJWTPath(p)) {
      return '$' + p.slice('$.vc'.length);
    }
    if(_isSquareJWTPath(p)) {
      return '$' + p.slice('$[\'vc\']'.length);
    }
    return p;
  }))];
}

function _isPresentationSubmissionPath(path) {
  return path.startsWith('$.verifiableCredential[') ||
    path.startsWith('$.vp.') ||
    path.startsWith('$[\'verifiableCredential') || path.startsWith('$[\'vp');
}

function _isJWTPath(path) {
  return path.startsWith('$.vc.');
}

function _isSquareJWTPath(path) {
  return path.startsWith('$[\'vc\']');
}

function _jsonPathToJsonPointer(jsonPath) {
  return JSONPath.toPointer(JSONPath.toPathArray(jsonPath));
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

function _toQueryByExampleQuery({inputDescriptor, strict = false}) {
  // every input descriptor must have an `id`
  if(typeof inputDescriptor?.id !== 'string') {
    throw new TypeError('Input descriptor "id" must be a string.');
  }

  const example = {};
  const credentialQuery = {example};
  if(inputDescriptor.purpose) {
    credentialQuery.reason = inputDescriptor.purpose;
  }

  /* Note: Each input descriptor object is currently mapped to a single example
  query. If multiple possible path values appear for a single field, these will
  be mapped to multiple properties in the example which may or may not be what
  is intended. This behavior could be changed in a future revision if it
  becomes clear there is a better approach. */

  const fields = inputDescriptor.constraints?.fields || [];
  for(const field of fields) {
    const {path, filter, optional} = field;
    // skip optional fields
    if(optional === true) {
      continue;
    }

    try {
      // each field must have a `path` (which can be a string or an array)
      if(!(Array.isArray(path) || typeof path === 'string')) {
        throw new TypeError(
          'Input descriptor field "path" must be a string or array.');
      }

      // process any filter
      let value = '';
      if(filter !== undefined) {
        value = _filterToValue({filter, strict});
      }
      // no value understood, skip field
      if(value === undefined) {
        continue;
      }
      // normalize value to array
      if(!Array.isArray(value)) {
        value = [value];
      }

      // get JSON pointers for every path inside a verifiable credential
      const pointers = pathsToVerifiableCredentialPointers({paths: path});

      // add values at each path, converting to an array / appending as needed
      for(const pointer of pointers) {
        const existing = jsonpointer.get(example, pointer);
        if(existing === undefined) {
          jsonpointer.set(
            example, pointer, value.length > 1 ? value : value[0]);
        } else if(Array.isArray(existing)) {
          if(!existing.includes(value)) {
            existing.push(...value);
          }
        } else if(existing !== value) {
          jsonpointer.set(example, pointer, [existing, ...value]);
        }
      }
    } catch(cause) {
      const id = field.id || (JSON.stringify(field).slice(0, 50) + ' ...');
      const error = new Error(
        `Could not process input descriptor field: "${id}".`, {cause});
      error.field = field;
      throw error;
    }
  }

  return credentialQuery;
}
