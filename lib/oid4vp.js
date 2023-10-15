/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {assert, assertOptional, fetchJSON} from './util.js';
import {JSONPath} from 'jsonpath-plus';
import jsonpointer from 'jsonpointer';
import {v4 as uuid} from 'uuid';

// For examples of presentation request and responses, see:
// eslint-disable-next-line max-len
// https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#appendix-A.1.2.2

// supported path types in input descriptor objects
const PATH_TYPES = ['string', 'array'];

// get an authorization request from a verifier
export async function getAuthorizationRequest({
  url, agent, documentLoader
} = {}) {
  try {
    assert(url, 'url', 'string');
    assertOptional(documentLoader, 'documentLoader', 'function');

    const response = await fetchJSON({url, agent});
    if(!response.data) {
      const error = new Error('Authorization request format is not JSON.');
      error.name = 'DataError';
      throw error;
    }

    // parse payload from response data...
    let payload;
    const contentType = response.headers.get('content-type');

    // verify authorization request to get payload if is JWT
    if(contentType.includes('application/oauth-authz-req+jwt')) {
      // FIXME: implement RFC 9101
      payload = {
        presentation_definition: {}
      };
      if(!documentLoader) {
        throw new TypeError(
          '"documentLoader" is required to process JWT-Secured Authorization ' +
          'Request (JAR).');
      }
      const error = new Error(
        'JWT-Secured Authorization Request (JAR) not implemented.');
      error.name = 'NotSupportedError';
      throw error;
    } else {
      payload = response.data;
    }

    // validate payload (expected authorization request)
    const {
      client_id,
      client_id_scheme,
      client_metadata,
      client_metadata_uri,
      nonce,
      presentation_definition,
      presentation_definition_uri,
      response_mode,
      scope
    } = payload;
    assert(client_id, 'client_id', 'string');
    assert(nonce, 'nonce', 'string');
    assertOptional(client_id_scheme, 'client_id_scheme', 'string');
    assertOptional(client_metadata, 'client_metadata', 'object');
    assertOptional(client_metadata_uri, 'client_metadata_uri', 'string');
    assertOptional(
      presentation_definition, 'presentation_definition', 'object');
    assertOptional(
      presentation_definition_uri, 'presentation_definition_uri', 'string');
    assertOptional(response_mode, 'response_mode', 'string');
    assertOptional(scope, 'scope', 'string');
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
    // Note: This implementation requires `response_mode` to be `direct_post`,
    // no other modes are supported.
    if(response_mode !== 'direct_post') {
      const error = new Error(
        'Only "direct_post" response mode is supported.');
      error.name = 'NotSupportedError';
      throw error;
    }

    // build merged authorization request
    const authorizationRequest = {...payload};

    // get client meta data from URL if specified
    if(client_metadata_uri) {
      const response = await fetchJSON({url: client_metadata_uri, agent});
      if(!response.data) {
        const error = new Error('Client meta data format is not JSON.');
        error.name = 'DataError';
        throw error;
      }
      // FIXME: can `data` be a JWT and require verification as well?
      delete authorizationRequest.client_metadata_uri;
      authorizationRequest.client_metadata = response.data;
    }

    // get presentation definition from URL if not embedded
    if(presentation_definition_uri) {
      const response = await fetchJSON(
        {url: presentation_definition_uri, agent});
      if(!response.data) {
        const error = new Error('Presentation definition format is not JSON.');
        error.name = 'DataError';
        throw error;
      }
      // FIXME: can `data` be a JWT and require verification as well?
      delete authorizationRequest.presentation_definition_uri;
      authorizationRequest.presentation_definition = response.data;
    }

    // FIXME: validate `authorizationRequest.presentation_definition`

    // return merged authorization request and original response
    return {authorizationRequest, response};
  } catch(cause) {
    const error = new Error('Could not get authorization request.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}

// converts an OID4VP authorization request (including its
// "presentation definition") to a VPR
export async function toVpr({authorizationRequest, strict = false} = {}) {
  try {
    const {
      client_id,
      client_metadata,
      client_metadata_uri,
      nonce,
      presentation_definition,
      presentation_definition_uri,
    } = authorizationRequest;

    // apply constraints for currently supported subset of AR data
    if(client_metadata_uri) {
      // FIXME: handle dereferencing `client_metadata_uri`
      const error = new Error('"client_metadata_uri" is not supported.');
      error.name = 'NotSupportedError';
      throw error;
    }
    assertOptional(client_metadata, 'client_metadata', 'object');
    if(presentation_definition_uri) {
      // FIXME: handle dereferencing `presentation_definition_uri`
      const error = new Error(
        '"presentation_definition_uri" is not supported.');
      error.name = 'NotSupportedError';
      throw error;
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
      // map each `input_descriptors` value to a `QueryByExample`
      query: presentation_definition.input_descriptors.map(
        inputDescriptor => _toQueryByExample({inputDescriptor, strict}))
    };

    // add `DIDAuthentication` query based on client_metadata
    if(client_metadata) {
      const query = _toDIDAuthenticationQuery({client_metadata, strict});
      if(query !== undefined) {
        verifiablePresentationRequest.query.push(query);
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
      'verifiable presentation request.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}

// converts a VPR to partial "authorization request"
export function fromVpr({verifiablePresentationRequest, strict = false} = {}) {
  try {
    let {query} = verifiablePresentationRequest;
    if(!Array.isArray(query)) {
      query = [query];
    }

    // convert any `QueryByExample` queries
    const queryByExample = query.filter(({type}) => type === 'QueryByExample');
    if(queryByExample.length === 0 && strict) {
      const error = new Error(
        'Only "QueryByExample" VPR queries are supported.');
      error.name = 'NotSupportedError';
      throw error;
    }
    const authorizationRequest = {
      presentation_definition: {
        id: uuid(),
        input_descriptors: queryByExample.map(_fromQueryByExample)
      },
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

    // include requested authn params
    if(verifiablePresentationRequest.domain) {
      // `authorizationRequest` uses `direct_post` so force client ID to
      // be the exchange response URL per "Note" here:
      // eslint-disable-next-line max-len
      // https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#section-6.2
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
      'an OID4VP authorization request.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}

// creates a "presentation submission" from a presentation definition and VP
export function createPresentationSubmission({
  presentationDefinition, verifiablePresentation
} = {}) {
  const descriptor_map = [];
  const presentationSubmission = {
    id: uuid(),
    definition_id: presentationDefinition.id,
    descriptor_map
  };

  try {
    // walk through each input descriptor object and match it to a VC
    let {verifiableCredential: vcs} = verifiablePresentation;
    const single = !Array.isArray(vcs);
    if(single) {
      vcs = [vcs];
    }
    /* Note: It is conceivable that the same VC could match multiple input
    descriptors. In this simplistic implementation, the first VC that matches
    is used. This may result in VCs in the VP not being mapped to an input
    descriptor, but every input descriptor having a VC that matches (i.e., at
    least one VC will be shared across multiple input descriptors). If
    some other behavior is more desirable, this can be changed in a future
    version. */
    for(const inputDescriptor of presentationDefinition.input_descriptors) {
      // walk through each VC and try to match it to the input descriptor
      for(let i = 0; i < vcs.length; ++i) {
        const verifiableCredential = vcs[i];
        if(_matchesInputDescriptor({inputDescriptor, verifiableCredential})) {
          descriptor_map.push({
            id: inputDescriptor.id,
            path: '$',
            format: 'ldp_vp',
            path_nested: {
              format: 'ldp_vc',
              path: single ?
                '$.verifiableCredential' :
                '$.verifiableCredential[' + i + ']'
            }
          });
          break;
        }
      }
    }
  } catch(cause) {
    const error = new Error(
      'Could not create presentation submission.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }

  return {presentationSubmission};
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

  `array`: with `items` or `contains` where uses a `string` filter

  */
  let value;

  const {type} = filter;
  if(type === 'string') {
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
  if(type === 'array') {
    if(filter.contains?.type === 'string') {
      value = _filterToValue({filter: filter.contains, strict});
    } else if(strict) {
      throw new Error(
        'Unsupported filter; array filters must use "enum" or "contains" ' +
        'with a string filter.');
    }
    return value;
  }
  if(strict) {
    throw new Error(`Unsupported filter type "${type}".`);
  }
}

function _jsonPathToJsonPointer(jsonPath) {
  return JSONPath.toPointer(JSONPath.toPathArray(jsonPath));
}

function _matchesInputDescriptor({
  inputDescriptor, verifiableCredential, strict = false
}) {
  // walk through each field ensuring there is a matching value
  const fields = inputDescriptor?.constraints?.fields || [];
  for(const field of fields) {
    const {path, filter, optional} = field;
    if(optional) {
      // skip field, it is optional
      continue;
    }

    try {
      // each field must have a `path` (which can be a string or an array)
      if(PATH_TYPES.includes(typeof path)) {
        throw new Error(
          'Input descriptor field "path" must be a string or array.');
      }

      // process any filter
      let value;
      if(filter !== undefined) {
        value = _filterToValue({filter, strict});
        // no value to match, presume no match
        if(value === undefined) {
          return false;
        }
      }
      // normalize value to array
      if(!Array.isArray(value)) {
        value = [value];
      }

      // convert each JSON path to a JSON pointer
      const paths = Array.isArray(path) ? path : [path];
      const pointers = paths.map(_jsonPathToJsonPointer);

      // check for a value at at least one path
      for(const pointer of pointers) {
        const existing = jsonpointer.get(verifiableCredential, pointer);
        if(existing === undefined) {
          // VC does not match
          return false;
        }
        // look for at least one matching value in `existing`
        let match = false;
        for(const v of value) {
          if(Array.isArray(existing)) {
            if(existing.includes(v)) {
              match = true;
              break;
            }
          } else if(existing === v) {
            match = true;
            break;
          }
        }
        if(!match) {
          return false;
        }
      }
    } catch(cause) {
      const id = field.id || (JSON.stringify(field).slice(0, 50) + ' ...');
      const error = new Error(
        `Could not process input descriptor field: "${id}".`);
      error.field = field;
      error.cause = cause;
      throw error;
    }
  }

  return true;
}

function _fromQueryByExample(queryByExample) {
  const fields = [];
  const inputDescriptor = {
    id: uuid(),
    constraints: {fields}
  };
  if(queryByExample.reason) {
    inputDescriptor.purpose = queryByExample.reason;
  }
  // FIXME: current implementation only supports top-level string/array
  // properties and presumes strings
  const path = ['$'];
  const {example = {}} = queryByExample;
  for(const key in example) {
    const value = example[key];
    path.push(key);

    const filter = {};
    if(Array.isArray(value)) {
      filter.type = 'array';
      filter.items = {
        type: 'string',
        enum: value.slice()
      };
    } else {
      filter.type = 'string',
      filter.const = value;
    }
    fields.push({
      path: JSONPath.toPathString(path),
      filter
    });

    path.pop();
  }

  return inputDescriptor;
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
    vp_formats: {
      ldp_vp: {
        proof_type: cryptosuites
      }
    }
  };
}

function _toQueryByExample({inputDescriptor, strict = false}) {
  // every input descriptor must have an `id`
  if(typeof inputDescriptor?.id !== 'string') {
    throw new TypeError('Input descriptor "id" must be a string.');
  }

  const example = {};
  const query = {
    type: 'QueryByExample',
    credentialQuery: [example]
  };

  if(inputDescriptor.purpose) {
    query.reason = inputDescriptor.purpose;
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
      if(PATH_TYPES.includes(typeof path)) {
        throw new TypeError(
          'Input descriptor field "path" must be a string or array.');
      }

      // process any filter
      let value;
      if(filter !== undefined) {
        value = _filterToValue({filter, strict});
        // no value understood, skip field
        if(value === undefined) {
          continue;
        }
      }
      // normalize value to array
      if(!Array.isArray(value)) {
        value = [value];
      }

      // convert each JSON path to a JSON pointer
      const paths = Array.isArray(path) ? path : [path];
      const pointers = paths.map(_jsonPathToJsonPointer);

      // add values at each path, converting to an array / appending as needed
      for(const pointer of pointers) {
        const existing = jsonpointer.get(example, pointer);
        if(existing === undefined) {
          jsonpointer.set(
            example, pointer, value.length > 1 ? value : value[0]);
        } else if(Array.isArray(existing)) {
          existing.push(...value);
        } else {
          jsonpointer.set(example, pointer, [existing, ...value]);
        }
      }
    } catch(cause) {
      const id = field.id || (JSON.stringify(field).slice(0, 50) + ' ...');
      const error = new Error(
        `Could not process input descriptor field: "${id}".`);
      error.field = field;
      error.cause = cause;
      throw error;
    }
  }

  return query;
}
