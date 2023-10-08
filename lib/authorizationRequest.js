/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */
import {JSONPath} from 'jsonpath-plus';
import jsonpointer from 'jsonpointer';

// supported path types in input descriptor objects
const PATH_TYPES = ['string', 'array'];

// converts an OID4VP authorization request (including its
// "presentation definition") to a VPR
export async function toVpr({authorizationRequest} = {}) {
  try {
    const {
      client_id,
      nonce,
      presentation_definition,
      presentation_definition_uri,
    } = authorizationRequest;

    // apply constraints for currently supported subset of PE
    if(presentation_definition_uri) {
      // FIXME: handle dereferencing `presentation_definition_uri`
      throw new Error('"presentation_definition_uri" not supported.');
    }
    if(!presentation_definition) {
      throw new Error('"presentation_definition" required.');
    }
    if(presentation_definition.submission_requirements) {
      throw new Error('"submission_requirements" not supported.');
    }

    // generate base VPR from presentation definition
    const verifiablePresentationRequest = {
      // map each `input_descriptors` value to a `QueryByExample`
      query: presentation_definition.input_descriptors
        .map(x => _toQueryByExample(x))
    };

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

// converts a VPR to an "authorization request"
export async function fromVpr({verifiablePresentationRequest} = {}) {
  try {
    // FIXME: implement
    throw new Error('Not implemented');
  } catch(cause) {
    const error = new Error(
      'Could not convert verifiable presentation request to ' +
      'an OID4VP authorization request.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}

// FIXME: consider accepting `authorizationRequest` instead
// creates a "presentation submission" from a presentation definition and VP
export async function createPresentationSubmission({
  presentationDefinition, verifiablePresentation
} = {}) {
  try {
    // FIXME: match VP VCs to presentation definition,
    // maybe do two passes: do possible matches first, then do selections
    // based on availability

    // FIXME: implement
    throw new Error('Not implemented');
  } catch(cause) {
    const error = new Error(
      'Could not create presentation submission.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}

function _toQueryByExample(inputDescriptor) {
  const example = {};
  const query = {
    type: 'QueryByExample',
    credentialQuery: [example]
  };

  if(inputDescriptor?.purpose) {
    query.reason = inputDescriptor?.purpose;
  }

  /* Note: Each input descriptor object is currently mapped to a single example
  query. If multiple possible path values appear for a single field, these will
  be mapped to multiple properties in the example which may or may not be what
  is intended. This behavior could be changed in a future revision if it
  becomes clear there is a better approach. */

  const fields = inputDescriptor?.constraints?.fields || [];
  for(const field of fields) {
    try {
      // each field must have a `path` (which can be a string or an array)
      const {path, filter} = field;
      if(PATH_TYPES.includes(typeof path)) {
        throw new Error(
          'Input descriptor field "path" must be a string or array.');
      }

      // process any filter
      let value;
      if(filter !== undefined) {
        value = _filterToValue(filter);
      }

      // convert each JSON path to a JSON pointer
      const paths = Array.isArray(path) ? path : [path];
      const pointers = paths.map(_jsonPathToJsonPointer);

      // set value at each path, converting to an array / appending as needed
      for(const pointer of pointers) {
        const existing = jsonpointer.get(example, pointer);
        if(Array.isArray(existing)) {
          existing.push(value);
        } else if(existing !== undefined) {
          jsonpointer.set(example, pointer, [existing, value]);
        } else {
          jsonpointer.set(example, pointer, value);
        }
      }
    } catch(cause) {
      const fieldString = JSON.stringify(field).slice(0, 50);
      const error = new Error(
        `Could not process input descriptor field: "${fieldString}...".`);
      error.field = field;
      error.cause = cause;
      throw error;
    }
  }

  return query;
}

function _filterToValue(filter) {
  /* Each `filter` has a JSON Schema object. In recognition of the fact that
  a query must be usable by common database engines (including perhaps
  encrypted cloud databases) and of the fact that each JSON Schema object will
  come from an untrusted source (and could have malicious regexes, etc.), only
  simple JSON Schema types are supported:

  `string`: with `const`, `format` is not supported and `pattern` has partial
    support as it will be treated as a simple string not a regex; regex is
    a DoS attack vector

  `array`: with `contains` where `contains` uses a `string` filter

  */
  let value;

  const {type} = filter;
  if(type === 'string') {
    if(filter.const !== undefined) {
      value = filter.const;
    } else if(filter.pattern) {
      value = filter.pattern;
    } else {
      throw new Error(
        'Unsupported filter; string filters must use "const" or "pattern".');
    }
    return value;
  }
  if(type === 'array') {
    if(filter.contains?.type === 'string') {
      value = _filterToValue(filter.contains);
    } else {
      throw new Error(
        'Unsupported filter; array filters must use "contains" with ' +
        'a string filter.');
    }
    return value;
  }

  throw new Error(`Unsupported filter type "${type}".`);
}

function _jsonPathToJsonPointer(jsonPath) {
  return JSONPath.toPointer(JSONPath.toPathArray(jsonPath));
}
