/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {resolvePointer, toJsonPointerMap} from './util.js';
import {exampleToJsonPointerMap} from './queryByExample.js';
import {JSONPath} from 'jsonpath-plus';
import jsonpointer from 'json-pointer';

const VALUE_TYPES = new Set(['string', 'number', 'boolean']);
const SUPPORTED_JWT_VC_ALGS = ['EdDSA', 'Ed25519', 'ES256', 'ES384'];

export function presentationDefinitionToVprGroups({
  presentation_definition, strict = false
} = {}) {
  const {input_descriptors: inputDescriptors} = presentation_definition;

  // only one group (no "OR" with presentation exchange), every input
  // input descriptor converts to a `QueryByExample` query in the same group
  const queries = inputDescriptors.map(inputDescriptor => {
    return {
      type: 'QueryByExample',
      credentialQuery: _toQueryByExampleQuery({inputDescriptor, strict})
    };
  });

  // output group map with a single group with all `QueryByExample` queries
  const group = new Map([['QueryByExample', queries]]);
  const groupMap = new Map([[undefined, group]]);
  return groupMap;
}

export function inputDescriptorToJsonPointerMap({inputDescriptor} = {}) {
  const queryByExample = _toQueryByExampleQuery({inputDescriptor});
  return exampleToJsonPointerMap(queryByExample);
}

export function vprGroupsToPresentationDefinition({
  groupMap, prefixJwtVcPath
} = {}) {
  const input_descriptors = [];
  const presentationDefinition = {
    id: crypto.randomUUID(),
    input_descriptors
  };

  const jwtVcJsonAlgs = [];
  const ldpVcProofTypes = new Set();
  // note: same group ID is logical "AND" and different group ID is "OR"
  const groups = [...groupMap.values()];
  for(const queries of groups) {
    // only `QueryByExample` is convertible
    const queryByExamples = queries.get('QueryByExample');
    if(!queryByExamples) {
      continue;
    }

    // for each `QueryByExample`, add another input descriptor (for every
    // "credentialQuery" within it
    for(const queryByExample of queryByExamples) {
      // should only be one `credentialQuery` but handle each one as a new
      // set of input descriptors
      const all = Array.isArray(queryByExample.credentialQuery) ?
        queryByExample.credentialQuery : [queryByExample.credentialQuery];
      for(const credentialQuery of all) {
        const inputDescriptor = _fromQueryByExampleQuery({
          credentialQuery, prefixJwtVcPath
        });
        input_descriptors.push(inputDescriptor);
        const {acceptedEnvelopes, acceptedCryptosuites} = credentialQuery;
        const shouldAddFormat = acceptedEnvelopes || acceptedCryptosuites;
        if(shouldAddFormat && !inputDescriptor.format) {
          inputDescriptor.format = {};
        }
        if(acceptedEnvelopes?.includes('application/jwt')) {
          inputDescriptor.format.jwt_vc_json = {
            alg: SUPPORTED_JWT_VC_ALGS
          };
          if(jwtVcJsonAlgs.length === 0) {
            jwtVcJsonAlgs.push(...SUPPORTED_JWT_VC_ALGS);
          }
        }
        if(acceptedCryptosuites) {
          const cryptosuites = acceptedCryptosuites
            .map(({cryptosuite}) => cryptosuite);
          inputDescriptor.format.ldp_vc = {
            proof_type: cryptosuites
          };
          for(const cryptosuite of cryptosuites) {
            ldpVcProofTypes.add(cryptosuite);
          }
        }
      }
    }
  }

  const shouldAddFormat = jwtVcJsonAlgs.length > 0 || ldpVcProofTypes.size > 0;
  if(shouldAddFormat && !presentationDefinition.format) {
    presentationDefinition.format = {};
  }
  if(jwtVcJsonAlgs.length > 0) {
    presentationDefinition.format.jwt_vp = {alg: jwtVcJsonAlgs};
    presentationDefinition.format.jwt_vp_json = {alg: jwtVcJsonAlgs};
    presentationDefinition.format.jwt_vc_json = {alg: jwtVcJsonAlgs};
  }
  if(ldpVcProofTypes.size > 0) {
    const proof_type = [...ldpVcProofTypes];
    presentationDefinition.format.ldp_vp = {proof_type};
    presentationDefinition.format.ldp_vc = {proof_type};
  }

  return presentationDefinition;
}

// exported for backwards compatibility only
export function pathsToVerifiableCredentialPointers({paths} = {}) {
  // get only the paths inside a verifiable credential
  paths = Array.isArray(paths) ? paths : [paths];
  paths = _getVerifiableCredentialPaths(paths);
  // convert each JSON path to a JSON pointer
  return paths.map(_jsonPathToJsonPointer);
}

function _filterToValue({filter, strict = false}) {
  /* Each `filter` has a JSON Schema object. In recognition of the fact that
  a query must be usable by common database engines (including perhaps
  encrypted cloud databases) and of the fact that each JSON Schema object will
  come from an untrusted source (and could have malicious regexes, etc.), only
  simple JSON Schema types are supported:

  simple type filters (`string`/`number`/`boolean`/`object`): with `const` or
    `enum`, `format` is not supported and `pattern` has partial support as it
    will be treated as a simple string not a regex; regex is a DoS attack
    vector

  `array`: with `contains` where uses a simple type filter

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
        '"contains" with a simple type filter.');
    }
    return value;
  }
  if(VALUE_TYPES.has(type) || type === 'object' || type === undefined) {
    if(filter.const !== undefined) {
      value = filter.const;
    } else if(filter.pattern) {
      value = filter.pattern;
    } else if(filter.enum) {
      value = filter.enum.slice();
    } else if(filter.type === 'object') {
      value = {};
    } else if(strict && type === 'string') {
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

  // convert `example` into json pointers
  const {example = {}} = credentialQuery || {};
  const pointers = toJsonPointerMap({obj: example});

  // walk pointers and produce fields
  for(const [pointer, value] of pointers) {
    const path = jsonpointer.parse(pointer);

    const field = {
      path: [
        JSONPath.toPathString(['$', ...path])
      ]
    };
    // include 'vc' path for queries against JWT payloads instead of VCs
    if(prefixJwtVcPath) {
      field.path.push(JSONPath.toPathString(['$', 'vc', ...path]));
    }

    if(value instanceof Set) {
      field.filter = {
        type: 'array',
        allOf: [...value].map(value => ({
          contains: _primitiveValueToFilter(value)
        }))
      };
    } else {
      field.filter = _primitiveValueToFilter(value);
    }

    fields.push(field);
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
      const originalValue = value;
      if(!Array.isArray(value)) {
        value = [value];
      }

      // get JSON pointers for every path inside a verifiable credential
      const pointers = pathsToVerifiableCredentialPointers({paths: path});

      // add values at each path, converting to an array / appending as needed
      for(const pointer of pointers) {
        const existing = resolvePointer(example, pointer);
        if(existing === undefined) {
          jsonpointer.set(example, pointer, originalValue);
          continue;
        }

        if(Array.isArray(existing)) {
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

function _primitiveValueToFilter(value) {
  const filter = {
    type: typeof value
  };
  if(VALUE_TYPES.has(filter.type)) {
    filter.const = value;
  } else {
    // default to `object`
    filter.type = 'object';
  }
  return filter;
}
