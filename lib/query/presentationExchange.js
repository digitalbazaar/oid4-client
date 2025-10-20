/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {JSONPath} from 'jsonpath-plus';
import jsonpointer from 'jsonpointer';

export function presentationDefinitionToQueryByExample({
  presentation_definition, strict = false
} = {}) {
  return {
    type: 'QueryByExample',
    credentialQuery: presentation_definition.input_descriptors.map(
      inputDescriptor => _toQueryByExampleQuery({inputDescriptor, strict}))
  };
}

export function queryByExampleToPresentationDefinition({
  queryByExample, prefixJwtVcPath
} = {}) {
  const credentialQuery = queryByExample.credentialQuery ?
    (Array.isArray(queryByExample.credentialQuery) ?
      queryByExample.credentialQuery : [queryByExample.credentialQuery]) : [];
  return {
    id: crypto.randomUUID(),
    input_descriptors: credentialQuery.map(q => _fromQueryByExampleQuery({
      credentialQuery: q,
      prefixJwtVcPath
    }))
  };
}

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
