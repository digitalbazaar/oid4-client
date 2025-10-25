/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {isNumber, toJsonPointerMap} from '../util.js';
import jsonpointer from 'json-pointer';

// exported for testing purposes only
export function _fromQueryByExampleQuery({
  credentialQuery, nullyifyArrayIndices = false
}) {
  const result = {
    id: crypto.randomUUID(),
    format: 'ldp_vc',
    meta: {
      type_values: ['https://www.w3.org/2018/credentials#VerifiableCredential']
    }
  };

  const {example = {}} = credentialQuery || {};

  // determine credential format
  if(Array.isArray(credentialQuery.acceptedEnvelopes)) {
    const set = new Set(credentialQuery.acceptedEnvelopes);
    if(set.has('application/jwt')) {
      result.format = 'jwt_vc_json';
    } else if(set.has('application/mdl')) {
      result.format = 'mso_mdoc';
      result.meta = {doctype_value: 'org.iso.18013.5.1.mDL'};
    } else if(set.has('application/dc+sd-jwt')) {
      result.format = 'dc+sd-jwt';
      result.meta = {vct_values: []};
      if(Array.isArray(example?.type)) {
        result.meta.vct_values.push(...example.type);
      } else if(typeof example.type === 'string') {
        result.meta.vct_values.push(example.type);
      }
    }
  }

  // convert `example` into json pointers and walk to produce DCQL claim paths
  const pointers = toJsonPointerMap({obj: example, flat: true});

  const pathsMap = new Map();
  for(const [pointer, value] of pointers) {
    let path = jsonpointer.parse(pointer);
    const isContext = path[0] === '@context';

    // check for array value that is not in an array
    if(!isContext && isNumber(path.at(-1)) && !isNumber(path.at(-2))) {
      // pointer terminates at an array element which means candidate matching
      // values are expressed; make sure to share the path for all candidates
      path.pop();
    }

    // convert subpaths into `null` numbers
    if(!isContext && nullyifyArrayIndices) {
      path = path.map(p => isNumber(p) ? null : p);
    } else {
      path = path.map(p => isNumber(p) ? parseInt(p, 10) : p);
    }

    const key = jsonpointer.compile(path.map(p => p === null ? 'null' : p));

    // create entry for path and combining candidate matching values
    let entry = pathsMap.get(key);
    if(!entry) {
      entry = {path, valueSet: new Set()};
      pathsMap.set(key, entry);
    }

    // add any non-QueryByExample-wildcard as a DCQL match value
    if(!(value === '' || value instanceof Map || value instanceof Set)) {
      entry.valueSet.add(value);
    }
  }

  // produce DCQL `claims`
  const claims = [...pathsMap.values()].map(({path, valueSet}) => {
    const entry = {path};
    if(valueSet.size > 0) {
      entry.values = [...valueSet];
    }
    return entry;
  });

  if(claims.length > 0) {
    result.claims = claims;
  }

  return result;
}
