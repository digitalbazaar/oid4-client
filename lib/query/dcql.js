/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  fromJsonPointerMap, isNumber, toJsonPointerMap, toNumberIfNumber
} from './util.js';
import jsonpointer from 'json-pointer';

const MDOC_MDL = 'org.iso.18013.5.1.mDL';

export function dcqlQueryToVprGroups({dcql_query} = {}) {
  const {credentials} = dcql_query;
  let {credential_sets: credentialSets} = dcql_query;
  if(!credentialSets) {
    credentialSets = [{
      options: [credentials.map(q => q.id)]
    }];
  }

  // convert `credentials` into a map based on `ID`
  const credentialQueryMap = new Map(credentials.map(
    query => [query.id, query]));

  // output group map
  const groupMap = new Map();
  for(const credentialSet of credentialSets) {
    for(const option of credentialSet.options) {
      const groupId = crypto.randomUUID();
      const queries = option.map(id => {
        const dcqlCredentialQuery = credentialQueryMap.get(id);
        return {
          type: 'QueryByExample',
          group: groupId,
          credentialQuery: _toQueryByExampleQuery({dcqlCredentialQuery})
        };
      });
      groupMap.set(groupId, new Map([['QueryByExample', queries]]));
    }
  }
  return groupMap;
}

export function vprGroupsToDcqlQuery({groupMap, options = {}} = {}) {
  // if there is any DCQL query, return it as-is
  const groups = [...groupMap.values()];
  let dcqlQuery = groups
    .filter(g => g.has('DigitalCredentialQueryLanguage'))
    .map(g => g.get('DigitalCredentialQueryLanguage'))
    .at(-1);
  if(dcqlQuery) {
    return dcqlQuery;
  }

  // convert all `QueryByExample` queries to a single DCQL query
  const {nullyifyArrayIndices = false} = options;
  dcqlQuery = {};
  const credentials = [];
  const credentialSets = [{options: []}];

  // note: same group ID is logical "AND" and different group ID is "OR"
  for(const queries of groups) {
    // only `QueryByExample` is convertible
    const queryByExamples = queries.get('QueryByExample');
    if(!(queryByExamples?.length > 0)) {
      continue;
    }

    // for each `QueryByExample`, add another option
    const option = [];
    for(const queryByExample of queryByExamples) {
      // should only be one `credentialQuery` but handle each one as a new
      // DCQL credential query
      const all = Array.isArray(queryByExample.credentialQuery) ?
        queryByExample.credentialQuery : [queryByExample.credentialQuery];
      for(const credentialQuery of all) {
        const result = _fromQueryByExampleQuery({
          credentialQuery, nullyifyArrayIndices
        });
        credentials.push(result);
        // DCQL credential set "option" includes all queries in the "AND" group
        option.push(result.id);
      }
    }

    // add "option" as another "OR" in the DCQL "options"
    credentialSets[0].options.push(option);
  }

  if(credentials.length > 0) {
    dcqlQuery.credentials = credentials;
  }
  if(credentialSets.length > 0) {
    dcqlQuery.credential_sets = credentialSets;
  }

  return dcqlQuery;
}

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
  if(credentialQuery?.reason) {
    result.meta.reason = credentialQuery.reason;
  }

  const {example = {}} = credentialQuery ?? {};

  // determine credential format
  if(Array.isArray(credentialQuery.acceptedEnvelopes)) {
    const set = new Set(credentialQuery.acceptedEnvelopes);
    if(set.has('application/jwt')) {
      result.format = 'jwt_vc_json';
    } else if(set.has('application/mdl')) {
      result.format = 'mso_mdoc';
      result.meta = {doctype_value: MDOC_MDL};
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
    // parse path into DCQL path w/ numbers for array indexes
    let path = jsonpointer.parse(pointer).map(toNumberIfNumber);

    // special process non-`@context` paths to convert some array indexes
    // to DCQL `null` (which means "any" index)
    if(path[0] !== '@context') {
      if(nullyifyArrayIndices) {
        // brute force convert every array index to `null` by request
        path = path.map(p => isNumber(p) ? null : p);
      } else if(isNumber(path.at(-1)) && !isNumber(path.at(-2))) {
        // when a pointer terminates at an array element it means candidate
        // matching values are expressed in the `example`, so make sure to
        // share the path for all candidates
        path[path.length - 1] = null;
      }
    }

    // compile processed path back to a key to consolidate `values`
    const key = jsonpointer.compile(path.map(p => p === null ? 'null' : p));

    // create shared entry for path and candidate matching values
    let entry = pathsMap.get(key);
    if(!entry) {
      entry = {path, valueSet: new Set()};
      pathsMap.set(key, entry);
    }

    // add any non-QueryByExample-wildcard as a DCQL candidate match value
    if(!(value === '' || value instanceof Map || value instanceof Set)) {
      entry.valueSet.add(value);
    }
  }

  // produce DCQL `claims`
  const claims = [...pathsMap.values()].map(({path, valueSet}) => {
    const claim = {path};
    if(valueSet.size > 0) {
      claim.values = [...valueSet];
    }
    return claim;
  });

  if(claims.length > 0) {
    result.claims = claims;
  }

  return result;
}

// exported for testing purposes only
export function _toQueryByExampleQuery({dcqlCredentialQuery}) {
  // convert DCQL credential query to pointers
  const pointers = new Map();
  const {format, meta, claims = []} = dcqlCredentialQuery;
  for(const claim of claims) {
    const {values} = claim;

    // a trailing `null` in a path means `values` should be treated as a set
    // of candidates inside an array value at path-1
    const path = claim.path?.at(-1) === null ?
      claim.path.slice(0, -1) : claim.path;

    // convert `null` path tokens to an index; assume the use of `null` will
    // not be combined with any other index
    const pointer = jsonpointer.compile(path.map(p => p === null ? '0' : p));
    if(!values) {
      pointers.set(pointer, '');
    } else if(values.length === 1 && claim.path.at(-1) !== null) {
      // convert a single choice for a non-array value to a primitive
      pointers.set(pointer, values[0]);
    } else {
      pointers.set(pointer, new Set(values));
    }
  }

  const credentialQuery = {};
  if(meta?.reason) {
    credentialQuery.reason = meta.reason;
  }

  // convert pointers to example object
  credentialQuery.example = fromJsonPointerMap({map: pointers});

  if(format === 'jwt_vc_json') {
    credentialQuery.acceptedEnvelopes = ['application/jwt'];
  } else if(format === 'mso_mdoc') {
    if(meta?.doctype_value === MDOC_MDL) {
      credentialQuery.acceptedEnvelopes = ['application/mdl'];
    } else {
      credentialQuery.acceptedEnvelopes = ['application/mdoc'];
    }
  } else if(format === 'dc+sd-jwt') {
    // FIXME: consider adding `vct_values` as params
    credentialQuery.acceptedEnvelopes = ['application/dc+sd-jwt'];
  }

  return credentialQuery;
}
