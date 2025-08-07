/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {assert, assertOptional, fetchJSON} from './util.js';
import {decodeJwt} from 'jose';
import {httpClient} from '@digitalbazaar/http-client';
import {JSONPath} from 'jsonpath-plus';
import jsonpointer from 'jsonpointer';

// For examples of presentation request and responses, see:
// eslint-disable-next-line max-len
// https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#appendix-A.1.2.2

// get an authorization request from a verifier
export async function getAuthorizationRequest({
  url, agent, documentLoader
} = {}) {
  try {
    assert(url, 'url', 'string');
    assertOptional(documentLoader, 'documentLoader', 'function');

    let requestUrl = url;
    let expectedClientId;
    if(url.startsWith('openid4vp://')) {
      const {authorizationRequest} = _parseOID4VPUrl({url});
      if(authorizationRequest.request) {
        const error = new Error(
          'JWT-Secured Authorization Request (JAR) not implemented.');
        error.name = 'NotSupportedError';
        throw error;
      }
      if(!authorizationRequest.request_uri) {
        // return direct request
        return {authorizationRequest, fetched: false};
      }
      requestUrl = authorizationRequest.request_uri;
      ({client_id: expectedClientId} = authorizationRequest);
    }

    // FIXME: every `fetchJSON` call needs to use a block list or other
    // protections to prevent a confused deputy attack where the `requestUrl`
    // accesses a location it should not, e.g., is on localhost and should
    // not be used in this way
    const response = await fetchJSON({url: requestUrl, agent});

    // parse payload from response data...
    const contentType = response.headers.get('content-type');
    const jwt = await response.text();
    // verify response is a JWT-secured authorization request
    if(!(contentType.includes('application/oauth-authz-req+jwt') &&
      typeof jwt === 'string')) {
      const error = new Error(
        'Authorization request content-type must be ' +
        '"application/oauth-authz-req+jwt".');
      error.name = 'DataError';
      throw error;
    }

    // decode JWT *WITHOUT* verification
    const payload = decodeJwt(jwt);

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
    // ensure `client_id` matches expected client ID
    if(expectedClientId !== undefined && client_id !== expectedClientId) {
      const error = new Error(
        '"client_id" in fetched request does not match authorization ' +
        'request URL parameter.');
      error.name = 'DataError';
      throw error;
    }
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
    return {authorizationRequest, fetched: true, requestUrl, response, jwt};
  } catch(cause) {
    const error = new Error('Could not get authorization request.', {cause});
    error.name = 'OperationError';
    throw error;
  }
}

export async function sendAuthorizationResponse({
  verifiablePresentation,
  presentationSubmission,
  authorizationRequest,
  vpToken,
  agent
} = {}) {
  try {
    // if no `presentationSubmission` provided, auto-generate one
    let generatedPresentationSubmission = false;
    if(!presentationSubmission) {
      ({presentationSubmission} = createPresentationSubmission({
        presentationDefinition: authorizationRequest.presentation_definition,
        verifiablePresentation
      }));
      generatedPresentationSubmission = true;
    }

    // send VP and presentation submission to complete exchange
    const body = new URLSearchParams();
    body.set('vp_token', vpToken ?? JSON.stringify(verifiablePresentation));
    body.set('presentation_submission', JSON.stringify(presentationSubmission));
    const response = await httpClient.post(authorizationRequest.response_uri, {
      agent, body, headers: {accept: 'application/json'},
      // FIXME: limit response size
      // timeout in ms for response
      timeout: 5000
    });
    // return response data as `result`
    const result = response.data || {};
    if(generatedPresentationSubmission) {
      // return any generated presentation submission
      return {result, presentationSubmission};
    }
    return {result};
  } catch(cause) {
    const error = new Error(
      'Could not send OID4VP authorization response.', {cause});
    error.name = 'OperationError';
    throw error;
  }
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
      'an OID4VP authorization request.', {cause});
    error.name = 'OperationError';
    throw error;
  }
}

// creates a "presentation submission" from a presentation definition and VP
export function createPresentationSubmission({
  presentationDefinition, verifiablePresentation
} = {}) {
  const descriptor_map = [];
  const presentationSubmission = {
    id: crypto.randomUUID(),
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
      'Could not create presentation submission.', {cause});
    error.name = 'OperationError';
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
      if(!(Array.isArray(path) || typeof path === 'string')) {
        throw new Error(
          'Input descriptor field "path" must be a string or array.');
      }

      // process any filter
      let value = '';
      if(filter !== undefined) {
        value = _filterToValue({filter, strict});
      }
      // no value to match, presume no match
      if(value === undefined) {
        return false;
      }
      // normalize value to array
      if(!Array.isArray(value)) {
        value = [value];
      }

      // filter out erroneous paths
      let paths = Array.isArray(path) ? path : [path];
      paths = _adjustErroneousPaths(paths);
      // convert each JSON path to a JSON pointer
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
        `Could not process input descriptor field: "${id}".`, {cause});
      error.field = field;
      throw error;
    }
  }

  return true;
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
    require_signed_request_object: false,
    vp_formats: {
      ldp_vp: {
        proof_type: cryptosuites
      }
    }
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

      // filter out erroneous paths
      let paths = Array.isArray(path) ? path : [path];
      paths = _adjustErroneousPaths(paths);
      // convert each JSON path to a JSON pointer
      const pointers = paths.map(_jsonPathToJsonPointer);

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

function _adjustErroneousPaths(paths) {
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

function _parseOID4VPUrl({url}) {
  const {searchParams} = new URL(url);
  const request = _get(searchParams, 'request');
  const request_uri = _get(searchParams, 'request_uri');
  const response_type = _get(searchParams, 'response_type');
  const response_mode = _get(searchParams, 'response_mode');
  const presentation_definition = _get(
    searchParams, 'presentation_definition');
  const presentation_definition_uri = _get(
    searchParams, 'presentation_definition_uri');
  const client_id = _get(searchParams, 'client_id');
  const client_id_scheme = _get(searchParams, 'client_id_scheme');
  const client_metadata = _get(searchParams, 'client_metadata');
  const nonce = _get(searchParams, 'nonce');
  const response_uri = _get(searchParams, 'response_uri');
  const state = _get(searchParams, 'state');
  if(request && request_uri) {
    const error = new Error(
      'Only one of "request" and "request_uri" may be present.');
    error.name = 'DataError';
    error.url = url;
    throw error;
  }
  if(!(request || request_uri)) {
    if(response_type !== 'vp_token') {
      throw new Error(`Unsupported "response_type", "${response_type}".`);
    }
    if(response_mode !== 'direct_post') {
      throw new Error(`Unsupported "response_type", "${response_type}".`);
    }
  }
  const authorizationRequest = {
    request,
    request_uri,
    response_type,
    response_mode,
    presentation_definition: presentation_definition &&
      JSON.parse(presentation_definition),
    presentation_definition_uri,
    client_id,
    client_id_scheme,
    client_metadata: client_metadata && JSON.parse(client_metadata),
    response_uri,
    nonce,
    state
  };
  return {authorizationRequest};
}

function _get(sp, name) {
  const value = sp.get(name);
  return value === null ? undefined : value;
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
