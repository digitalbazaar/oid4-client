/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {httpClient} from '@digitalbazaar/http-client';
import jsonpointer from 'jsonpointer';
import {pathsToVerifiableCredentialPointers} from './convert.js';

export async function send({
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

    // if `authorizationRequest.response_mode` is `direct.jwt` generate a JWT
    if(authorizationRequest.response_mode === 'direct_post.jwt') {
      console.log('response_mode is direct_post.jwt');
      // FIXME: implement
      // FIXME: get key encryption JWK and other details from client metadata
      // FIXME: `authorizationRequest.client_metadata`

      /*
      // FIXME:
      const claimSet = {
        presentation_submission: {...},
        vp_token: '<base64url-encoded mdoc presentation>'
      };
      const jwt = await new jose.EncryptJWT(claimSet)
        .setProtectedHeader({
          alg: 'ECDH-ES', enc: 'A256GCM',
          kid: recipientPublicJwk.kid
        })
        .setKeyManagementParameters({
          apu: Buffer.from("", 'base64url'),
          apv: Buffer.from("", 'base64url'),
          // FIXME: leave blank to let library generate EPK
          epk: await crypto.subtle.importKey('jwk', senderPrivateJwk, {
            name: 'ECDH',
            namedCurve: 'P-256'
          }, true, ['deriveBits'])
        })
        // FIXME: bikeshed requirements
        .setIssuedAt()
        .setIssuer('urn:example:issuer')
        .setAudience('urn:example:audience')
        .setExpirationTime('2h')
        .encrypt(recipientPublicJwk);
      */
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

      // get JSON pointers for every path inside a verifiable credential
      const pointers = pathsToVerifiableCredentialPointers({paths: path});

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
