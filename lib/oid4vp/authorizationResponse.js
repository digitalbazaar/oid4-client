/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {createNamedError, selectJwk} from '../util.js';
import {EncryptJWT} from 'jose';
import {httpClient} from '@digitalbazaar/http-client';
import jsonpointer from 'json-pointer';
import {pathsToVerifiableCredentialPointers} from '../convert/index.js';

const TEXT_ENCODER = new TextEncoder();

// creates an authorization response without sending it; use `send()` to create
// and send one at once
export async function create({
  verifiablePresentation,
  presentationSubmission,
  authorizationRequest,
  vpToken,
  encryptionOptions = {}
} = {}) {
  if(!(verifiablePresentation || vpToken)) {
    throw createNamedError({
      message: 'One of "verifiablePresentation" or "vpToken" must be given.',
      name: 'DataError'
    });
  }
  // if no `vpToken` given, use VP
  vpToken = vpToken ?? JSON.stringify(verifiablePresentation);

  // if no `presentationSubmission` provided, auto-generate one
  let generatedPresentationSubmission = false;
  if(!presentationSubmission) {
    ({presentationSubmission} = createPresentationSubmission({
      presentationDefinition: authorizationRequest.presentation_definition,
      verifiablePresentation
    }));
    generatedPresentationSubmission = true;
  }

  // prepare response body
  const body = {};

  // if `authorizationRequest.response_mode` is `direct.jwt` generate a JWT
  if(authorizationRequest.response_mode === 'direct_post.jwt') {
    if(submitsFormat({presentationSubmission, format: 'mso_mdoc'}) &&
      !encryptionOptions?.mdl?.sessionTranscript) {
      throw createNamedError({
        message: '"encryptionOptions.mdl.sessionTranscript" is required ' +
          'when submitting an mDL presentation.',
        name: 'DataError'
      });
    }

    const jwt = await _encrypt({
      vpToken, presentationSubmission, authorizationRequest,
      encryptionOptions
    });
    body.response = jwt;
  } else {
    // include vp token and presentation submittion directly in body
    body.vp_token = vpToken;
    body.presentation_submission = JSON.stringify(presentationSubmission);
  }

  const authorizationResponse = body;
  if(generatedPresentationSubmission) {
    // return any generated presentation submission
    return {authorizationResponse, presentationSubmission};
  }
  return {authorizationResponse};
}

export async function send({
  verifiablePresentation,
  presentationSubmission,
  authorizationRequest,
  vpToken,
  encryptionOptions = {},
  authorizationResponse,
  agent
} = {}) {
  try {
    // create `authorizationResponse` if not passed
    let generatedPresentationSubmission;
    if(!authorizationResponse) {
      ({
        authorizationResponse,
        presentationSubmission: generatedPresentationSubmission
      } = await create({
        verifiablePresentation,
        presentationSubmission,
        authorizationRequest,
        vpToken,
        encryptionOptions
      }));
    } else if(verifiablePresentation || presentationSubmission || vpToken ||
      encryptionOptions) {
      throw new TypeError(
        'Only "authorizationResponse" or its components ( ' +
        '"verifiablePresentation", "presentationSubmission", "vpToken", ' +
        '"encryptionOptions") can be passed, but not both.');
    }

    // prepare response body
    const body = new URLSearchParams(authorizationResponse);

    // send response
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
      return {result, presentationSubmission: generatedPresentationSubmission};
    }
    return {result};
  } catch(cause) {
    const message = cause.data?.error_description ?? cause.message;
    const error = new Error(
      `Could not send OID4VP authorization response: ${message}`,
      {cause});
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
    throw createNamedError({
      message: `Could not create presentation submission: ${cause.message}`,
      name: 'OperationError',
      cause
    });
  }

  return {presentationSubmission};
}

export function submitsFormat({presentationSubmission, format} = {}) {
  /* e.g. presentation submission submitting an mdoc:
  {
    "definition_id": "mDL-sample-req",
    "id": "mDL-sample-res",
    "descriptor_map": [{
      "id": "org.iso.18013.5.1.mDL",
      "format": "mso_mdoc",
      "path": "$"
    }]
  }
  */
  return presentationSubmission?.descriptor_map?.some(
    e => e?.format === format);
}

async function _encrypt({
  vpToken, presentationSubmission, authorizationRequest, encryptionOptions
}) {
  // get recipient public JWK from client_metadata JWK key set
  const jwks = authorizationRequest?.client_metadata?.jwks;
  const recipientPublicJwk = selectJwk({
    keys: jwks?.keys, alg: 'ECDH-ES', kty: 'EC', crv: 'P-256', use: 'enc'
  });
  if(!recipientPublicJwk) {
    throw createNamedError({
      message: 'No matching key found for "ECDH-ES" in client meta data ' +
        'JWK key set.',
      name: 'NotFoundError'
    });
  }

  // configure `keyManagementParameters` for `EncryptJWT` API
  const keyManagementParameters = {};
  if(encryptionOptions?.mdl?.sessionTranscript) {
    // ISO 18013-7: include specific session transcript params as apu + apv
    const {
      mdocGeneratedNonce,
      // default to using `authorizationRequest.nonce` for verifier nonce
      verifierGeneratedNonce = authorizationRequest.nonce
    } = encryptionOptions.mdl.sessionTranscript;
    // note: `EncryptJWT` API requires `apu/apv` (`partyInfoU`/`partyInfoV`)
    // to be passed as Uint8Arrays; they will be encoded using `base64url` by
    // that API
    keyManagementParameters.apu = TEXT_ENCODER.encode(mdocGeneratedNonce);
    keyManagementParameters.apv = TEXT_ENCODER.encode(verifierGeneratedNonce);
  }

  const claimSet = {
    vp_token: vpToken,
    presentation_submission: presentationSubmission
  };
  const jwt = await new EncryptJWT(claimSet)
    .setProtectedHeader({
      alg: 'ECDH-ES', enc: 'A256GCM',
      kid: recipientPublicJwk.kid
    })
    .setKeyManagementParameters(keyManagementParameters)
    .encrypt(recipientPublicJwk);
  return jwt;
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
      const error = createNamedError({
        message: `Could not process input descriptor field: "${id}".`,
        name: 'DataError',
        cause
      });
      error.field = field;
      throw error;
    }
  }

  return true;
}
