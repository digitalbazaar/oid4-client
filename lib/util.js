/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {httpClient} from '@digitalbazaar/http-client';
import jsonpointer from 'json-pointer';

const TEXT_ENCODER = new TextEncoder();
const ENCODED_PERIOD = TEXT_ENCODER.encode('.');

export function assert(x, name, type, optional = false) {
  const article = type === 'object' ? 'an' : 'a';
  const xType = typeof type === 'string' ?
    typeof x : (x instanceof type && type);
  if(x !== undefined && xType !== type) {
    throw new TypeError(
      `${optional ? 'When present, ' : ''} ` +
      `"${name}" must be ${article} ${type?.name ?? type}.`);
  }
}

export function assertOptional(x, name, type) {
  return assert(x, name, type, true);
}

export function base64Decode(str) {
  if(Uint8Array.fromBase64) {
    return Uint8Array.fromBase64(str);
  }
  return base64url.decode(
    str.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'));
}

export function base64Encode(data) {
  if(data.toBase64) {
    return data.toBase64();
  }
  // note: this is base64-no-pad; will only work with specific data lengths
  return base64url.encode(data).replace(/-/g, '+').replace(/_/g, '/');
}

export function createNamedError({message, name, details, cause} = {}) {
  const error = new Error(message, {cause});
  error.name = name;
  if(details) {
    error.details = details;
  }
  return error;
}

export function fetchJSON({url, agent} = {}) {
  // allow these params to be passed / configured
  const fetchOptions = {
    // max size for issuer config related responses (in bytes, ~4 KiB)
    size: 4096,
    // timeout in ms for fetching an issuer config
    timeout: 5000,
    agent
  };

  return httpClient.get(url, fetchOptions);
}

export function fromJsonPointerMap({map} = {}) {
  assert(map, 'map', Map);
  return _fromPointers({map});
}

export function isNumber(x) {
  return typeof toNumberIfNumber(x) === 'number';
}

export function parseJSON(x, name) {
  try {
    return JSON.parse(x);
  } catch(cause) {
    throw createNamedError({
      message: `Could not parse "${name}".`,
      name: 'DataError',
      details: {httpStatusCode: 400, public: true},
      cause
    });
  }
}

export function selectJwk({keys, kid, alg, kty, crv, use} = {}) {
  /* Example JWKs "keys":
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "use": "enc",
        "crv": "P-256",
        "x": "...",
        "y": "...",
        "alg": "ECDH-ES",
        "kid": "..."
      }
    ]
  } */
  if(!Array.isArray(keys)) {
    return;
  }

  // match `kid` exactly if given
  if(kid !== undefined) {
    return keys.find(jwk => jwk?.kid === kid);
  }

  return keys.find(jwk => {
    // default unspecified search values to whatever is in `jwk`
    const alg1 = alg ?? jwk.alg;
    const kty1 = kty ?? jwk.kty;
    const crv1 = crv ?? jwk.crv;
    const use1 = use ?? jwk.use;
    const {
      // default missing `alg` value in `jwk` to search value
      alg: alg2 = alg1,
      kty: kty2,
      crv: crv2,
      // default missing `use` value in `jwk` to search value
      use: use2 = use1
    } = jwk;
    // return if `jwk` matches computed values
    return alg1 === alg2 && kty1 === kty2 && crv1 === crv2 && use1 === use2;
  });
}

export async function sha256(data) {
  if(typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  const algorithm = {name: 'SHA-256'};
  return new Uint8Array(await crypto.subtle.digest(algorithm, data));
}

export async function signJWT({payload, protectedHeader, signer} = {}) {
  // encode payload and protected header
  const b64Payload = base64url.encode(JSON.stringify(payload));
  const b64ProtectedHeader = base64url.encode(JSON.stringify(protectedHeader));
  payload = TEXT_ENCODER.encode(b64Payload);
  protectedHeader = TEXT_ENCODER.encode(b64ProtectedHeader);

  // concatenate
  const data = new Uint8Array(
    protectedHeader.length + ENCODED_PERIOD.length + payload.length);
  data.set(protectedHeader);
  data.set(ENCODED_PERIOD, protectedHeader.length);
  data.set(payload, protectedHeader.length + ENCODED_PERIOD.length);

  // sign
  const signature = await signer.sign({data});

  // create JWS
  const jws = {
    signature: base64url.encode(signature),
    payload: b64Payload,
    protected: b64ProtectedHeader
  };

  // create compact JWT
  return `${jws.protected}.${jws.payload}.${jws.signature}`;
}

// produces a map of deep pointers to primitives and sets; the values in each
// set share the same pointer value and if any value in the set is an object,
// it becomes a new map of deep pointers from that starting place; the pointer
// value for an empty objects will be an empty map
export function toJsonPointerMap({obj, flat = false} = {}) {
  assert(obj, 'obj', 'object');
  return _toPointers({cursor: obj, map: new Map(), flat});
}

export function toNumberIfNumber(x) {
  if(typeof x === 'number') {
    return x;
  }
  const num = parseInt(x, 10);
  if(!isNaN(num)) {
    return num;
  }
  return x;
}

export function _fromPointers({map} = {}) {
  const result = {};

  for(const [pointer, value] of map) {
    // convert any non-primitive values
    let val = value;
    if(value instanceof Map) {
      val = _fromPointers({map: value});
    } else if(value instanceof Set) {
      val = [...value].map(e => e instanceof Map ?
        _fromPointers({map: e}) : e);
    }

    // if root pointer is used, `value` is result
    if(pointer === '/') {
      return val;
    }

    jsonpointer.set(result, pointer, val);
  }

  return result;
}

function _toPointers({
  cursor, map, tokens = [], pointer = '/', flat = false
}) {
  if(!flat && Array.isArray(cursor)) {
    const set = new Set();
    // when `map` is not set, case is array of arrays; return a new map
    const result = map ? set : (map = new Map());
    map.set(pointer, set);
    for(const element of cursor) {
      // reset map, tokens, and pointer for array elements
      set.add(_toPointers({cursor: element, flat}));
    }
    return result;
  }
  if(cursor !== null && typeof cursor === 'object') {
    map = map ?? new Map();
    const entries = Object.entries(cursor);
    if(entries.length === 0) {
      // ensure empty object / array case is represented
      map.set(pointer, Array.isArray(cursor) ? new Set() : new Map());
    }
    for(const [token, value] of entries) {
      tokens.push(String(token));
      pointer = jsonpointer.compile(tokens);
      _toPointers({cursor: value, map, tokens, pointer, flat});
      tokens.pop();
    }
    return map;
  }
  map?.set(pointer, cursor);
  return cursor;
}
