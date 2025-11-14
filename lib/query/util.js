/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {assert} from '../util.js';
import jsonpointer from 'json-pointer';

export function fromJsonPointerMap({map} = {}) {
  assert(map, 'map', Map);
  return _fromPointers({map});
}

export function isNumber(x) {
  return typeof toNumberIfNumber(x) === 'number';
}

export function isObject(x) {
  return x && typeof x === 'object' && !Array.isArray(x);
}

export function resolvePointer(obj, pointer) {
  try {
    return jsonpointer.get(obj, pointer);
  } catch(e) {
    return undefined;
  }
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
      val = [...value].map(e => e instanceof Map ? _fromPointers({map: e}) : e);
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
