/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {isObject, resolvePointer, toNumberIfNumber} from './util.js';

/**
 * Returns whether a credential matches against a JSON pointer map.
 *
 * A JSON pointer map must be created from a QueryByExample `example`, a DCQL
 * `credential` query value, or a Presentation Exchange input descriptor
 * by calling the respective utility APIs in this library. It is more efficient
 * to produce this JSON pointer map just once when looking for matches in a
 * list of more than one credential.
 *
 * @param {object} options - The options.
 * @param {object} options.credential - The credential to try to match.
 * @param {Map} options.map - The JSON pointer map.
 * @param {object} options.options - Match options, such as:
 *   [coerceNumbers=true] - String/numbers will be coerced.
 *
 * @returns {boolean} `true` if the credential matches, `false` if not.
 */
export function credentialMatches({
  credential, map, options = {coerceNumbers: true}
} = {}) {
  // credential must be an object to match
  if(!isObject(credential)) {
    return false;
  }
  return _match({cursor: credential, matchValue: map, options});
}

function _match({cursor, matchValue, options}) {
  // handle wildcard matching
  if(_isWildcard(matchValue)) {
    return true;
  }

  if(matchValue instanceof Set) {
    // some element in the set must match `cursor`
    return [...matchValue].some(e => _match({cursor, matchValue: e, options}));
  }

  if(matchValue instanceof Map) {
    // all pointers and values in the map must match `cursor`
    return [...matchValue.entries()].every(([pointer, matchValue]) => {
      const value = resolvePointer(cursor, pointer);
      if(value === undefined) {
        // no value at `pointer`; no match
        return false;
      }
      // handles case where `value` is an empty array + wildcard `matchValue`
      if(_isWildcard(matchValue)) {
        return true;
      }
      // normalize value to an array for matching
      const values = Array.isArray(value) ? value : [value];
      return values.some(v => _match({cursor: v, matchValue, options}));
    });
  }

  // primitive comparison
  if(cursor === matchValue) {
    return true;
  }

  // string/number coercion
  if(options.coerceNumbers) {
    const cursorNumber = toNumberIfNumber(cursor);
    const matchNumber = toNumberIfNumber(matchValue);
    return cursorNumber !== undefined && cursorNumber === matchNumber;
  }

  return false;
}

function _isWildcard(value) {
  // empty string, Map, or Set
  return value === '' || value?.size === 0;
}
