/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {isObject, resolvePointer} from './util.js';

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
 *
 * @returns {boolean} `true` if the credential matches, `false` if not.
 */
export function credentialMatches({credential, map} = {}) {
  // credential must be an object to match
  if(!(credential && typeof credential === 'object' &&
    !Array.isArray(credential))) {
    return false;
  }
  return _match({cursor: credential, matchValue: map});
}

function _match({cursor, matchValue}) {
  // handle wildcard matching
  if(_isWildcard(matchValue)) {
    return true;
  }

  if(matchValue instanceof Set) {
    if(!Array.isArray(cursor)) {
      return false;
    }
    // some element in `cursor` must match an element in `matchValue`
    const array = [...matchValue];
    return cursor.some(
      value => array.some(e => _match({cursor: value, matchValue: e})));
  }

  if(matchValue instanceof Map) {
    if(!isObject(cursor)) {
      return false;
    }
    // all pointers and values in the map must match `cursor`
    return [...matchValue.entries()].every(([pointer, matchValue]) => {
      let value = resolvePointer(cursor, pointer);
      if(value === undefined) {
        return false;
      }
      // normalize value to an array for matching
      if(!Array.isArray(value)) {
        value = [value];
      }
      // one value in the array must match
      if(!value.some(v => _match({cursor: v, matchValue}))) {
        return false;
      }
      return true;
    });
  }

  return cursor === matchValue;
}

function _isWildcard(value) {
  const isArray = Array.isArray(value);
  const emptyString = value === '';
  let emptyArray = false;
  let emptyObject = false;
  if(isArray) {
    emptyArray = value.length === 0;
  } else if(value && typeof value === 'object' && Object.keys(value) === 0) {
    emptyObject = true;
  }
  return emptyString || emptyArray || emptyObject;
}
