/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {toJsonPointerMap} from './util.js';

export function exampleToJsonPointerMap({example} = {}) {
  return toJsonPointerMap({obj: example, flat: false});
}
