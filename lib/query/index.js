/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {dcqlCredentialQueryToJsonPointerMap} from './dcql.js';
import {exampleToJsonPointerMap} from './queryByExample.js';
import {inputDescriptorToJsonPointerMap} from './presentationExchange.js';

export {credentialMatches} from './match.js';

export const dcql = {
  toJsonPointerMap: dcqlCredentialQueryToJsonPointerMap
};
export const presentationExchange = {
  toJsonPointerMap: inputDescriptorToJsonPointerMap
};
export const queryByExample = {
  toJsonPointerMap: exampleToJsonPointerMap
};
