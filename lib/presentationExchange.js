/*!
 * Copyright (c) 2023 Digital Bazaar, Inc. All rights reserved.
 */

// converts a "presentation definition" to a VPR
export async function toVpr({presentationDefinition} = {}) {
  try {
    // FIXME: implement
    throw new Error('Not implemented');
  } catch(cause) {
    const error = new Error(
      'Could not convert presentation definition to ' +
      'verifiable presentation request.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}

// converts a VPR to a "presentation definition"
export async function fromVpr({verifiablePresentationRequest} = {}) {
  try {
    // FIXME: implement
    throw new Error('Not implemented');
  } catch(cause) {
    const error = new Error(
      'Could not convert verifiable presentation request to ' +
      'presentation definition.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}

// creates a "presentation submission" from a presentation definition and VP
export async function createPresentationSubmission({
  presentationDefinition, verifiablePresentation
} = {}) {
  try {
    // FIXME: match VP VCs to presentation definition,
    // maybe do two passes: do possible matches first, then do selections
    // based on availability

    // FIXME: implement
    throw new Error('Not implemented');
  } catch(cause) {
    const error = new Error(
      'Could not create presentation submission.');
    error.name = 'OperationError';
    error.cause = cause;
    throw error;
  }
}
