/*!
 * Copyright (c) 2022-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {assert, fetchJSON} from '../util.js';

export async function getCredentialOffer({url, agent} = {}) {
  const {protocol, searchParams} = new URL(url);
  if(protocol !== 'openid-credential-offer:') {
    throw new SyntaxError(
      '"url" must express a URL with the ' +
      '"openid-credential-offer" protocol.');
  }
  const offer = searchParams.get('credential_offer');
  if(offer) {
    return JSON.parse(offer);
  }

  // try to fetch offer from URL
  const offerUrl = searchParams.get('credential_offer_uri');
  if(!offerUrl) {
    throw new SyntaxError(
      'OID4VCI credential offer must have "credential_offer" or ' +
      '"credential_offer_uri".');
  }

  if(!offerUrl.startsWith('https://')) {
    const error = new Error(
      `"credential_offer_uri" (${offerUrl}) must start with "https://".`);
    error.name = 'NotSupportedError';
    throw error;
  }

  const response = await fetchJSON({url: offerUrl, agent});
  if(!response.data) {
    const error = new Error(
      `Credential offer fetched from "${offerUrl}" is not JSON.`);
    error.name = 'DataError';
    throw error;
  }
  return response.data;
}

export function parseCredentialOfferUrl({url} = {}) {
  assert(url, 'url', 'string');

  /* Parse URL, e.g.:

  'openid-credential-offer://?' +
    'credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2F' +
    'localhost%3A18443%2Fexchangers%2Fz19t8xb568tNRD1zVm9R5diXR%2F' +
    'exchanges%2Fz1ADs3ur2s9tm6JUW6CnTiyn3%22%2C%22credentials' +
    '%22%3A%5B%7B%22format%22%3A%22ldp_vc%22%2C%22credential_definition' +
    '%22%3A%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2F' +
    'credentials%2Fv1%22%2C%22https%3A%2F%2Fwww.w3.org%2F2018%2F' +
    'credentials%2Fexamples%2Fv1%22%5D%2C%22type%22%3A%5B%22' +
    'VerifiableCredential%22%2C%22UniversityDegreeCredential' +
    '%22%5D%7D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams' +
    '%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22' +
    'pre-authorized_code%22%3A%22z1AEvnk2cqeRM1Mfv75vzHSUo%22%7D%7D%7D';
  */
  const {protocol, searchParams} = new URL(url);
  if(protocol !== 'openid-credential-offer:') {
    throw new SyntaxError(
      '"url" must express a URL with the ' +
      '"openid-credential-offer" protocol.');
  }
  return JSON.parse(searchParams.get('credential_offer'));
}
