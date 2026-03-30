/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import {assert, fetchJSON} from '../util.js';

export function createAuthorizationDetailsFromOffer({
  issuerConfig, offer, supportedFormats
} = {}) {
  if(!(Array.isArray(issuerConfig.authorization_details_types_supported) &&
    issuerConfig.authorization_details_types_supported
      .includes('openid_credential'))) {
    // issuer does not support authz details
    return;
  }

  // build authz details from configs that match `offer` and `supportedFormats`
  const configs = getCredentialConfigurations({
    issuerConfig, offer, supportedFormats
  });
  const authorizationDetails = configs.map(
    c => ({
      type: 'openid_credential',
      credential_configuration_id: c.id
    }));
  // only return details if there are matching configuration IDs
  return authorizationDetails.length > 0 ? authorizationDetails : undefined;
}

export function createCredentialRequestsFromOffer({
  issuerConfig, offer, format, authorizationDetails
} = {}) {
  // get credential configs that match `offer` and `format`
  const matchingConfigurations = getCredentialConfigurations({
    issuerConfig, offer, supportedFormats: [format]
  });

  // build requests...
  let requests;

  // the presence of `authorizationDetails` triggers OID4VCI 1.0+ format,
  // which uses `credential_identifier` instead of
  // Draft 13 `format` + `credential_definition`
  if(authorizationDetails) {
    // add a request for each `credential_identifier` mentioned in each
    // matching configuration
    requests = [];
    const matchingIds = new Set(matchingConfigurations.map(({id}) => id));
    for(const element of authorizationDetails) {
      const {
        type, credential_configuration_id, credential_identifiers = []
      } = element;
      if(type !== 'openid_credential') {
        continue;
      }
      if(matchingIds.has(credential_configuration_id)) {
        requests.push(
          ...credential_identifiers.map(id => ({credential_identifier: id})));
      }
    }
  } else {
    // OID4VCI Draft 13 request format
    requests = matchingConfigurations.map(
      ({format, credential_definition}) => ({format, credential_definition}));
  }
  if(!(requests?.length > 0)) {
    throw new Error(
      `No supported credential(s) with format "${format}" found.`);
  }

  return requests;
}

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

export function getCredentialConfigurations({
  issuerConfig, offer, credentialConfigurationIds, supportedFormats
} = {}) {
  // get all supported credential configurations from issuer config
  let supported = [
    ..._createSupportedCredentialsMap({issuerConfig}).entries()]
    .map(([id, c]) => ({id, ...c}));

  // compute `credentialConfigurationIds` from `offer` as necessary
  if(offer && !credentialConfigurationIds) {
    if(offer.credential_configuration_ids) {
      credentialConfigurationIds = offer.credential_configuration_ids;
    } else if(offer.credentials) {
      // allow legacy `offer.credentials` that express IDs
      credentialConfigurationIds = offer.credentials
        .map(c => typeof c === 'string' ? c : undefined)
        .filter(c => c !== undefined);

      // if no IDs; handle degenerate case of objects expressed in
      // `offer.credentials` for pre-draft 13, to be dropped in a future major
      // release that also drops draft 13 support
      if(credentialConfigurationIds.length === 0) {
        supported = offer.credentials.filter(c => typeof c === 'object');
        credentialConfigurationIds = undefined;
      }
    }
  }

  // filter by IDs, if given
  if(credentialConfigurationIds) {
    const idSet = new Set(credentialConfigurationIds);
    supported = supported.filter(c => idSet.has(c.id));
  }

  // filter by supported formats, if given
  if(supportedFormats) {
    const formatSet = new Set(supportedFormats);
    supported = supported.filter(c => formatSet.has(c.format));
  }

  return supported;
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

function _createSupportedCredentialsMap({issuerConfig}) {
  const {
    credential_configurations_supported,
    credentials_supported
  } = issuerConfig;

  let supported;
  if(credential_configurations_supported &&
    typeof credential_configurations_supported === 'object') {
    supported = new Map(Object.entries(
      issuerConfig.credential_configurations_supported));
  } else if(Array.isArray(credentials_supported)) {
    // handle legacy `credentials_supported` array
    supported = new Map();
    for(const entry of issuerConfig.credentials_supported) {
      supported.set(entry.id, entry);
    }
  } else {
    // no supported credentials from issuer config
    supported = new Map();
  }

  return supported;
}
