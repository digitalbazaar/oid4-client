/*!
 * Copyright (c) 2023-2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  Certificate,
  CertificateChainValidationEngine,
  id_SubjectAltName
} from 'pkijs';
import {base64Decode} from './util.js';

export function fromPemOrBase64(str) {
  const tag = 'CERTIFICATE';
  const pattern = new RegExp(
    `-{5}BEGIN ${tag}-{5}([a-zA-Z0-9=+\\/\\n\\r]+)-{5}END ${tag}-{5}`, 'g');
  const matches = pattern.exec(str);
  if(!matches) {
    throw new Error('No PEM or Base64-formatted certificate found.');
  }
  const b64 = matches[1].replace(/\r/g, '').replace(/\n/g, '');
  return _fromBase64(b64);
}

export function hasDomainSubjectAltName({certificate, name} = {}) {
  const subjectAltNames = new Set();
  for(const extension of certificate.extensions) {
    if(extension.extnID === id_SubjectAltName) {
      for(const altName of extension.parsedValue.altNames) {
        // `domain` type
        if(altName.type === 2) {
          subjectAltNames.add(altName.value);
        }
      }
    }
  }
  return subjectAltNames.has(name);
}

export function parseCertificateChain({x5c} = {}) {
  return x5c.map(c => Certificate.fromBER(base64Decode(c)));
}

export async function verifyCertificateChain({
  chain, trustedCertificates
} = {}) {
  if(!(chain?.length > 0)) {
    throw new Error('No matching certificate.');
  }

  const chainEngine = new CertificateChainValidationEngine({
    certs: chain.map(c => typeof c === 'string' ? fromPemOrBase64(c) : c),
    trustedCerts: trustedCertificates.map(
      c => typeof c === 'string' ? fromPemOrBase64(c) : c)
  });

  const verifyResult = await chainEngine.verify();
  return verifyResult;
}

function _fromBase64(str) {
  return Certificate.fromBER(base64Decode(str));
}
