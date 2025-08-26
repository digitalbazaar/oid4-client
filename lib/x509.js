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

  const certificates = [];
  // FIXME: use regex split instead
  // FIXME: ensure if there are no matches to just run base64Decode()
  let matches = pattern.exec(str);
  while(matches) {
    const base64 = matches[1].replace(/\r/g, '').replace(/\n/g, '');
    certificates.push(Certificate.fromBER(base64Decode(base64)));
    matches = pattern.exec(str);
  }

  return certificates;
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
  // FIXME: remove logging
  console.log('subjectAltNames', subjectAltNames);
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
