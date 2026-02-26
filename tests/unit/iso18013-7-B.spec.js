/*!
 * Copyright (c) 2022-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as mdlUtils from '../mdlUtils.js';
import {exportJWK, generateKeyPair} from 'jose';
import {oid4vp, signJWT} from '../../lib/index.js';
import chai from 'chai';
import {generateCertificateChain} from '../certUtils.js';

chai.should();
const {expect} = chai;

describe('OID4VP ISO 18013-7 Annex B', () => {
  it('should pass', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // create a certificate chain that ends in the MDL issuer (leaf)
    const issuerCertChainEntities = await generateCertificateChain();

    // issue an example MDL
    const issuerPrivateJwk = issuerCertChainEntities.leaf.subject.jwk;
    const issuerCertificate = issuerCertChainEntities.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // generate example verifier identity and cert chain...

    // auto-generate `x5c` that includes public key for signing key
    const leafDnsName = 'mdl.reader.example';
    const verifierCertificateChainEntities = await generateCertificateChain({
      leafConfig: {dnsName: leafDnsName}
    });
    const x5c = [verifierCertificateChainEntities.leaf.b64Certificate];
    // trusted certs for verifying authz request from verifier, NOT for
    // verifying mDL from issuer
    const verifierCertificateChain = [
      verifierCertificateChainEntities.intermediate.pemCertificate,
      verifierCertificateChainEntities.root.pemCertificate
    ];

    // create example presentation defintion from verifier
    const presentationDefinition = {
      id: 'mdl-test-age-over-21',
      input_descriptors: [
        {
          id: 'org.iso.18013.5.1.mDL',
          format: {
            mso_mdoc: {
              alg: ['ES256']
            }
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                // eslint-disable-next-line quotes
                path: ["$['org.iso.18013.5.1']['age_over_21']"],
                intent_to_retain: false
              }
            ]
          }
        }
      ]
    };

    // create verifier key agreement pair
    const keyAgreementKeyPair = await generateKeyPair('ECDH-ES', {
      crv: 'P-256', extractable: true
    });
    const [kakPrivateKeyJwk, kakPublicKeyJwk] = await Promise.all([
      exportJWK(keyAgreementKeyPair.privateKey),
      exportJWK(keyAgreementKeyPair.publicKey)
    ]);
    kakPublicKeyJwk.use = 'enc';
    kakPublicKeyJwk.alg = 'ECDH-ES';
    kakPrivateKeyJwk.kid = kakPublicKeyJwk.kid =
      `urn:uuid:${crypto.randomUUID()}`;

    // create authorization request
    const authorizationRequest = {
      aud: 'https://self-issued.me/v2',
      client_id: 'mdl.reader.example',
      client_id_scheme: 'x509_san_dns',
      client_metadata: {
        require_signed_request_object: true,
        vp_formats: {
          mso_mdoc: {
            alg: ['ES256', 'ES384']
          }
        },
        jwks: {
          keys: [kakPublicKeyJwk]
        }
      },
      presentation_definition: presentationDefinition,
      response_mode: 'direct_post.jwt',
      response_type: 'vp_token',
      response_uri: 'https://mdl.reader.example/' +
        'workflows/1/exchanges/2/openid/clients/default/authorization/response',
      // note: not strictly 128-bits of random; should instead use 128-bits
      nonce: crypto.randomUUID()
    };

    // create signed authorization request
    const payload = {
      ...authorizationRequest
    };
    const protectedHeader = {
      typ: 'JWT',
      alg: 'ES256',
      kid: kakPublicKeyJwk.kid,
      x5c
    };
    const signer = {
      async sign({data}) {
        // verifier signs authz request
        const {keyPair} = verifierCertificateChainEntities.leaf.subject;
        const algorithm = {name: 'ECDSA', hash: {name: 'SHA-256'}};
        const signature = new Uint8Array(await crypto.subtle.sign(
          algorithm, keyPair.privateKey, data));
        return signature;
      }
    };
    const authzRequestJwt = await signJWT({payload, protectedHeader, signer});

    // get authz request JWT using oid4-client; this will also verify the JWT
    const searchParams = new URLSearchParams({
      client_id: leafDnsName,
      // expected to be `request_uri` not `request` in a deployed system
      request: authzRequestJwt
    });
    const mdocUrl = `mdoc-openid4vp://?${searchParams}`;
    const getAuthzRequestResult = await oid4vp.getAuthorizationRequest({
      url: mdocUrl, getTrustedCertificates: () => verifierCertificateChain
    });

    // ensure parsed authz request matches generated one
    expect(getAuthzRequestResult.authorizationRequest).to.deep.equal(
      authorizationRequest);

    // create an MDL handover for ISO 18013-7 Annex B
    const handover = {
      type: 'AnnexBHandover',
      // note: not strictly 128-bits of random; should instead use 128-bits
      mdocGeneratedNonce: crypto.randomUUID(),
      clientId: authorizationRequest.client_id,
      responseUri: authorizationRequest.response_uri,
      verifierGeneratedNonce: authorizationRequest.nonce
    };

    // create MDL "device response" presentation
    const deviceResponse = await mdlUtils.createDeviceResponse({
      presentationDefinition,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // set `vpToken` to base64url-no-pad-encoded device response
    const vpToken = base64url.encode(deviceResponse);

    // create authz response
    const presentationSubmission = {
      id: `urn:uuid:${crypto.randomUUID()}`,
      definition_id: presentationDefinition.id,
      descriptor_map: [{
        id: 'org.iso.18013.5.1.mDL',
        format: 'mso_mdoc',
        path: '$'
      }]
    };
    const {authorizationResponse} = await oid4vp.authzResponse.create({
      presentationSubmission,
      authorizationRequest,
      vpToken,
      encryptionOptions: {
        mdl: {
          handover
        }
      }
    });

    // parse authz response into device response
    let parsedDeviceResponse;
    {
      const {
        responseMode, parsed, protectedHeader
      } = await oid4vp.verifier.parseAuthorizationResponse({
        body: authorizationResponse,
        getDecryptParameters() {
          const keys = [kakPrivateKeyJwk];
          return {keys};
        }
      });
      expect(responseMode).to.eql('direct_post.jwt');
      expect(protectedHeader.alg).to.eql('ECDH-ES');
      expect(protectedHeader.enc).to.eql('A256GCM');
      expect(protectedHeader).to.include.keys(['kid', 'epk', 'apu', 'apv']);
      parsedDeviceResponse = base64url.decode(parsed.vpToken);
    }

    // verify presentation...

    // can currently only be tested in node.js because karma isn't mapping the
    // right version of `jose` for `@auth0/mdl`
    const isNode = globalThis.process !== undefined;
    if(isNode) {
      const result = await mdlUtils.verifyPresentation({
        deviceResponse: parsedDeviceResponse,
        handover,
        trustedCertificates: [
          issuerCertChainEntities.intermediate.pemCertificate
        ]
      });

      expect(result).to.be.an('object');
    }
  });

  // to be updated / moved to OID4VP "Annex D" / "HAIP" for JavaCards w/A128GCM
  it('should pass w/enc=A128GCM', async () => {
    // get device key pair
    const deviceKeyPair = await mdlUtils.generateDeviceKeyPair();

    // create a certificate chain that ends in the MDL issuer (leaf)
    const issuerCertChainEntities = await generateCertificateChain();

    // issue an example MDL
    const issuerPrivateJwk = issuerCertChainEntities.leaf.subject.jwk;
    const issuerCertificate = issuerCertChainEntities.leaf.pemCertificate;
    const mdoc = await mdlUtils.issue({
      issuerPrivateJwk, issuerCertificate,
      devicePublicJwk: deviceKeyPair.publicJwk
    });

    // generate example verifier identity and cert chain...

    // auto-generate `x5c` that includes public key for signing key
    const leafDnsName = 'mdl.reader.example';
    const verifierCertificateChainEntities = await generateCertificateChain({
      leafConfig: {dnsName: leafDnsName}
    });
    const x5c = [verifierCertificateChainEntities.leaf.b64Certificate];
    // trusted certs for verifying authz request from verifier, NOT for
    // verifying mDL from issuer
    const verifierCertificateChain = [
      verifierCertificateChainEntities.intermediate.pemCertificate,
      verifierCertificateChainEntities.root.pemCertificate
    ];

    // create example presentation defintion from verifier
    const presentationDefinition = {
      id: 'mdl-test-age-over-21',
      input_descriptors: [
        {
          id: 'org.iso.18013.5.1.mDL',
          format: {
            mso_mdoc: {
              alg: ['ES256']
            }
          },
          constraints: {
            limit_disclosure: 'required',
            fields: [
              {
                // eslint-disable-next-line quotes
                path: ["$['org.iso.18013.5.1']['age_over_21']"],
                intent_to_retain: false
              }
            ]
          }
        }
      ]
    };

    // create verifier key agreement pair
    const keyAgreementKeyPair = await generateKeyPair('ECDH-ES', {
      crv: 'P-256', extractable: true
    });
    const [kakPrivateKeyJwk, kakPublicKeyJwk] = await Promise.all([
      exportJWK(keyAgreementKeyPair.privateKey),
      exportJWK(keyAgreementKeyPair.publicKey)
    ]);
    kakPublicKeyJwk.use = 'enc';
    kakPublicKeyJwk.alg = 'ECDH-ES';
    kakPrivateKeyJwk.kid = kakPublicKeyJwk.kid =
      `urn:uuid:${crypto.randomUUID()}`;

    // create authorization request
    const authorizationRequest = {
      aud: 'https://self-issued.me/v2',
      client_id: 'mdl.reader.example',
      client_id_scheme: 'x509_san_dns',
      client_metadata: {
        require_signed_request_object: true,
        vp_formats: {
          mso_mdoc: {
            alg: ['ES256', 'ES384']
          }
        },
        jwks: {
          keys: [kakPublicKeyJwk]
        }
      },
      presentation_definition: presentationDefinition,
      response_mode: 'direct_post.jwt',
      response_type: 'vp_token',
      response_uri: 'https://mdl.reader.example/' +
        'workflows/1/exchanges/2/openid/clients/default/authorization/response',
      // note: not strictly 128-bits of random; should instead use 128-bits
      nonce: crypto.randomUUID()
    };

    // create signed authorization request
    const payload = {
      ...authorizationRequest
    };
    const protectedHeader = {
      typ: 'JWT',
      alg: 'ES256',
      kid: kakPublicKeyJwk.kid,
      x5c
    };
    const signer = {
      async sign({data}) {
        // verifier signs authz request
        const {keyPair} = verifierCertificateChainEntities.leaf.subject;
        const algorithm = {name: 'ECDSA', hash: {name: 'SHA-256'}};
        const signature = new Uint8Array(await crypto.subtle.sign(
          algorithm, keyPair.privateKey, data));
        return signature;
      }
    };
    const authzRequestJwt = await signJWT({payload, protectedHeader, signer});

    // get authz request JWT using oid4-client; this will also verify the JWT
    const searchParams = new URLSearchParams({
      client_id: leafDnsName,
      // expected to be `request_uri` not `request` in a deployed system
      request: authzRequestJwt
    });
    const mdocUrl = `mdoc-openid4vp://?${searchParams}`;
    const getAuthzRequestResult = await oid4vp.getAuthorizationRequest({
      url: mdocUrl, getTrustedCertificates: () => verifierCertificateChain
    });

    // ensure parsed authz request matches generated one
    expect(getAuthzRequestResult.authorizationRequest).to.deep.equal(
      authorizationRequest);

    // create an MDL handover for ISO 18013-7 Annex B
    const handover = {
      type: 'AnnexBHandover',
      // note: not strictly 128-bits of random; should instead use 128-bits
      mdocGeneratedNonce: crypto.randomUUID(),
      clientId: authorizationRequest.client_id,
      responseUri: authorizationRequest.response_uri,
      verifierGeneratedNonce: authorizationRequest.nonce
    };

    // create MDL "device response" presentation
    const deviceResponse = await mdlUtils.createDeviceResponse({
      presentationDefinition,
      mdoc,
      handover,
      devicePrivateJwk: deviceKeyPair.privateJwk
    });

    // set `vpToken` to base64url-no-pad-encoded device response
    const vpToken = base64url.encode(deviceResponse);

    // create authz response
    const presentationSubmission = {
      id: `urn:uuid:${crypto.randomUUID()}`,
      definition_id: presentationDefinition.id,
      descriptor_map: [{
        id: 'org.iso.18013.5.1.mDL',
        format: 'mso_mdoc',
        path: '$'
      }]
    };
    const {authorizationResponse} = await oid4vp.authzResponse.create({
      presentationSubmission,
      authorizationRequest,
      vpToken,
      encryptionOptions: {
        mdl: {
          handover
        },
        enc: 'A128GCM'
      }
    });

    // parse authz response into device response
    let parsedDeviceResponse;
    {
      const {
        responseMode, parsed, protectedHeader
      } = await oid4vp.verifier.parseAuthorizationResponse({
        body: authorizationResponse,
        getDecryptParameters() {
          const keys = [kakPrivateKeyJwk];
          return {keys};
        }
      });
      expect(responseMode).to.eql('direct_post.jwt');
      expect(protectedHeader.alg).to.eql('ECDH-ES');
      expect(protectedHeader.enc).to.eql('A128GCM');
      expect(protectedHeader).to.include.keys(['kid', 'epk', 'apu', 'apv']);
      parsedDeviceResponse = base64url.decode(parsed.vpToken);
    }

    // verify presentation...

    // can currently only be tested in node.js because karma isn't mapping the
    // right version of `jose` for `@auth0/mdl`
    const isNode = globalThis.process !== undefined;
    if(isNode) {
      const result = await mdlUtils.verifyPresentation({
        deviceResponse: parsedDeviceResponse,
        handover,
        trustedCertificates: [
          issuerCertChainEntities.intermediate.pemCertificate
        ]
      });

      expect(result).to.be.an('object');
    }
  });
});
