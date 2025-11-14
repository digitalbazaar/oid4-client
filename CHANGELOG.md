# @digitalbazaar/oid4-client Changelog

## 5.2.0 - 2025-mm-dd

### Added
- Add support for converting `QueryByExample` to/from DCQL.

## 5.1.0 - 2025-08-31

### Added
- Add `oid4vp.verifier.parseAuthorizationResponse()` helper that OID4VP
  verifiers can use to parse authorization responses.

## 5.0.0 - 2025-08-30

### Added
- When `getVerificationKey` is not passed when getting a signed authorization
  request, if the `x5c` claim is present, automatically use the public key
  from its leaf certificate to verify the JWT. This is the expected behavior
  for `x509_san_dns` and `x509_hash` anyway. If other schemes are supported
  by the caller, they must provide `getVerificationKey` and can return the
  passed `certificatePublicKey` for those schemes and another key for other
  schemes (such as DID-based schemes, which will require a DID resolver to
  be used). The unprotected `scheme` and unprotected `authorizationRequest`
  are passed to enable checking of the scheme or other parameters that might
  be needed to make a key decision consistent with what is to be verified.
- The parameter `getTrustedCertificates({x5c, chain, authorizationRequest})`
  must be provided when getting an authorization request if any of the
  `x509_*` client ID schemes are supported by the caller. This function must
  return an array of PEM or base64-encoded certificates, each of which will
  be considered trusted, i.e., if any of these certificates is found when
  verifying a certificate chain, the verification process will halt assuming
  trust has been established, even if the trusted certificate found is not a
  root certificate.

### Removed
- **BREAKING**: Remove support for `client_metadata_uri` and
  `presentation_definition_uri` in authorization responses. These have been
  removed from the latest OID4VP specification, are considered unnecessarily
  complex, and are predicted to be very rarely used.

## 4.4.0 - 2025-08-25

### Added
- Add OID4VP encrypted authz response implementation.
- Add OID4VP signed authz request verification. When getting an
  authorization request, a (optionally async)
  `getVerificationKey({protectedHeader})` function must be provided
  as an option in order to provide key material for verification. If
  not provided when a signed authz request is required based on the
  client ID scheme/prefix or client metadata, then a `NotFoundError`
  will be thrown during JWT verification.
- Add support for OID4VP `direct_post.jwt` response mode.
- Add `selectJwk()` utility.
- Expose authz request, authz response, and convert utilities via
  `oid4vp.authzRequest.*`, `oid4vp.authzResponse.*`, and
  `oid4vp.convert.*` respectively. Future releases may make these more
  easily importable as individual symbols w/tree-shaking support.

### Changed
- Update dependencies.

## 4.3.0 - 2024-11-10

### Added
- Add `getNonce` to client API for use with OID4VCI `nonce_endpoint`.
- Add option to pass `nonce` to `requestCredential(s)`.

## 4.2.0 - 2024-10-15

### Changed
- Update dependencies.

## 4.1.0 - 2024-10-01

### Added
- Auto-detect whether to include `vc` in the JSON paths when
  computing presentation definition constraints from a VPR.

### Fixed
- Ensure duplicate paths aren't used when generating a VPR from a presentation
  definition.

## 4.0.0 - 2024-09-20

### Changed
- **BREAKING**: Use `allOf` instead of an invalid `contains` with an
  array value when generating presentation filters from a VPR.

## 3.8.0 - 2024-09-20

### Added
- Accept `allOf` in combination with `contains` for array schemas.

## 3.7.0 - 2024-08-22

### Added
- Add support for fetching credential offer from `credential_offer_uri` via
  `getCredentialOffer()`.
- Improve automatic credential definition selection from a credential offer
  based on the specified `format`.

## 3.6.0 - 2024-08-22

### Added
- Add support for issuer configuration URLs that do not match RFC 8414,
  but instead match the OID4VCI spec, i.e., `<issuer>/.well-known/...` will
  be accepted and not just `<issuer origin>/.well-known/.../<issuer path>`.
- Add support for parsing and using credential offers with `credentials`
  or `credential_configuration_ids` that include credential configuration
  IDs that are present in the issuer configuration.

## 3.5.0 - 2024-08-08

### Added
- Allow `vpToken` param to be given when sending an authorization response.
  This param is optional and does not replace the `verifiablePresentation`
  parameter which is required to build the presentation submission. The
  `vpToken` param can be used if the format of the `vp_token` is not
  the plain JSON expression of the `verifiablePresentation`, but is instead
  some enveloping format that wraps the VP, such as a JWT (as in VC-JWT).

## 3.4.1 - 2024-07-29

### Fixed
- Ensure `presentation_required` error is properly nested.

## 3.4.0 - 2024-07-15

### Added
- Allow `format` to be passed when requesting credentials.

### Changed
- Allow any `format` to be used in credential requests.

## 3.3.0 - 2024-01-24

### Changed
- Update `@digitalbazaar/http-client` to 4.0.0.

## 3.2.0 - 2023-11-30

### Changed
- Add `prefixJwtVcPath` option to add an additional JSON path that includes
  the JWT W3C VC 1.1 'vc' prefix to presentation definition constraints fields.

## 3.1.0 - 2023-10-25

### Added
- Add basic OID4VP support. There are many differences in OID4VP
  implementations in the ecosystem today and OID4VP is still in
  draft form. This implementation supports a profile of draft 20
  that uses LDP / Data Integrity secured VCs and provides utility
  functions for converting a subset of VPRs to authorization
  requests and vice versa. This OID4VP implementation should be
  considered experimental as the ecosystem matures and changes
  are made.

## 3.0.1 - 2023-08-09

### Fixed
- Ensure authorization server metadata is retrieved along with credential
  issuer metadata. This information is combined to create the `issuerConfig`
  stored in the client. The client also stores `metadata` with the original
  metadata from each to allow differentiation as needed. A future version may
  remove `issuerConfig` to avoid any conflation that was the result of previous
  versions of the OID4VCI spec and implementations built off of this client.

## 3.0.0 - 2023-08-09

### Changed
- **BREAKING**: The client now uses `.well-known/openid-credential-issuer`
  instead of `.well-known/oauth-authorization-server` to match the
  current version of the OID4VCI spec as of this date.

## 2.0.0 - 2023-06-01

### Added
- Initial release, see individual commits for history. Notably,
  no version 1.x was released under this name, instead it was
  released as `@digitalbazaar/oidc4vci-client`.
