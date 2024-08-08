# @digitalbazaar/oid4-client Changelog

## 3.5.0 - 2024-08-dd

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
