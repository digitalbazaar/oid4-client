# @digitalbazaar/oid4-client Changelog

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