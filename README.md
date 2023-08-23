# OID4Client Library _(@digitalbazaar/oid4-client)_

[![NPM Version](https://img.shields.io/npm/v/@digitalbazaar/oid4-client.svg)](https://npm.im/@digitalbazaar/oid4-client)

A Javascript library for working with the OpenID 4 Verifiable Credential
Issuance (OID4VCI) protocol, offering functionality for requesting Verifiable
Credentials.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Testing](#testing)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

This library is a Javascript (Node.js and browser) implementation of the
[OID4VCI v11](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
Protocol.

It allows you to perform the following operations:

1. Request a credential to be issued given a OID4VCI credential offer.
2. Request multiple credentials to be issued given a OID4VCI credential offer.
3. Authenticate using a DID if the offer requires it.

## Install

```bash
npm install @digitalbazaar/oid4-client
```

## Usage

### Importing the Library

```javascript
import { OID4Client } from "@digitalbazaar/oid4-client";
```

### Constructor

The `OID4Client` can be instantiated using the following parameters:

- `accessToken` (Optional)
- `issuerConfig`
- `metadata`
- `offer`

Example:

```javascript
const client = new OID4Client({
  accessToken: "YOUR_ACCESS_TOKEN",
  issuerConfig: "YOUR_ISSUER_CONFIG",
  metadata: "YOUR_METADATA",
  offer: "YOUR_OFFER",
});
```

### Creating a Client from a Credential Offer

```javascript
const clientFromOffer = await OID4Client.fromCredentialOffer({
  offer: "YOUR_CREDENTIAL_OFFER",
});
```

### Requesting a Credential

To request a single credential:

```javascript
const credential = await client.requestCredential({
  credentialDefinition: "YOUR_CREDENTIAL_DEFINITION",
  did: "YOUR_DID",
  didProofSigner: "YOUR_DID_PROOF_SIGNER",
});
```

To request multiple credentials:

```javascript
const credentials = await client.requestCredentials({
  requests: "YOUR_REQUESTS",
  did: "YOUR_DID",
  didProofSigner: "YOUR_DID_PROOF_SIGNER",
});
```

## Testing

To run tests:

```
npm run test
```

## Contribute

See
[the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

Note: If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from Digital
Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar
