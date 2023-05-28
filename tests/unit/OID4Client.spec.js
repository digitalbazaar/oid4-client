/*!
 * Copyright (c) 2022-2023 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import {OID4Client} from '../../lib/index.js';

chai.should();
const {expect} = chai;

describe('OID4Client', () => {
  describe('constructor', () => {
    it('should create an OID4Client', async () => {
      const client = new OID4Client({});
      expect(client).to.exist;
    });
  });
});
