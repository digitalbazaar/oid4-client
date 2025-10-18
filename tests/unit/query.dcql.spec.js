/*!
 * Copyright (c) 2025 Digital Bazaar, Inc. All rights reserved.
 */
import {
  _fromQueryByExampleQuery
} from '../../lib/query/dcql.js';
import chai from 'chai';

chai.should();
const {expect} = chai;

describe('query.dcql', () => {
  describe('QueryByExample => DCQL', () => {
    it('should pass', async () => {
      const result = _fromQueryByExampleQuery({});
      expect(result).to.exist;
    });
  });
});
