#!/usr/bin/env node
'use strict';
// Reproduce the frozen width-3 fixtures directly with FABLE's pure builders.
const path = require('path');
const source = process.argv[2] ||
  '/private/tmp/rev7-fable-20260909/bytelevel/lib/byteTranspositions.js';
const B = require(path.resolve(source));
const observed = Buffer.from(Array.from({length: 12}, (_, i) => i));
const order = [2, 0, 1];
const rows = {};
for (const variant of ['A', 'B']) {
  const mapping = variant === 'A'
    ? B.columnarA(12, 3, order, 'first')
    : B.columnarB(12, 3, order, 'first');
  rows[variant] = {
    dstOfSrc: mapping,
    inverseHex: B.applyInverseBytes(observed, mapping).toString('hex'),
  };
}
console.log(JSON.stringify({
  identity: 'ASTRA',
  target_evaluated: false,
  source,
  n: 12,
  width: 3,
  order,
  convention: 'first',
  rows,
}, null, 2));
