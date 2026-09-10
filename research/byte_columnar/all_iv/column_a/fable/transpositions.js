'use strict';
/*
 * Transposition inverse-mapping builders. Everything here works on the
 * character-level hex string (1092 chars), per the task's own permutation
 * counts (widths 2-9 sum to ~409k, matching 2!+...+9!). Each builder
 * returns dstOfSrc: an array such that plaintext[i] = ciphertext[dstOfSrc[i]],
 * i.e. dstOfSrc encodes the FORWARD (encrypt-time) index mapping; applying
 * it as a gather on the ciphertext recovers the pre-transposition string.
 */

// Column lengths for a ragged n-char rectangle of width w.
// convention 'first': the first (n % w) columns (natural left-to-right
//   order) get the extra row -- the standard "fill rows left-to-right"
//   ragged columnar convention.
// convention 'last': the LAST (n % w) natural columns get the extra row --
//   models a plaintext padded to a full rectangle and then having the pad
//   characters stripped from the trailing columns.
function columnLengths(n, w, convention) {
  const rows = Math.ceil(n / w);
  const rem = n % w; // number of "long" columns (rows chars); rest have rows-1
  const lengths = new Array(w);
  if (rem === 0) {
    for (let c = 0; c < w; c++) lengths[c] = rows;
    return lengths;
  }
  if (convention === 'last') {
    for (let c = 0; c < w; c++) lengths[c] = (c >= w - rem) ? rows : rows - 1;
  } else {
    for (let c = 0; c < w; c++) lengths[c] = (c < rem) ? rows : rows - 1;
  }
  return lengths;
}

/*
 * Row-major cell numbering for a ragged w-column rectangle: scans (r, c)
 * in row-major order and assigns original-string indices 0..n-1 only to
 * VALID cells (r < lengths[c]). This is needed (rather than the naive
 * i = r*w + c) because with the 'last' convention the incomplete final
 * row's valid columns are the high-indexed ones, not 0..rem-1, so the
 * cell-to-index correspondence for that row is not r*w + c.
 */
function buildCellIndex(n, w, convention) {
  const lengths = columnLengths(n, w, convention);
  const rows = Math.max(...lengths);
  const cellIndex = []; // rows x w, cellIndex[r][c] = original index i, or -1
  let i = 0;
  for (let r = 0; r < rows; r++) {
    const row = new Array(w).fill(-1);
    for (let c = 0; c < w; c++) {
      if (r < lengths[c]) row[c] = i++;
    }
    cellIndex.push(row);
  }
  return { cellIndex, lengths, rows };
}

/*
 * Variant A ("standard columnar"): plaintext written row-major into the
 * matrix, ciphertext read column-major with columns visited in `order`
 * (order[k] = which natural column is k-th to be read).
 */
function columnarA(n, w, order, convention) {
  const { cellIndex, lengths, rows } = buildCellIndex(n, w, convention);
  const colStart = new Array(w);
  let off = 0;
  for (let k = 0; k < w; k++) {
    const c = order[k];
    colStart[c] = off;
    off += lengths[c];
  }
  const dstOfSrc = new Array(n);
  for (let c = 0; c < w; c++) {
    let r2 = 0;
    for (let r = 0; r < rows; r++) {
      const i = cellIndex[r][c];
      if (i !== -1) dstOfSrc[i] = colStart[c] + r2++;
    }
  }
  return dstOfSrc;
}

/*
 * Variant B ("row-wise readout" / dual route): plaintext written
 * column-major (columns visited in natural order 0..w-1, contiguous chunks
 * of length lengths[c]), ciphertext read row-major but visiting columns
 * within each row in `order`.
 */
function columnarB(n, w, order, convention) {
  const lengths = columnLengths(n, w, convention);
  const colOffset = new Array(w); // start index (in original string) of column c
  {
    let off = 0;
    for (let c = 0; c < w; c++) { colOffset[c] = off; off += lengths[c]; }
  }
  const rows = Math.ceil(n / w);
  const dstOfSrc = new Array(n);
  let pos = 0;
  for (let r = 0; r < rows; r++) {
    for (let k = 0; k < w; k++) {
      const c = order[k];
      if (r < lengths[c]) {
        const i = colOffset[c] + r;
        dstOfSrc[i] = pos++;
      }
    }
  }
  return dstOfSrc;
}

// Apply dstOfSrc as a gather: candidate[i] = ciphertext[dstOfSrc[i]].
function applyInverse(ciphertext, dstOfSrc) {
  const n = dstOfSrc.length;
  let out = Buffer.allocUnsafe(n);
  for (let i = 0; i < n; i++) out[i] = ciphertext.charCodeAt(dstOfSrc[i]);
  return out.toString('latin1');
}

/* ---------------- Rail fence ---------------- */
// Encrypt: write plaintext in a zig-zag across `rails` rows starting at
// `offset` (0 = start going down), read off row by row. dstOfSrc[i] =
// position of original char i within the concatenated row-major ciphertext.
function railFence(n, rails, offset, startDir) {
  const rowOf = new Array(n);
  let r = offset % rails, dir = startDir || 1;
  // Simulate the same zig-zag libraries use: rows cycle 0..rails-1..0..
  // offset shifts the starting row, startDir (+1/-1) the initial direction.
  for (let i = 0; i < n; i++) {
    rowOf[i] = r;
    if (rails > 1) {
      if (r === 0) dir = 1;
      else if (r === rails - 1) dir = -1;
      r += dir;
    }
  }
  const rowStart = new Array(rails).fill(0);
  const rowLen = new Array(rails).fill(0);
  for (let i = 0; i < n; i++) rowLen[rowOf[i]]++;
  let off = 0;
  for (let rr = 0; rr < rails; rr++) { rowStart[rr] = off; off += rowLen[rr]; }
  const cursor = rowStart.slice();
  const dstOfSrc = new Array(n);
  for (let i = 0; i < n; i++) dstOfSrc[i] = cursor[rowOf[i]]++;
  return dstOfSrc;
}

/* ---------------- AMSCO ---------------- */
// Numeric-key AMSCO with alternating 1-2 or 2-1 character group pattern,
// re-verification per spec item 5 (solver already tried this, cheap to redo).
function amscoGroups(n, keyLen, startPattern) {
  // Build the sequence of group sizes 1,2,1,2,... or 2,1,2,1,... covering n chars,
  // arranged in keyLen columns row-major (each "row" assigns keyLen consecutive
  // groups, one per column), then columns are read out in key numeric order.
  const groups = [];
  let sizeToggle = startPattern === '21' ? 2 : 1;
  let pos = 0;
  while (pos < n) {
    const sz = Math.min(sizeToggle, n - pos);
    groups.push({ start: pos, len: sz });
    pos += sz;
    sizeToggle = sizeToggle === 1 ? 2 : 1;
  }
  return groups;
}

function amsco(n, order, startPattern) {
  const keyLen = order.length;
  const groups = amscoGroups(n, keyLen, startPattern);
  // assign groups to matrix cells row-major (col = index % keyLen)
  const colGroups = Array.from({ length: keyLen }, () => []);
  groups.forEach((g, idx) => colGroups[idx % keyLen].push(g));
  // ciphertext = concat columns in `order`, each column's groups in row order,
  // each group's chars in original order.
  const dstOfSrc = new Array(n);
  let pos = 0;
  for (let k = 0; k < keyLen; k++) {
    const c = order[k];
    for (const g of colGroups[c]) {
      for (let j = 0; j < g.len; j++) dstOfSrc[g.start + j] = pos++;
    }
  }
  return dstOfSrc;
}

/* ---------------- Route transposition ---------------- */
// Write row-major into w columns, read out column-major in natural order
// (no key permutation) -- and its reverse (write column-major, read
// row-major). These are columnarA/columnarB with the identity order, but
// kept as named entry points for clarity/reporting.
function routeColumnwise(n, w, convention) {
  const order = Array.from({ length: w }, (_, i) => i);
  return columnarA(n, w, order, convention);
}
function routeRowwise(n, w, convention) {
  const order = Array.from({ length: w }, (_, i) => i);
  return columnarB(n, w, order, convention);
}

/* ---------------- Permutation generation (Heap's algorithm, generator) ---------------- */
function* permutations(arr) {
  const n = arr.length;
  const a = arr.slice();
  const c = new Array(n).fill(0);
  yield a.slice();
  let i = 0;
  while (i < n) {
    if (c[i] < i) {
      const j = (i % 2 === 0) ? 0 : c[i];
      [a[i], a[j]] = [a[j], a[i]];
      yield a.slice();
      c[i]++;
      i = 0;
    } else {
      c[i] = 0;
      i++;
    }
  }
}

// nth permutation of [0..w-1] in Lehmer-code (factorial number system) order,
// used to shard the permutation space across workers without materializing it.
function nthPermutation(w, n) {
  const items = Array.from({ length: w }, (_, i) => i);
  const result = [];
  let idx = n;
  for (let k = w; k >= 1; k--) {
    const f = factorial(k - 1);
    const sel = Math.floor(idx / f);
    idx = idx % f;
    result.push(items[sel]);
    items.splice(sel, 1);
  }
  return result;
}

const FACT_CACHE = [1];
function factorial(k) {
  while (FACT_CACHE.length <= k) FACT_CACHE.push(FACT_CACHE[FACT_CACHE.length - 1] * FACT_CACHE.length);
  return FACT_CACHE[k];
}

/* ---------------- Keyword -> numeric order ---------------- */
// Standard keyword columnar ranking: letters ranked alphabetically,
// left-to-right tie-break for repeats. order[k] = natural column read at
// step k (0-indexed rank).
function keywordOrder(keyword) {
  const letters = keyword.toUpperCase().split('');
  const idx = letters.map((ch, i) => ({ ch, i }));
  idx.sort((a, b) => (a.ch < b.ch ? -1 : a.ch > b.ch ? 1 : a.i - b.i));
  const order = new Array(letters.length);
  idx.forEach((e, rank) => { order[rank] = e.i; });
  return order;
}

// Myszkowski variant: equal letters share the same rank; columns with tied
// letters are read left-to-right together (as one merged group) in the
// pass for that rank. We approximate this at the dstOfSrc level by
// building a custom columnarA-like mapping where tied columns interleave.
function myszkowskiOrderGroups(keyword) {
  const letters = keyword.toUpperCase().split('');
  const uniqueSorted = Array.from(new Set(letters)).sort();
  // groups: array of arrays of natural column indices, in rank order
  return uniqueSorted.map(ch => letters.reduce((acc, c, i) => (c === ch ? (acc.push(i), acc) : acc), []));
}

// Myszkowski always uses the 'first' ragged convention (standard columnar
// fill); using cellIndex (not the naive r*w+c formula) keeps it correct.
function myszkowskiA(n, w, groups) {
  const { cellIndex, lengths, rows } = buildCellIndex(n, w, 'first');
  const dstOfSrc = new Array(n);
  let pos = 0;
  for (const group of groups) {
    const maxLen = Math.max(...group.map(c => lengths[c]));
    for (let r = 0; r < maxLen; r++) {
      for (const c of group) {
        if (r < lengths[c]) {
          const i = cellIndex[r][c];
          if (i !== -1) dstOfSrc[i] = pos++;
        }
      }
    }
  }
  return dstOfSrc;
}

module.exports = {
  columnLengths, buildCellIndex, columnarA, columnarB, applyInverse, railFence, amsco, amscoGroups,
  routeColumnwise, routeRowwise, permutations, nthPermutation, factorial,
  keywordOrder, myszkowskiOrderGroups, myszkowskiA,
};
