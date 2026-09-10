'use strict';
const fs = require('fs');
const path = require('path');
const C = require('../cascade/cascade_lib.js');
const S3 = require('./scan3.js');

function readHex(p) { return fs.readFileSync(p, 'utf8').trim().replace(/\s+/g, '').toUpperCase(); }

const TOPK = 25;

/* Bounded top-K tracker: only materializes path arrays for candidates that
 * actually make the cut, to keep per-leaf overhead near-zero for the
 * ~6.2M x N-datasets leaves that don't. */
function makeTopKTracker(k) {
  const arr = []; // ascending by (longestRun, validCount); arr[0] is worst kept
  function worse(a, b) { return a.longestRun < b.longestRun || (a.longestRun === b.longestRun && a.validCount < b.validCount); }
  return {
    maybeAdd(sc, orientation, b0, l1, b1, l2, b2, l3, b3) {
      if (arr.length < k || worse(arr[0], sc)) {
        const entry = { orientation, path: S3.pathFromFlags(b0, l1, b1, l2, b2, l3, b3), longestRun: sc.longestRun, validCount: sc.validCount, tailLen: sc.tailLen };
        arr.push(entry);
        arr.sort((a, b) => (a.longestRun - b.longestRun) || (a.validCount - b.validCount));
        if (arr.length > k) arr.shift();
      }
    },
    top() { return arr.slice().reverse(); },
  };
}

function makeHistogram() {
  const byLongestRun = {};
  const byValidCountBucket20 = {};
  let n = 0;
  return {
    add(sc) {
      n++;
      byLongestRun[sc.longestRun] = (byLongestRun[sc.longestRun] || 0) + 1;
      const bucket = Math.floor(sc.validCount / 20) * 20;
      byValidCountBucket20[bucket] = (byValidCountBucket20[bucket] || 0) + 1;
    },
    result() { return { n, byLongestRun, byValidCountBucket20 }; },
  };
}

/* Runs the full exhaustive sweep over `orientationsToRun` orientations of
 * hexStrRaw, feeding every leaf into topK + histogram, and (if targetChain
 * given) tracking its exact rank via a running better/equal/worse counter
 * -- without ever storing the full 6.2M-entry result set in memory. */
function runFullSweep(ctx, hexStrRaw, orientationNames, targetChain) {
  const orientations = C.orientations(hexStrRaw);
  const topK = makeTopKTracker(TOPK);
  const hist = makeHistogram();
  let totalCount = 0;
  const perOrientation = {};
  let targetScore = null, targetSeen = false, betterCount = 0, equalCount = 0;
  const targetKey = targetChain ? targetChain.join(',') : null;

  for (const name of orientationNames) {
    const hexStr = orientations[name];
    const t0 = Date.now();
    let cnt = 0;
    const onLeaf = (sc, b0, l1, b1, l2, b2, l3, b3) => {
      cnt++;
      topK.maybeAdd(sc, name, b0, l1, b1, l2, b2, l3, b3);
      hist.add(sc);
      if (targetKey) {
        const p = S3.pathFromFlags(b0, l1, b1, l2, b2, l3, b3);
        if (p.join(',') === targetKey) {
          targetScore = { longestRun: sc.longestRun, validCount: sc.validCount, tailLen: sc.tailLen, orientation: name };
          targetSeen = true;
        }
      }
    };
    cnt = S3.scanDepth3FullExhaustive(ctx, hexStr, onLeaf);
    perOrientation[name] = { elapsedMs: Date.now() - t0, count: cnt };
    totalCount += cnt;
  }

  // second pass to get exact rank of target (cheap re-scan is wasteful at
  // this scale; instead recompute better/equal counts by re-running once
  // more only if a target was requested, reusing the same memoized nesting)
  if (targetKey && targetSeen) {
    for (const name of orientationNames) {
      const hexStr = orientations[name];
      S3.scanDepth3FullExhaustive(ctx, hexStr, (sc) => {
        if (sc.longestRun > targetScore.longestRun || (sc.longestRun === targetScore.longestRun && sc.validCount > targetScore.validCount)) betterCount++;
        else if (sc.longestRun === targetScore.longestRun && sc.validCount === targetScore.validCount) equalCount++;
      });
    }
  }

  return {
    totalCount, perOrientation, topK: topK.top(), histogram: hist.result(),
    target: targetKey ? { chain: targetChain, found: targetSeen, score: targetScore, rank: targetSeen ? betterCount + 1 : null, tieCount: targetSeen ? equalCount : null, totalRanked: totalCount } : null,
  };
}

async function main() {
  const mode = process.argv[2] || 'full';
  const ctx = await C.loadMcrypt();
  const ALL_OR = ['displayed', 'fullReversed', 'bytePairReversed', 'nibbleSwap'];
  const out = { generatedAt: new Date().toISOString(), mode, searchSpace: {
    layerOptionsPerLayer: S3.LAYER_OPTS.length,
    totalChainsSpec: 4 * 46 * 46 * 46 * 16,
  } };

  if (mode === 'probe') {
    const rev7HexRaw = readHex(path.join(__dirname, '..', 'rev7_hex.txt'));
    const t0 = Date.now();
    const res = runFullSweep(ctx, rev7HexRaw, ['displayed'], null);
    const elapsed = Date.now() - t0;
    out.probe = { elapsedMs: elapsed, chainsRun: res.totalCount, throughputPerSec: res.totalCount / (elapsed / 1000), topK: res.topK.slice(0, 10) };
    fs.writeFileSync(path.join(__dirname, 'probe_results.json'), JSON.stringify(out, null, 2));
    console.log(JSON.stringify(out.probe, null, 2));
    return;
  }

  // ============ POSITIVE CONTROL (single orientation, matches ../cascade convention) ============
  {
    const hex = readHex(path.join(__dirname, 'plant3_hex.txt'));
    const trueChain = ['decrypt:serpent:Zombies', 'reverse', 'decrypt:blowfish:Zombies', 'decrypt:twofish:Zombies'];
    const t0 = Date.now();
    const res = runFullSweep(ctx, hex, ['displayed'], trueChain);
    out.positiveControl = { elapsedMs: Date.now() - t0, chainsScored: res.totalCount, target: res.target, top5: res.topK.slice(0, 5) };
    console.error('positive control done: rank=' + JSON.stringify(res.target && res.target.rank));
  }

  // ============ NEGATIVE CONTROL (all 4 orientations, reuse ../cascade seed) ============
  let negRes;
  {
    const hex = readHex(path.join(__dirname, '..', 'cascade', 'negative_seed_hex.txt'));
    const t0 = Date.now();
    negRes = runFullSweep(ctx, hex, ALL_OR, null);
    out.negativeControl = { elapsedMs: Date.now() - t0, chainsScored: negRes.totalCount, perOrientation: negRes.perOrientation, top10: negRes.topK.slice(0, 10), histogram: negRes.histogram };
    console.error('negative control done: chainsScored=' + negRes.totalCount + ' elapsedMs=' + (Date.now() - t0));
  }

  // ============ REV7 (all 4 orientations, exhaustive) ============
  let rev7Res;
  {
    const rev7HexRaw = readHex(path.join(__dirname, '..', 'rev7_hex.txt'));
    const t0 = Date.now();
    rev7Res = runFullSweep(ctx, rev7HexRaw, ALL_OR, null);
    out.rev7 = { elapsedMs: Date.now() - t0, chainsScored: rev7Res.totalCount, perOrientation: rev7Res.perOrientation, top10: rev7Res.topK.slice(0, 10), histogram: rev7Res.histogram };
    console.error('rev7 done: chainsScored=' + rev7Res.totalCount + ' elapsedMs=' + (Date.now() - t0));
  }

  out.comparison = {
    rev7Best: rev7Res.topK[0], negativeBest: negRes.topK[0],
    insideNullBand: rev7Res.topK[0].longestRun <= negRes.topK[0].longestRun,
  };

  fs.writeFileSync(path.join(__dirname, 'results.json'), JSON.stringify(out, null, 2));
  console.error('wrote results.json');
}

main().catch((e) => { console.error(e); process.exit(1); });
