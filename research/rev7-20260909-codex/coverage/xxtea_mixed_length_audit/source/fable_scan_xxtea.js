'use strict';
/* Gap 1: XXTEA scan over trims x orientations x keys x {pecl, raw} variants. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ivf = require(path.join(__dirname, '..', 'ivframe', 'lib.js'));
const { xxteaPeclDecrypt, xxteaRawDecrypt, xxteaPeclEncrypt } = require('./xxtea.js');

const REV7_DIR = path.join(__dirname, '..');
const HEX = ivf.readHexFile(path.join(REV7_DIR, 'rev7_hex.txt'));

function isPrintable(b) { return b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126); }
function printableFraction(buf) {
  if (buf.length === 0) return 1;
  let ok = 0;
  for (let i = 0; i < buf.length; i++) if (isPrintable(buf[i])) ok++;
  return ok / buf.length;
}
function hexFraction(buf) {
  let ok = 0;
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    const isHex = (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
    if (isHex) ok++;
  }
  return buf.length ? ok / buf.length : 0;
}
const B64_RE = /^[A-Za-z0-9+/=]$/;
function b64Fraction(buf) {
  let ok = 0;
  for (let i = 0; i < buf.length; i++) if (B64_RE.test(String.fromCharCode(buf[i]))) ok++;
  return buf.length ? ok / buf.length : 0;
}

/* Build (dFront,dBack) even-count trims with dFront+dBack<=12, keeping
 * only decoded lengths that are multiples of 4 bytes. */
function buildTrims4(hexStr) {
  const out = [];
  for (let dFront = 0; dFront <= 12; dFront += 2) {
    for (let dBack = 0; dFront + dBack <= 12; dBack += 2) {
      const s = hexStr.slice(dFront, hexStr.length - dBack);
      if (s.length % 8 !== 0) continue; // hex chars -> bytes%4==0 means hexlen%8==0
      out.push({ dFront, dBack, buf: Buffer.from(s, 'hex') });
    }
  }
  return out;
}

const trims = buildTrims4(HEX);

function orientationsOf(buf) {
  return ivf.orientationsFromNormal(buf);
}

function loadKeys() {
  const lore = ivf.readKeyFile(path.join(REV7_DIR, 'dictkey', 'keys_lore.txt'));
  const artifacts = ivf.readKeyFile(path.join(REV7_DIR, 'dictkey', 'keys_artifacts.txt'));
  return { lore, artifacts };
}

function runScan(keys, label, opts) {
  const variants = [
    { name: 'pecl', fn: xxteaPeclDecrypt },
    { name: 'raw', fn: xxteaRawDecrypt },
  ];
  let jobs = 0;
  let bestPrintable = {};
  const survivors = [];
  const t0 = Date.now();
  for (const trim of trims) {
    const orients = orientationsOf(trim.buf);
    for (const orient of orients) {
      for (const key of keys) {
        const keyBytes = Buffer.from(key, 'ascii');
        for (const v of variants) {
          jobs++;
          let out;
          try { out = v.fn(orient.buf, keyBytes); } catch (e) { out = null; }
          if (!out || out.length === 0) continue;
          const pf = printableFraction(out);
          if (!bestPrintable[v.name] || pf > bestPrintable[v.name].pf) {
            bestPrintable[v.name] = { pf, key, orient: orient.name, dFront: trim.dFront, dBack: trim.dBack, sample: out.subarray(0, 80).toString('latin1') };
          }
          if (pf >= 0.90) {
            survivors.push({
              scan: 'xxtea', variant: v.name, key, orientation: orient.name,
              dFront: trim.dFront, dBack: trim.dBack, printableFraction: pf,
              hexFraction: hexFraction(out), b64Fraction: b64Fraction(out),
              length: out.length, text: out.toString('latin1'),
            });
          }
        }
      }
    }
  }
  const dt = Date.now() - t0;
  return { jobs, dt, bestPrintable, survivors, label, trimCount: trims.length };
}

function main() {
  const { lore, artifacts } = loadKeys();
  const keysLA = Array.from(new Set([...lore, ...artifacts]));

  // ---- Control: encrypt 544-byte English text with pecl xxtea, key
  // "Kronorium", hex, prepend 4 junk hex symbols, confirm recovery.
  const englishText = ('The Revelations of Nikolai and the Rezurrection lie hidden within the walls of the Giant, beyond the ' +
    'reach of the living, where the Keeper watches over ash and bone, waiting for a signal from beyond the veil that ' +
    'never truly departs from this cursed world we call our own and always will remain forever more amen ')
    .slice(0, 544);
  const ptBuf = Buffer.from(englishText, 'ascii');
  const ctBuf = xxteaPeclEncrypt(ptBuf, Buffer.from('Kronorium', 'ascii'));
  let ctHex = ctBuf.toString('hex');
  ctHex = 'dead' + ctHex; // 4 junk hex symbols prepended
  const controlTrims = buildTrims4(ctHex);
  let controlHit = null;
  for (const trim of controlTrims) {
    if (trim.dFront !== 4) continue; // should strip exactly the 4 junk symbols
    const orients = orientationsOf(trim.buf);
    const normalOrient = orients.find((o) => o.name === 'normal');
    const out = xxteaPeclDecrypt(normalOrient.buf, Buffer.from('Kronorium', 'ascii'));
    if (out && out.equals(ptBuf)) { controlHit = { dFront: trim.dFront, dBack: trim.dBack }; break; }
  }

  // ---- Negative control: random 546 bytes over lore+artifacts keys.
  const rnd = crypto.randomBytes(546).toString('hex');
  const negTrims = buildTrims4(rnd);
  let negFalsePos = 0;
  let negBest = 0;
  for (const trim of negTrims) {
    const orients = orientationsOf(trim.buf);
    for (const orient of orients) {
      for (const key of keysLA) {
        const keyBytes = Buffer.from(key, 'ascii');
        for (const fn of [xxteaPeclDecrypt, xxteaRawDecrypt]) {
          const out = fn(orient.buf, keyBytes);
          if (!out || out.length === 0) continue;
          const pf = printableFraction(out);
          if (pf > negBest) negBest = pf;
          if (pf >= 0.90) negFalsePos++;
        }
      }
    }
  }

  console.log('trim count (mod-4 filtered):', trims.length);
  console.log('control (pecl, +4 junk hex):', controlHit ? 'RECOVERED at dFront=' + controlHit.dFront : 'NOT RECOVERED');

  const resLA = runScan(keysLA, 'lore+artifacts', {});
  console.log('lore+artifacts jobs:', resLA.jobs, 'time(ms):', resLA.dt);
  console.log('best printable (lore+artifacts):', JSON.stringify(resLA.bestPrintable));
  console.log('negative control: false positives =', negFalsePos, 'best printable seen =', negBest);

  const results = {
    gap: 'xxtea',
    trimCount: trims.length,
    control: { recovered: !!controlHit, detail: controlHit },
    negativeControl: { falsePositives: negFalsePos, bestPrintableSeen: negBest, keysTested: keysLA.length },
    loreArtifacts: {
      keysTested: keysLA.length,
      jobs: resLA.jobs,
      timeMs: resLA.dt,
      bestPrintable: resLA.bestPrintable,
      survivorCount: resLA.survivors.length,
    },
  };
  fs.writeFileSync(path.join(__dirname, 'results_xxtea.json'), JSON.stringify(results, null, 2));

  let allSurvivors = resLA.survivors;

  // If time/throughput allows, run full dict.
  const throughputPerSec = resLA.jobs / (resLA.dt / 1000);
  console.log('throughput (jobs/sec):', throughputPerSec.toFixed(0));
  const dictPath = path.join(REV7_DIR, 'dictkey', 'keys_dict.txt');
  const dictKeys = ivf.readKeyFile(dictPath);
  const estSeconds = (dictKeys.length / keysLA.length) * (resLA.dt / 1000);
  console.log('estimated full-dict time (s):', estSeconds.toFixed(1), 'for', dictKeys.length, 'keys');
  results.fullDictEstimateSeconds = estSeconds;
  results.fullDictKeyCount = dictKeys.length;

  let dictRan = false;
  if (estSeconds < 400) {
    const resDict = runScan(dictKeys, 'full-dict', {});
    console.log('full-dict jobs:', resDict.jobs, 'time(ms):', resDict.dt);
    console.log('best printable (full-dict):', JSON.stringify(resDict.bestPrintable));
    allSurvivors = allSurvivors.concat(resDict.survivors);
    results.fullDict = {
      keysTested: dictKeys.length, jobs: resDict.jobs, timeMs: resDict.dt,
      bestPrintable: resDict.bestPrintable, survivorCount: resDict.survivors.length,
    };
    dictRan = true;
  }
  results.fullDictRan = dictRan;

  fs.writeFileSync(path.join(__dirname, 'results_xxtea.json'), JSON.stringify(results, null, 2));
  fs.writeFileSync(path.join(__dirname, 'survivors_xxtea.json'), JSON.stringify(allSurvivors, null, 2));
  console.log('survivors (>=90% printable):', allSurvivors.length);
}

main();
