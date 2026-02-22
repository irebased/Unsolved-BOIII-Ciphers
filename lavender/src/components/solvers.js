const BASE = '/Unsolved-BOIII-Ciphers/ciphers';

// Map a cipher entry to its URL path (matches existing MDX file structure)
export function cipherToPath(cipher) {
    const { id, map, number } = cipher;
    const comicMatch = map.match(/^comic_issue(\d+)$/);
    if (comicMatch) return `${BASE}/comics/issue${comicMatch[1]}/cipher${number}`;

    switch (map) {
        case 'revelations':     return `${BASE}/bo3/rev/rev${number}`;
        case 'gorod_krovi':     return `${BASE}/bo3/gk/gk${number}`;
        case 'the_giant':       return `${BASE}/bo3/tg/tg${number}`;
        case 'soe':             return `${BASE}/bo3/soe/soe${number}`;
        case 'der_eisendrache': return `${BASE}/bo3/de/de${number}`;
        case 'zetsubou':        return `${BASE}/bo3/zns/zns${number}`;
        case 'tranzit':         return `${BASE}/bo2/tranzit/tranzit${number}`;
        case 'motd':            return `${BASE}/bo2/motd/mob${number}`;
        case 'origins':         return `${BASE}/bo2/origins/origins${number}`;
        case 'verruckt':        return `${BASE}/waw/verruckt/verruckt${number}`;
        case 'derriese':        return `${BASE}/waw/derriese/derriese${number}`;
        case 'waw_general':     return `${BASE}/waw/general/${id === 'waw_bios' ? 'bios' : id}`;
        case 'ae':              return `${BASE}/bo4/ae/ae${number}`;
        case 'botd':            return `${BASE}/bo4/botd/botd${number}`;
        case 'class':           return `${BASE}/bo4/class/class${number}`;
        case 'dotn':            return `${BASE}/bo4/dotn/dotn${number}`;
        case 'ix':              return `${BASE}/bo4/ix/ix${number}`;
        case 'vod':             return `${BASE}/bo4/vod/vod${number}`;
        case 'bo4_general':     return `${BASE}/bo4/general/bo4gen${number}`;
        case 'dai':             return `${BASE}/bo5/dai/dai${number}`;
        case 'dm':              return `${BASE}/bo5/dm/dm${number}`;
        case 'fbz':             return `${BASE}/bo5/fbz/fbz${number}`;
        case 'mtd':             return `${BASE}/bo5/mtd/mtd${number}`;
        case 'otb':             return `${BASE}/bo5/otb/otb${number}`;
        default:                return `${BASE}/${id}`;
    }
}

// Label lookup from path slug
const CIPHER_PREFIXES = {
    rev: 'Revelations',
    gk: 'Gorod Krovi',
    tg: 'The Giant',
    tranzit: 'Tranzit',
    mob: 'Mob of the Dead',
    origins: 'Origins',
    soe: 'Shadows of Evil',
    de: 'Der Eisendrache',
    zns: 'Zetsubou',
    ae: 'Ancient Evil',
    botd: 'Blood of the Dead',
    class: 'Classified',
    dotn: 'Dead of the Night',
    ix: 'IX',
    vod: 'Voyage of Despair',
    bo4gen: 'BO4 Teaser',
    dai: 'Dark Aether Intel',
    dm: 'Die Maschine',
    fbz: 'Firebase Z',
    mtd: 'Mauer der Toten',
    otb: 'Outbreak',
};

export function getCipherLabel(path) {
    const parts = path.split('/');
    const slug = parts.pop();

    const comicMatch = path.match(/comics\/issue(\d+)\/cipher(\d+)$/);
    if (comicMatch) return `Comic Issue #${comicMatch[1]}, Cipher #${comicMatch[2]}`;

    const match = slug.match(/^([a-z]+)(\d+)$/);
    if (!match) return slug;
    const prefix = CIPHER_PREFIXES[match[1]];
    return prefix ? `${prefix} ${match[2]}` : slug;
}
