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
