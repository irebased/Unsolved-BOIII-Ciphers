export const SOLVERS = {
    "JessesOcean": {
        "platform": "discord",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/gk12",
        ],
        "credits": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev10",
        ]
    },
    "randomiser": {
        "platform": "discord",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev2",
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev5",
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev6",
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev8",
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev9",
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev10",
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev12",
        ],
        "credits": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev11",
        ]
    },
    "WXAudio": {
        "platform": "discord",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/gk12",
        ],
    },
    "codewarrior0": {
        "platform": "reddit",
        "credits": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/gk12",
        ],
    },
    "waterkh": {
        "platform": "reddit",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev13",
        ],
        "credits": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev4",
        ],
    },
    "rebase": {
        "platform": "discord",
        "credits": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/gk12",
        ],
    },
    "pretz": {
        "platform": "reddit",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev3",
        ],
    },
    "certainpersonio": {
        "platform": "reddit",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev4",
        ],
    },
    "oxin8": {
        "platform": "reddit",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev4",
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev14",
        ],
    },
    "Lizizadolphin": {
        "platform": "reddit",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev4",
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev14",
        ],
    },
    "preferredwhale6": {
        "platform": "reddit",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev4",
        ],
    },
    "bio-roxas": {
        "platform": "reddit",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev4",
        ],
    },
    "Tac": {
        "platform": "generic",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev4",
        ],
    },
    "Aquillian": {
        "platform": "generic",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev4",
        ],
    },
    "junedgasp": {
        "platform": "discord",
        "credits": [
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/gk12",
            "/Unsolved-BOIII-Ciphers/ciphers/bo3/rev3",
        ],
    },
    "RageOverlord": {
        "platform": "twitter",
        "solves": [
            "/Unsolved-BOIII-Ciphers/ciphers/waw/general/bios",
        ]
    }
}

const CIPHER_PREFIXES = {
    rev: 'Revelations',
    gk: 'Gorod Krovi',
    tg: 'The Giant',
};

export function getCipherLabel(path) {
    const slug = path.split('/').pop();
    const match = slug.match(/^([a-z]+)(\d+)$/);
    if (!match) return slug;
    const prefix = CIPHER_PREFIXES[match[1]];
    return prefix ? `${prefix} ${match[2]}` : slug;
}
