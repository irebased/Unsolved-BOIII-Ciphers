// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const WAW_CIPHERS = [
	{
		label: 'General',
		items: [
			{
				label: 'Character Bios Solve',
				slug: 'ciphers/waw/general/bios',
			}
		]
	},
	{
		label: 'Verruckt',
		items: [
			{
				label: 'Verruckt 1 Solve',
				slug: 'ciphers/waw/verruckt/verruckt1',
			},
			{
				label: 'Verruckt 2 Solve',
				slug: 'ciphers/waw/verruckt/verruckt2',
			},
		]
	},
	{
		label: 'Der Riese',
		items: [
			{
				label: 'Der Riese 1 Solve',
				slug: 'ciphers/waw/derriese/derriese1',
			},
			{
				label: 'Der Riese 2 Solve',
				slug: 'ciphers/waw/derriese/derriese2',
			},
			{
				label: 'Der Riese 3 Solve',
				slug: 'ciphers/waw/derriese/derriese3',
			},
		]
	}
]

const BO1_CIPHERS = [
	{
		label: 'Kino der toten',
		items: [
			{
				label: 'Kino 1 Solve',
				slug: 'ciphers/bo1/kino/kino1'
			}
		]
	},
	{
		label: 'Ascension',
		items: [
			{
				label: 'Ascension 1 Solve',
				slug: 'ciphers/bo1/asc/asc1'
			}
		]
	},
	{
		label: 'Call of the Dead',
		items: [
			{
				label: 'Call of the Dead 1',
				slug: 'ciphers/bo1/cotd/cotd1'
			}
		]
	},
	{
		label: 'Shangri La',
		items: [
			{
				label: 'Shangri La 1 Solve',
				slug: 'ciphers/bo1/shang/shang1'
			}
		]
	}
]

const BO2_CIPHERS = [
	{
		label: 'Tranzit',
		items: [
			{
				label: 'Tranzit 1 Solve',
				slug: 'ciphers/bo2/tranzit/tranzit1',
			}
		]
	},
	{
		label: 'Mob of the Dead',
		items: [
			{
				label: 'Mob of the Dead 1 Solve',
				slug: 'ciphers/bo2/motd/mob1',
			},
			{
				label: 'Mob of the Dead 2 Solve',
				slug: 'ciphers/bo2/motd/mob2',
			},
			{
				label: 'Mob of the Dead 3 Solve',
				slug: 'ciphers/bo2/motd/mob3',
			},
			{
				label: 'Mob of the Dead 4 Solve',
				slug: 'ciphers/bo2/motd/mob4',
			},
			{
				label: 'Mob of the Dead 5 Solve',
				slug: 'ciphers/bo2/motd/mob5',
			},
			{
				label: 'Mob of the Dead 6 Solve',
				slug: 'ciphers/bo2/motd/mob6',
			},
			{
				label: 'Mob of the Dead 7 Solve',
				slug: 'ciphers/bo2/motd/mob7',
			},
		]
	},
	{
		label: 'Origins',
		items: [
			{
				label: 'Origins 1 Solve',
				slug: 'ciphers/bo2/origins/origins1'
			},
			{
				label: 'Origins 2 Solve',
				slug: 'ciphers/bo2/origins/origins2'
			},
			{
				label: 'Origins 3 Solve',
				slug: 'ciphers/bo2/origins/origins3'
			},
			{
				label: 'Origins 4 Solve',
				slug: 'ciphers/bo2/origins/origins4'
			},
			{
				label: 'Origins 5 Solve',
				slug: 'ciphers/bo2/origins/origins5'
			},
			{
				label: 'Origins 6 Solve',
				slug: 'ciphers/bo2/origins/origins6'
			},
		]
	}
]

const BO3_CIPHERS = [
	{
		label: 'Shadows of Evil',
		items: [
			{
				label: 'Shadows of Evil 1 Solve',
				slug: 'ciphers/bo3/soe/soe1'
			},
			{
				label: 'Shadows of Evil 2 Solve',
				slug: 'ciphers/bo3/soe/soe2'
			},
			{
				label: 'Shadows of Evil 3 Solve',
				slug: 'ciphers/bo3/soe/soe3'
			},
			{
				label: 'Shadows of Evil 4 Solve',
				slug: 'ciphers/bo3/soe/soe4'
			},
			{
				label: 'Shadows of Evil 5 Solve',
				slug: 'ciphers/bo3/soe/soe5'
			},
			{
				label: 'Shadows of Evil 6 Solve',
				slug: 'ciphers/bo3/soe/soe6'
			}
		]
	},
	{
		label: 'The Giant',
		items: [
			{
				label: 'Solved',
				items: [
					{ label: 'The Giant 1 Solve', slug: 'ciphers/bo3/tg/tg1' },
					{ label: 'The Giant 2 Solve', slug: 'ciphers/bo3/tg/tg2' },
					{ label: 'The Giant 3 Solve', slug: 'ciphers/bo3/tg/tg3' },
					{ label: 'The Giant 5 Solve', slug: 'ciphers/bo3/tg/tg5' },
					{ label: 'The Giant 6 Solve', slug: 'ciphers/bo3/tg/tg6' },
				]
			},
			{
				label: 'Unsolved',
				items: [
					{ label: 'The Giant 4', slug: 'ciphers/bo3/tg/tg4' },
				]
			}
		]
	},
	{
		label: 'Der Eisendrache',
		items: [
			{ label: 'Der Eisendrache 1 Solve', slug: 'ciphers/bo3/de/de1' },
			{ label: 'Der Eisendrache 2 Solve', slug: 'ciphers/bo3/de/de2' },
			{ label: 'Der Eisendrache 3 Solve', slug: 'ciphers/bo3/de/de3' },
			{ label: 'Der Eisendrache 4 Solve', slug: 'ciphers/bo3/de/de4' },
			{ label: 'Der Eisendrache 5 Solve', slug: 'ciphers/bo3/de/de5' },
			{ label: 'Der Eisendrache 6 Solve', slug: 'ciphers/bo3/de/de6' },
			{ label: 'Der Eisendrache 7 Solve', slug: 'ciphers/bo3/de/de7' },
			{ label: 'Der Eisendrache 8 Solve', slug: 'ciphers/bo3/de/de8' },
			{ label: 'Der Eisendrache 9 Solve', slug: 'ciphers/bo3/de/de9' },
			{ label: 'Der Eisendrache 10 Solve', slug: 'ciphers/bo3/de/de10' },
			{ label: 'Der Eisendrache 11 Solve', slug: 'ciphers/bo3/de/de11' },
			{ label: 'Der Eisendrache 12 Solve', slug: 'ciphers/bo3/de/de12' },
		]
	},
	{
		label: 'Zetsubou No Shima',
		items: [
			{ label: 'Zetsubou No Shima 1 Solve', slug: 'ciphers/bo3/zns/zns1' },
			{ label: 'Zetsubou No Shima 2 Solve', slug: 'ciphers/bo3/zns/zns2' },
			{ label: 'Zetsubou No Shima 3 Solve', slug: 'ciphers/bo3/zns/zns3' },
			{ label: 'Zetsubou No Shima 4 Solve', slug: 'ciphers/bo3/zns/zns4' },
			{ label: 'Zetsubou No Shima 5 Solve', slug: 'ciphers/bo3/zns/zns5' },
			{ label: 'Zetsubou No Shima 6 Solve', slug: 'ciphers/bo3/zns/zns6' },
			{ label: 'Zetsubou No Shima 7 Solve', slug: 'ciphers/bo3/zns/zns7' },
			{ label: 'Zetsubou No Shima 8 Solve', slug: 'ciphers/bo3/zns/zns8' },
			{ label: 'Zetsubou No Shima 9 Solve', slug: 'ciphers/bo3/zns/zns9' },
			{ label: 'Zetsubou No Shima 10 Solve', slug: 'ciphers/bo3/zns/zns10' },
			{ label: 'Zetsubou No Shima 11 Solve', slug: 'ciphers/bo3/zns/zns11' },
			{ label: 'Zetsubou No Shima 12 Solve', slug: 'ciphers/bo3/zns/zns12' },
			{ label: 'Zetsubou No Shima 13 Solve', slug: 'ciphers/bo3/zns/zns13' },
		]
	},
	{
		label: 'Gorod Krovi',
		items: [
			{ label: 'Gorod Krovi 1 Solve', slug: 'ciphers/bo3/gk/gk1' },
			{ label: 'Gorod Krovi 2 Solve', slug: 'ciphers/bo3/gk/gk2' },
			{ label: 'Gorod Krovi 3 Solve', slug: 'ciphers/bo3/gk/gk3' },
			{ label: 'Gorod Krovi 4 Solve', slug: 'ciphers/bo3/gk/gk4' },
			{ label: 'Gorod Krovi 5 Solve', slug: 'ciphers/bo3/gk/gk5' },
			{ label: 'Gorod Krovi 6 Solve', slug: 'ciphers/bo3/gk/gk6' },
			{ label: 'Gorod Krovi 7 Solve', slug: 'ciphers/bo3/gk/gk7' },
			{ label: 'Gorod Krovi 8 Solve', slug: 'ciphers/bo3/gk/gk8' },
			{ label: 'Gorod Krovi 9 Solve', slug: 'ciphers/bo3/gk/gk9' },
			{ label: 'Gorod Krovi 10 Solve', slug: 'ciphers/bo3/gk/gk10' },
			{ label: 'Gorod Krovi 11 Solve', slug: 'ciphers/bo3/gk/gk11' },
			{ label: 'Gorod Krovi 12 Solve', slug: 'ciphers/bo3/gk/gk12' },
			{ label: 'Gorod Krovi 13 Solve', slug: 'ciphers/bo3/gk/gk13' },
			{ label: 'Gorod Krovi 14 Solve', slug: 'ciphers/bo3/gk/gk14' },
		]
	},
	{
		label: 'Revelations',
		items: [
			{
				label: 'Unsolved',
				items: [
					{ label: 'Revelations 1', slug: 'ciphers/bo3/rev/rev1' },
					{ label: 'Revelations 7', slug: 'ciphers/bo3/rev/rev7' },
					{ label: 'Revelations 11', slug: 'ciphers/bo3/rev/rev11' },
				]
			},
			{
				label: 'Solved',
				items: [
					{ label: 'Revelations 2 Solve', slug: 'ciphers/bo3/rev/rev2' },
					{ label: 'Revelations 3 Solve', slug: 'ciphers/bo3/rev/rev3' },
					{ label: 'Revelations 4 Solve', slug: 'ciphers/bo3/rev/rev4' },
					{ label: 'Revelations 5 Solve', slug: 'ciphers/bo3/rev/rev5' },
					{ label: 'Revelations 6 Solve', slug: 'ciphers/bo3/rev/rev6' },
					{ label: 'Revelations 8 Solve', slug: 'ciphers/bo3/rev/rev8' },
					{ label: 'Revelations 9 Solve', slug: 'ciphers/bo3/rev/rev9' },
					{ label: 'Revelations 10 Solve', slug: 'ciphers/bo3/rev/rev10' },
					{ label: 'Revelations 12 Solve', slug: 'ciphers/bo3/rev/rev12' },
					{ label: 'Revelations 13 Solve', slug: 'ciphers/bo3/rev/rev13' },
					{ label: 'Revelations 14 Solve', slug: 'ciphers/bo3/rev/rev14' },
				]
			}
		]
	},
];

const COMIC_CIPHERS = [
	{
		label: 'Issue 1',
		items: [
			{
				label: 'Comic Cipher 1.1 Solve',
				slug: 'ciphers/comics/issue1/cipher1',
			},
			{
				label: 'Comic Cipher 1.2 Solve',
				slug: 'ciphers/comics/issue1/cipher2',
			},
			{
				label: 'Comic Cipher 1.3 Solve',
				slug: 'ciphers/comics/issue1/cipher3',
			},
		]
	},
	{
		label: 'Issue 2',
		items: [
			{
				label: 'Comic Cipher 2.1 Solve',
				slug: 'ciphers/comics/issue2/cipher1',
			},
			{
				label: 'Comic Cipher 2.2 Solve',
				slug: 'ciphers/comics/issue2/cipher2',
			},
			{
				label: 'Comic Cipher 2.3 Solve',
				slug: 'ciphers/comics/issue2/cipher3',
			},
		]
	},
	{
		label: 'Issue 3',
		items: [
			{
				label: 'Comic Cipher 3.1 Solve',
				slug: 'ciphers/comics/issue3/cipher1',
			},
			{
				label: 'Comic Cipher 3.2 Solve',
				slug: 'ciphers/comics/issue3/cipher2',
			},
			{
				label: 'Comic Cipher 3.3 Solve',
				slug: 'ciphers/comics/issue3/cipher3',
			},
		]
	},
	{
		label: 'Issue 4',
		items: [
			{
				label: 'Comic Cipher 4.1 Solve',
				slug: 'ciphers/comics/issue4/cipher1',
			},
			{
				label: 'Comic Cipher 4.2 Solve',
				slug: 'ciphers/comics/issue4/cipher2',
			},
			{
				label: 'Comic Cipher 4.3 Solve',
				slug: 'ciphers/comics/issue4/cipher3',
			},
		]
	},
	{
		label: 'Issue 5',
		items: [
			{
				label: 'Comic Cipher 5.1 Solve',
				slug: 'ciphers/comics/issue5/cipher1',
			},
			{
				label: 'Comic Cipher 5.2 Solve',
				slug: 'ciphers/comics/issue5/cipher2',
			},
			{
				label: 'Comic Cipher 5.3 Solve',
				slug: 'ciphers/comics/issue5/cipher3',
			},
		]
	},
	{
		label: 'Issue 6',
		items: [
			{
				label: 'Comic Cipher 6.1 Solve',
				slug: 'ciphers/comics/issue6/cipher1',
			},
			{
				label: 'Comic Cipher 6.2 Solve',
				slug: 'ciphers/comics/issue6/cipher2',
			},
			{
				label: 'Comic Cipher 6.3 Solve',
				slug: 'ciphers/comics/issue6/cipher3',
			},
		]
	}
]

export default defineConfig({
	site: "https://irebased.github.io/Unsolved-BOIII-Ciphers",
	base: "/Unsolved-BOIII-Ciphers",
	integrations: [
		starlight({
			title: 'BO3 Unsolved Ciphers',
			logo: {
				src: './src/assets/cryptographic_enigma.PNG',
				replacesTitle: true,
			},
			editLink: {
				baseUrl: 'https://github.com/irebased/Unsolved-BOIII-Ciphers/edit/main/lavender/',
			},
			social: [{ icon: 'discord', label: 'Discord', href: 'https://discord.gg/dsjVrtYygJ' }],
			sidebar: [
				{ label: 'About the hunt', slug: 'background'},
				{
					label: 'Ciphers',
					items: [
						{
							label: 'World at War',
							items: WAW_CIPHERS
						},
						{
							label: 'Black Ops',
							items: BO1_CIPHERS
						},
						{
							label: 'Black Ops II',
							items: BO2_CIPHERS
						},
						{
							label: 'Black Ops III',
							items: BO3_CIPHERS
						},
						{
							label: 'Comics',
							items: COMIC_CIPHERS
						}
					],
				},
				{ label: 'Acknowledgements', slug: 'acknowledgements'},
				{ label: 'Leaderboard', slug: 'leaderboard' },
			],
		}),
	],
	image: {
		responsiveStyles: true,
		layout: 'constrained',
	},
});
