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

const BO3_CIPHERS = [
	{
		label: 'Revelations',
		items: [
			{
				label: 'Unsolved',
				items: [
					{ label: 'Revelations 1', slug: 'ciphers/bo3/rev1' },
					{ label: 'Revelations 7', slug: 'ciphers/bo3/rev7' },
					{ label: 'Revelations 11', slug: 'ciphers/bo3/rev11' },
				]
			},
			{
				label: 'Solved',
				items: [
					{ label: 'Revelations 2 Solve', slug: 'ciphers/bo3/rev2' },
					{ label: 'Revelations 3 Solve', slug: 'ciphers/bo3/rev3' },
					{ label: 'Revelations 4 Solve', slug: 'ciphers/bo3/rev4' },
					{ label: 'Revelations 5 Solve', slug: 'ciphers/bo3/rev5' },
					{ label: 'Revelations 6 Solve', slug: 'ciphers/bo3/rev6' },
					{ label: 'Revelations 8 Solve', slug: 'ciphers/bo3/rev8' },
					{ label: 'Revelations 9 Solve', slug: 'ciphers/bo3/rev9' },
					{ label: 'Revelations 10 Solve', slug: 'ciphers/bo3/rev10' },
					{ label: 'Revelations 12 Solve', slug: 'ciphers/bo3/rev12' },
					{ label: 'Revelations 13 Solve', slug: 'ciphers/bo3/rev13' },
					{ label: 'Revelations 14 Solve', slug: 'ciphers/bo3/rev14' },
				]
			}
		]
	},
	{
		label: 'Gorod Krovi',
		items: [
			{ label: 'GK12 Solve', slug: 'ciphers/bo3/gk12' },
		]
	},
	{
		label: 'The Giant',
		items: [
			{
				label: 'Unsolved',
				items: [
					{ label: 'The Giant cipher', slug: 'ciphers/bo3/tg1' },
				]
			}
		]
	}
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
