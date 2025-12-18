// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

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
							label: 'Revelations',
							items: [
								{
									label: 'Unsolved',
									items: [
										{ label: 'Revelations 1', slug: 'ciphers/rev1' },
										{ label: 'Revelations 2', slug: 'ciphers/rev2' },
										{ label: 'Revelations 5', slug: 'ciphers/rev5' },
										{ label: 'Revelations 6', slug: 'ciphers/rev6' },
										{ label: 'Revelations 7', slug: 'ciphers/rev7' },
										{ label: 'Revelations 8', slug: 'ciphers/rev8' },
										{ label: 'Revelations 9', slug: 'ciphers/rev9' },
										{ label: 'Revelations 10', slug: 'ciphers/rev10' },
										{ label: 'Revelations 11', slug: 'ciphers/rev11' },
										{ label: 'Revelations 12', slug: 'ciphers/rev12' },
									]
								},
								{
									label: 'Solved',
									items: [
										{ label: 'Revelations 3 Solve', slug: 'ciphers/rev3' },
										{ label: 'Revelations 4 Solve', slug: 'ciphers/rev4' },
										{ label: 'Revelations 13 Solve', slug: 'ciphers/rev13' },
										{ label: 'Revelations 14 Solve', slug: 'ciphers/rev14' },
									]
								}
							]
						},
						{
							label: 'Gorod Krovi',
							items: [
								{ label: 'GK Solve', slug: 'ciphers/gk1' },
							]
						},
						{
							label: 'The Giant',
							items: [
								{
									label: 'Unsolved',
									items: [
																		{ label: 'TheGiant cipher', slug: 'ciphers/tg1' },
									]
								}
							]
						}
					],
				},
				{ label: 'Acknowledgements', slug: 'acknowledgements'},
			],
		}),
	],
	image: {
		responsiveStyles: true,
		layout: 'constrained',
	},
});
