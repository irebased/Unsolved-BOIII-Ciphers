// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const WAW_CIPHERS = [
	{
		label: 'General',
		collapsed: true,
		items: [
			{
				label: 'Character Bios Solve',
				slug: 'ciphers/waw/general/bios',
			}
		]
	},
	{
		label: 'Verruckt',
		collapsed: true,
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
		collapsed: true,
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
		collapsed: true,
		items: [
			{
				label: 'Kino 1 Solve',
				slug: 'ciphers/bo1/kino/kino1'
			}
		]
	},
	{
		label: 'Ascension',
		collapsed: true,
		items: [
			{
				label: 'Ascension 1 Solve',
				slug: 'ciphers/bo1/asc/asc1'
			}
		]
	},
	{
		label: 'Call of the Dead',
		collapsed: true,
		items: [
			{
				label: 'Call of the Dead 1',
				slug: 'ciphers/bo1/cotd/cotd1'
			}
		]
	},
	{
		label: 'Shangri La',
		collapsed: true,
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
		collapsed: true,
		items: [
			{
				label: 'Tranzit 1 Solve',
				slug: 'ciphers/bo2/tranzit/tranzit1',
			}
		]
	},
	{
		label: 'Mob of the Dead',
		collapsed: true,
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
		collapsed: true,
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
		collapsed: true,
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
		collapsed: true,
		items: [
			{
				label: 'Solved',
				collapsed: true,
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
				collapsed: true,
				items: [
					{ label: 'The Giant 4', slug: 'ciphers/bo3/tg/tg4' },
				]
			}
		]
	},
	{
		label: 'Der Eisendrache',
		collapsed: true,
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
		collapsed: true,
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
		collapsed: true,
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
		collapsed: true,
		items: [
			{
				label: 'Unsolved',
				collapsed: true,
				items: [
					{ label: 'Revelations 1', slug: 'ciphers/bo3/rev/rev1' },
					{ label: 'Revelations 7', slug: 'ciphers/bo3/rev/rev7' },
					{ label: 'Revelations 11', slug: 'ciphers/bo3/rev/rev11' },
				]
			},
			{
				label: 'Solved',
				collapsed: true,
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

const BO4_CIPHERS = [
	{
		label: 'Ancient Evil',
		collapsed: true,
		items: [
			{ label: 'Ancient Evil Intro Solve', slug: 'ciphers/bo4/ae/ae0' },
			{ label: 'Ancient Evil 1 Solve', slug: 'ciphers/bo4/ae/ae1' },
			{ label: 'Ancient Evil 2 Solve', slug: 'ciphers/bo4/ae/ae2' },
			{ label: 'Ancient Evil 3 Solve', slug: 'ciphers/bo4/ae/ae3' },
			{ label: 'Ancient Evil 4 Solve', slug: 'ciphers/bo4/ae/ae4' },
			{ label: 'Ancient Evil 5 Solve', slug: 'ciphers/bo4/ae/ae5' },
		]
	},
	{
		label: 'Blood of the Dead',
		collapsed: true,
		items: [
			{ label: 'Blood of the Dead 1', slug: 'ciphers/bo4/botd/botd1' },
			{ label: 'Blood of the Dead 2', slug: 'ciphers/bo4/botd/botd2' },
			{ label: 'Blood of the Dead 3', slug: 'ciphers/bo4/botd/botd3' },
			{ label: 'Blood of the Dead 4', slug: 'ciphers/bo4/botd/botd4' },
			{ label: 'Blood of the Dead 5', slug: 'ciphers/bo4/botd/botd5' },
			{ label: 'Blood of the Dead 6', slug: 'ciphers/bo4/botd/botd6' },
			{ label: 'Blood of the Dead 7', slug: 'ciphers/bo4/botd/botd7' },
			{ label: 'Blood of the Dead 8', slug: 'ciphers/bo4/botd/botd8' },
			{ label: 'Blood of the Dead 9', slug: 'ciphers/bo4/botd/botd9' },
			{ label: 'Blood of the Dead 10', slug: 'ciphers/bo4/botd/botd10' },
			{ label: 'Blood of the Dead 11', slug: 'ciphers/bo4/botd/botd11' },
			{ label: 'Blood of the Dead 12', slug: 'ciphers/bo4/botd/botd12' },
			{ label: 'Blood of the Dead 13', slug: 'ciphers/bo4/botd/botd13' },
			{ label: 'Blood of the Dead 14', slug: 'ciphers/bo4/botd/botd14' },
			{ label: 'Blood of the Dead 15', slug: 'ciphers/bo4/botd/botd15' },
		]
	},
	{
		label: 'Classified',
		collapsed: true,
		items: [
			{ label: 'Classified 1', slug: 'ciphers/bo4/class/class1' },
			{ label: 'Classified 2', slug: 'ciphers/bo4/class/class2' },
			{ label: 'Classified 3', slug: 'ciphers/bo4/class/class3' },
			{ label: 'Classified 4', slug: 'ciphers/bo4/class/class4' },
			{ label: 'Classified 5', slug: 'ciphers/bo4/class/class5' },
		]
	},
	{
		label: 'Dead of the Night',
		collapsed: true,
		items: [
			{ label: 'Dead of the Night 1', slug: 'ciphers/bo4/dotn/dotn1' },
			{ label: 'Dead of the Night 2', slug: 'ciphers/bo4/dotn/dotn2' },
			{ label: 'Dead of the Night 3', slug: 'ciphers/bo4/dotn/dotn3' },
			{ label: 'Dead of the Night 4', slug: 'ciphers/bo4/dotn/dotn4' },
			{ label: 'Dead of the Night 5', slug: 'ciphers/bo4/dotn/dotn5' },
			{ label: 'Dead of the Night 6', slug: 'ciphers/bo4/dotn/dotn6' },
			{ label: 'Dead of the Night 7', slug: 'ciphers/bo4/dotn/dotn7' },
			{ label: 'Dead of the Night 8', slug: 'ciphers/bo4/dotn/dotn8' },
		]
	},
	{
		label: 'IX',
		collapsed: true,
		items: [
			{
				label: "Unsolved",
				collapsed: true,
				items: [
					{ label: 'IX 3', slug: 'ciphers/bo4/ix/ix3' },
					{ label: 'IX 7', slug: 'ciphers/bo4/ix/ix7' },
					{ label: 'IX 9', slug: 'ciphers/bo4/ix/ix9' }
				]
			},
			{
				label: "Solved",
				collapsed: true,
				items: [
					{ label: 'IX 1 Solve', slug: 'ciphers/bo4/ix/ix1' },
					{ label: 'IX 2 Solve', slug: 'ciphers/bo4/ix/ix2' },
					{ label: 'IX 4 Solve', slug: 'ciphers/bo4/ix/ix4' },
					{ label: 'IX 5 Solve', slug: 'ciphers/bo4/ix/ix5' },
					{ label: 'IX 6 Solve', slug: 'ciphers/bo4/ix/ix6' },
					{ label: 'IX 8 Solve', slug: 'ciphers/bo4/ix/ix8' },
					{ label: 'IX 10 Solve', slug: 'ciphers/bo4/ix/ix10' },
					{ label: 'IX 11 Solve', slug: 'ciphers/bo4/ix/ix11' },
					{ label: 'IX 12 Solve', slug: 'ciphers/bo4/ix/ix12' },
					{ label: 'IX 13 Solve', slug: 'ciphers/bo4/ix/ix13' },
					{ label: 'IX 14 Solve', slug: 'ciphers/bo4/ix/ix14' },
					{ label: 'IX 15 Solve', slug: 'ciphers/bo4/ix/ix15' },
					{ label: 'IX 16 Solve', slug: 'ciphers/bo4/ix/ix16' },
					{ label: 'IX 17 Solve', slug: 'ciphers/bo4/ix/ix17' },
					{ label: 'IX 18 Solve', slug: 'ciphers/bo4/ix/ix18' },
					{ label: 'IX 19 Solve', slug: 'ciphers/bo4/ix/ix19' },
					{ label: 'IX 20 Solve', slug: 'ciphers/bo4/ix/ix20' },
					{ label: 'IX 21 Solve', slug: 'ciphers/bo4/ix/ix21' },
					{ label: 'IX 22 Solve', slug: 'ciphers/bo4/ix/ix22' },
					{ label: 'IX 23 Solve', slug: 'ciphers/bo4/ix/ix23' },
					{ label: 'IX 24 Solve', slug: 'ciphers/bo4/ix/ix24' },
					{ label: 'IX 25 Solve', slug: 'ciphers/bo4/ix/ix25' },
					{ label: 'IX 26 Solve', slug: 'ciphers/bo4/ix/ix26' },
					{ label: 'IX 27 Solve', slug: 'ciphers/bo4/ix/ix27' },
					{ label: 'IX 28 Solve', slug: 'ciphers/bo4/ix/ix28' },
					{ label: 'IX 29 Solve', slug: 'ciphers/bo4/ix/ix29' },
				]
			}
		]
	},
	{
		label: 'Voyage of Despair',
		collapsed: true,
		items: [
			{ label: 'Voyage 1 Solve', slug: 'ciphers/bo4/vod/vod1' },
			{ label: 'Voyage 2 Solve', slug: 'ciphers/bo4/vod/vod2' },
			{ label: 'Voyage 3 Solve', slug: 'ciphers/bo4/vod/vod3' },
			{ label: 'Voyage 4 Solve', slug: 'ciphers/bo4/vod/vod4' },
			{ label: 'Voyage 5 Solve', slug: 'ciphers/bo4/vod/vod5' },
			{ label: 'Voyage 6 Solve', slug: 'ciphers/bo4/vod/vod6' },
			{ label: 'Voyage 7 Solve', slug: 'ciphers/bo4/vod/vod7' },
			{ label: 'Voyage 8 Solve', slug: 'ciphers/bo4/vod/vod8' },
			{ label: 'Voyage 9 Solve', slug: 'ciphers/bo4/vod/vod9' },
			{ label: 'Voyage 10 Solve', slug: 'ciphers/bo4/vod/vod10' },
			{ label: 'Voyage 11 Solve', slug: 'ciphers/bo4/vod/vod11' },
			{ label: 'Voyage 12 Solve', slug: 'ciphers/bo4/vod/vod12' },
			{ label: 'Voyage 13 Solve', slug: 'ciphers/bo4/vod/vod13' },
			{ label: 'Voyage 14 Solve', slug: 'ciphers/bo4/vod/vod14' },
			{ label: 'Voyage 15 Solve', slug: 'ciphers/bo4/vod/vod15' },
			{ label: 'Voyage 16 Solve', slug: 'ciphers/bo4/vod/vod16' },
			{ label: 'Voyage 17 Solve', slug: 'ciphers/bo4/vod/vod17' },
			{ label: 'Voyage 18 Solve', slug: 'ciphers/bo4/vod/vod18' },
			{ label: 'Voyage 19 Solve', slug: 'ciphers/bo4/vod/vod19' },
			{ label: 'Voyage 20 Solve', slug: 'ciphers/bo4/vod/vod20' },
			{ label: 'Voyage 21 Solve', slug: 'ciphers/bo4/vod/vod21' },
			{ label: 'Voyage 22 Solve', slug: 'ciphers/bo4/vod/vod22' },
			{ label: 'Voyage 23 Solve', slug: 'ciphers/bo4/vod/vod23' },
		]
	},
	{
		label: 'General',
		collapsed: true,
		items: [
			{ label: 'BO4 Teaser 1 Solve', slug: 'ciphers/bo4/general/bo4gen1' },
			{ label: 'BO4 Teaser 2 Solve', slug: 'ciphers/bo4/general/bo4gen2' },
			{ label: 'BO4 Teaser 3 Solve', slug: 'ciphers/bo4/general/bo4gen3' },
			{ label: 'BO4 Teaser 4 Solve', slug: 'ciphers/bo4/general/bo4gen4' },
			{ label: 'BO4 Teaser 5 Solve', slug: 'ciphers/bo4/general/bo4gen5' },
		]
	},
];

const BO5_CIPHERS = [
	{
		label: 'Dark Aether Intel',
		collapsed: true,
		items: [
			{ label: 'Dark Aether Intel 1', slug: 'ciphers/bo5/dai/dai1' },
		]
	},
	{
		label: 'Die Maschine',
		collapsed: true,
		items: [
			{ label: 'Die Maschine 1', slug: 'ciphers/bo5/dm/dm1' },
			{ label: 'Die Maschine 2', slug: 'ciphers/bo5/dm/dm2' },
			{ label: 'Die Maschine 3', slug: 'ciphers/bo5/dm/dm3' },
			{ label: 'Die Maschine 4', slug: 'ciphers/bo5/dm/dm4' },
		]
	},
	{
		label: 'Firebase Z',
		collapsed: true,
		items: [
			{ label: 'Firebase Z 1', slug: 'ciphers/bo5/fbz/fbz1' },
			{ label: 'Firebase Z 2', slug: 'ciphers/bo5/fbz/fbz2' },
			{ label: 'Firebase Z 3', slug: 'ciphers/bo5/fbz/fbz3' },
		]
	},
	{
		label: 'Mauer der Toten',
		collapsed: true,
		items: [
			{ label: 'Mauer der Toten 1', slug: 'ciphers/bo5/mtd/mtd1' },
			{ label: 'Mauer der Toten 2', slug: 'ciphers/bo5/mtd/mtd2' },
		]
	},
	{
		label: 'Outbreak',
		collapsed: true,
		items: [
			{ label: 'Outbreak 1', slug: 'ciphers/bo5/otb/otb1' },
			{ label: 'Outbreak 2', slug: 'ciphers/bo5/otb/otb2' },
			{ label: 'Outbreak 3', slug: 'ciphers/bo5/otb/otb3' },
		]
	},
];

const COMIC_CIPHERS = [
	{
		label: 'Issue 1',
		collapsed: true,
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
		collapsed: true,
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
		collapsed: true,
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
		collapsed: true,
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
		collapsed: true,
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
		collapsed: true,
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
							collapsed: true,
							items: WAW_CIPHERS
						},
						{
							label: 'Black Ops',
							collapsed: true,
							items: BO1_CIPHERS
						},
						{
							label: 'Black Ops II',
							collapsed: true,
							items: BO2_CIPHERS
						},
						{
							label: 'Black Ops III',
							collapsed: true,
							items: BO3_CIPHERS
						},
						{
							label: 'Black Ops 4',
							collapsed: true,
							items: BO4_CIPHERS
						},
						{
							label: 'Black Ops Cold War',
							collapsed: true,
							items: BO5_CIPHERS
						},
						{
							label: 'Comics',
							collapsed: true,
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
