import users from './users.json';
import games from './games.json';
import maps from './maps.json';

// Eagerly import all cipher files
const cipherModules = import.meta.glob('./ciphers/*.json', { eager: true });
const ciphers: Cipher[] = Object.values(cipherModules).flatMap(
  (m: any) => m.default,
);

// Types
export interface User {
  platform: string;
}
export interface Game {
  label: string;
}
export interface CipherMap {
  game: string;
  label: string;
}
export interface SolutionStep {
  type: string;
  method?: string;
  key?: string;
  description?: string;
  notes?: string;
  [key: string]: any;
}
export interface Solution {
  steps: SolutionStep[];
  notes?: string;
}
export interface Cipher {
  id: string;
  map: string;
  number: number;
  title: string;
  type?: string;
  image: string | null;
  solved: boolean;
  solvers: string[];
  credits: string[];
  ciphertext: string | null;
  plaintext: string | null;
  solution: Solution | null;
}

// Query functions
export function getCipher(id: string): Cipher | undefined {
  return ciphers.find((c) => c.id === id);
}

export function getCiphersByMap(mapId: string): Cipher[] {
  return ciphers.filter((c) => c.map === mapId);
}

export function getAllCiphers(): Cipher[] {
  return ciphers;
}

export function getUser(name: string): User | undefined {
  return (users as Record<string, User>)[name];
}

export function getAllUsers(): Record<string, User> {
  return users as Record<string, User>;
}

export function getMap(mapId: string): CipherMap | undefined {
  return (maps as Record<string, CipherMap>)[mapId];
}

export function getGame(gameId: string): Game | undefined {
  return (games as Record<string, Game>)[gameId];
}
