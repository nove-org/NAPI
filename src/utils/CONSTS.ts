import { join } from 'path';

export const STORAGE_PATH = join(__dirname, '../../storage/users/avatars/');
export const AVAILABLE_LANGUAGES = ['pl-PL', 'sw-PL', 'en-US', 'en-GB', 'nl-NL', 'fr-FR', 'uk-UA', 'hu-HU', 'ja-JP'];
export const AVAILABLE_LANGUAGES_REGEX = new RegExp(`^(${AVAILABLE_LANGUAGES.join('|')})$`);

export const RATELIMIT_IP_WHITELIST: string[] = [];
