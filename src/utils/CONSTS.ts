import { join } from 'path';

export const STORAGE_PATH = join(__dirname, '../../storage/users/avatars/');
export const AVAILABLE_LANGUAGES = ['pl-PL', 'en-US', 'en-GB'];
export const AVAILABLE_LANGUAGES_REGEX = new RegExp(`^(${AVAILABLE_LANGUAGES.join('|')})$`);
