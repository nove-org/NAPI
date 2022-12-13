// SOURCE: https://github.com/JuzioMiecio520/CaT/blob/main/server/src/utils/masker.ts

import { memoize } from 'lodash';

// Authors: Lodash contributors
// Sources:
//   https://github.com/lodash/lodash/blob/2da024c3b4f9947a48517639de7560457cd4ec6c/.internal/stringToPath.js
//   https://github.com/lodash/lodash/blob/2da024c3b4f9947a48517639de7560457cd4ec6c/.internal/castPath.js
//   https://github.com/lodash/lodash/blob/2da024c3b4f9947a48517639de7560457cd4ec6c/.internal/baseGet.js
//   https://github.com/lodash/lodash/blob/2da024c3b4f9947a48517639de7560457cd4ec6c/.internal/memoizeCapped.js
// Adapted from sources above, since Lodash does not export functions from .internal/
// just use it and don't look at it never ever.
// or maybe redo it sometime, i dunno, it just works
// TODO: refactor this mess. it's a mess.

function memoizeCapped(func: any) {
    const result = memoize(func, (key) => {
        const { cache } = result;
        if (cache.size === 500) {
            cache.clear();
        }
        return key;
    });

    return result;
}

const charCodeOfDot = '.'.charCodeAt(0);
const reEscapeChar = /\\(\\)?/g;
const rePropName = RegExp(
    // Match anything that isn't a dot or bracket.
    '[^.[\\]]+' +
        '|' +
        // Or match property names within brackets.
        '\\[(?:' +
        // Match a non-string expression.
        '([^"\'][^[]*)' +
        '|' +
        // Or match strings (supports escaping characters).
        '(["\'])((?:(?!\\2)[^\\\\]|\\\\.)*?)\\2' +
        ')\\]' +
        '|' +
        // Or match "" as the space between consecutive dots or empty brackets.
        '(?=(?:\\.|\\[\\])(?:\\.|\\[\\]|$))',
    'g'
);

/**
 * Converts `string` to a property path array.
 *
 * @private
 * @param {string} string The string to convert.
 * @returns {Array} Returns the property path array.
 */
const stringToPath = memoizeCapped((string: any) => {
    const result = [];
    if (string.charCodeAt(0) === charCodeOfDot) {
        result.push('');
    }
    string.replace(rePropName, (match: any, expression: any, quote: any, subString: any) => {
        let key = match;
        if (quote) {
            key = subString.replace(reEscapeChar, '$1');
        } else if (expression) {
            key = expression.trim();
        }
        result.push(key);
    });
    return result;
});

export function removeProps<T>(object: T, masks: string[]): Partial<T> {
    for (const mask of masks) {
        const path = stringToPath(mask);
        let index = -1;
        let length = path.length;
        let result = object;

        while (result != null && ++index < length) {
            const key = path[index];
            if (index === length - 1) {
                delete (result as any)[key];
            } else {
                result = (result as any)[key];
            }
        }
    }
    return object;
}

export function showProps<T>(object: T, masks: string[]): Partial<T> {
    const newObject: any = {};

    for (const mask of masks) {
        const path = stringToPath(mask);
        let index = -1;
        let length = path.length;
        let result = object;

        while (result != null && ++index < length) {
            const key = path[index];
            if (index === length - 1) {
                newObject[key] = (result as any)[key];
            } else {
                result = (result as any)[key];
            }
        }
    }

    return newObject;
}
