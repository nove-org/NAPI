import { readFileSync } from 'fs';
import { minify } from 'html-minifier';
import { sanitize } from 'isomorphic-dompurify';
import { join } from 'path';

export default function parseHTML(fileName: string, vars?: object) {
    let file: string = readFileSync(join(__dirname, `../../../src/emails/${fileName}.htm`)).toString();

    if (vars)
        for (const [key, value] of Object.entries(vars)) {
            file = file.replaceAll('{' + key + '}', value);
        }

    return sanitize(
        minify(file, {
            keepClosingSlash: true,
        })
    );
}
