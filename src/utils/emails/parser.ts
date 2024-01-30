import { readFileSync } from 'fs';
import { join } from 'path';

export default function parseHTML(fileName: string, vars?: object) {
    let file: string = readFileSync(join(__dirname, `../../../src/emails/${fileName}.txt`)).toString();

    if (vars)
        for (const [key, value] of Object.entries(vars)) {
            file = file.replaceAll('{' + key + '}', value);
        }

    return file.replaceAll('{frontend}', process.env.FRONTEND_URL as string);
}
