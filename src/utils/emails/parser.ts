import { readFileSync } from 'fs';
import { join } from 'path';
import { sanitize } from 'isomorphic-dompurify';
import * as pgp from 'openpgp';
import ObjectHelper from '@util/object';

export default async function parseEmail(fileName: string, language: string, pubkey?: string, vars?: object) {
    let file: string;
    let options: JSON;
    try {
        file = readFileSync(join(__dirname, `../../../src/emails/${language}/${fileName}.txt`)).toString();
        options = JSON.parse(readFileSync(join(__dirname, `../../../src/emails/${language}/options.json`)).toString());
    } catch {
        file = readFileSync(join(__dirname, `../../../src/emails/en-US/${fileName}.txt`)).toString();
        options = JSON.parse(readFileSync(join(__dirname, `../../../src/emails/en-US/options.json`)).toString());
    }

    if (vars)
        for (const [key, value] of Object.entries(vars)) {
            file = file.replaceAll('{' + key + '}', value);
        }

    file = sanitize(file.replaceAll('{frontend}', process.env.FRONTEND_URL as string));

    if (pubkey)
        try {
            file = (await pgp.encrypt({
                message: await pgp.createMessage({ text: file }),
                encryptionKeys: await pgp.readKey({ armoredKey: pubkey }),
            })) as string;
        } catch {
            file = `COULD NOT ENCRYPT EMAIL, PLAIN TEXT FALLBACK - SOMETHING IS WRONG WITH YOUR PGP KEY\n\n` + file;
        }

    return { name: ObjectHelper.getValueByStringPath(options, 'addressName'), subject: ObjectHelper.getValueByStringPath(options, fileName), text: file };
}
