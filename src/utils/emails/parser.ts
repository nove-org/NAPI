import { readFileSync } from 'fs';
import { join } from 'path';
import { sanitize } from 'isomorphic-dompurify';
import * as pgp from 'openpgp';

export default async function parseEmail(fileName: string, pubkey?: string, vars?: object) {
    let file: string = readFileSync(join(__dirname, `../../../src/emails/${fileName}.txt`)).toString();

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

    return file;
}
