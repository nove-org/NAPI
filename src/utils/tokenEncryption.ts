import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

const method: string = 'aes-256-cbc';

export function encryptWithToken(text: string, token: string): string {
    const iv = randomBytes(16);
    const cipher = createCipheriv(method, scryptSync(token, Buffer.alloc(16), 32), iv);
    const enc = cipher.update(text, 'utf-8', 'hex') + cipher.final('hex');

    return Buffer.concat([iv, Buffer.from(enc, 'hex')]).toString('base64');
}

export function decryptWithToken(text: string, token: string): string {
    const combinedBuffer = Buffer.from(text, 'base64');
    const ivLength = 16;

    const iv = Buffer.alloc(ivLength);
    for (let i = 0; i < ivLength; i++) {
        iv[i] = combinedBuffer[i];
    }

    const encryptedText = Buffer.alloc(combinedBuffer.byteLength - ivLength);
    for (let i = ivLength; i < combinedBuffer.byteLength; i++) {
        encryptedText[i - ivLength] = combinedBuffer[i];
    }

    const decipher = createDecipheriv(method, scryptSync(token, Buffer.alloc(16), 32), iv);

    let dec = decipher.update(encryptedText);

    return Buffer.concat([dec, decipher.final()]).toString();
}
