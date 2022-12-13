import crypto from 'crypto';

export function randomString(length: number, charset: string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'): string {
    const charsLength = charset.length;
    if (charsLength > 256) {
        throw new Error("Argument 'chars' should not have more than 256 characters" + ', otherwise unpredictability will be broken');
    }

    const randomBytes = crypto.randomBytes(length);
    let result = new Array(length);

    let cursor = 0;
    for (let i = 0; i < length; i++) {
        cursor += randomBytes[i];
        result[i] = charset[cursor % charsLength];
    }

    return result.join('');
}
