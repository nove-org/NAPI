import { OAuth_Authorization, PrismaClient, User } from '@prisma/client';
import { removeProps } from './masker';
import { TPermission, checkPermission } from './permissions';

const prisma = new PrismaClient();
export default prisma;

export function getUniqueKey(model: any, key: string, generator?: () => string): Promise<string> {
    return new Promise(async (resolve, reject) => {
        let unique = false;
        let value = '';
        while (!unique) {
            value = generator ? generator() : Math.random().toString(36).substring(2, 15);
            const result = await model.findFirst({
                where: {
                    [key]: value,
                },
            });
            if (!result) unique = true;
        }
        resolve(value);
    });
}

/**
 * Mask user object for "me-only" use
 * @param user User to mask
 * @param includeToken Include token in the masked object
 * @returns User object with removed properties
 */
export function maskUserMe(user: User, includeToken: boolean = false) {
    const mask = ['password', 'oauth_authorizations', 'oauth_codes', 'mfaSecret', 'mfaRecoveryCodes'];

    if (!includeToken) mask.push('token');

    return removeProps(user, mask);
}

/**
 * Mask user object for public use
 * @param user User to mask
 * @param includeEmail include mail in the masked object
 * @returns User object with removed properties
 */
export function maskUserQuery(user: User, includeEmail: boolean = false) {
    const { profilePublic } = user;
    const mask = ['password', 'trackActivity', 'oauth_authorizations', 'oauth_codes', 'token', 'email', 'mfaSecret', 'mfaRecoveryCodes'];

    if (!profilePublic) mask.push('bio', 'language', 'createdAt', 'updatedAt');
    if (!includeEmail || !profilePublic) mask.push('email');

    return removeProps(user, mask);
}

/**
 * Mask user object for OAuth use
 * @param user User to mask
 * @param oauth OAuth authorization requesting data
 * @returns User object with removed properties
 */
export function maskUserOAuth(user: User, oauth: OAuth_Authorization) {
    const mask = ['password', 'token', 'trackActivity', 'oauth_authorizations', 'oauth_codes', 'mfaSecret', 'mfaRecoveryCodes'];

    if (checkPermission(oauth.scopes as TPermission[], 'account.read.basic') && !checkPermission(oauth.scopes as TPermission[], 'account.read.email')) mask.push('email');
    if (!checkPermission(oauth.scopes as TPermission[], 'account.read.basic')) mask.push('bio', 'language', 'createdAt', 'updatedAt', 'mfaEnabled');

    return removeProps(user, mask);
}
