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
export function maskUserMe(user: User) {
    const mask = ['password', 'oauth_authorizations', 'oauth_codes', 'mfaSecret', 'mfaRecoveryCodes', 'emailVerifyCode', 'token', 'tokenHash'];

    return removeProps(user, mask);
}

/**
 * Mask user object for public use
 * @param user User to mask
 * @param includeEmail include mail in the masked object
 * @returns User object with removed properties
 */
export function maskUserQuery(user: User) {
    const { profilePublic } = user;
    const mask = [
        'password',
        'email',
        'trackActivity',
        'oauth_authorizations',
        'oauth_codes',
        'token',
        'tokenHash',
        'email',
        'mfaSecret',
        'mfaRecoveryCodes',
        'emailVerifyCode',
        'verified',
        'mfaEnabled',
        'updatedAt',
        'permissionLevel',
        'profilePublic',
        'activityNotify',
        'pubkey',
    ];

    if (!profilePublic) mask.push('bio', 'language', 'createdAt');

    return removeProps(user, mask);
}

/**
 * Mask user object for OAuth use
 * @param user User to mask
 * @param oauth OAuth authorization requesting data
 * @returns User object with removed properties
 */
export function maskUserOAuth(user: User, oauth: OAuth_Authorization) {
    const mask = [
        'password',
        'token',
        'tokenHash',
        'trackActivity',
        'oauth_authorizations',
        'oauth_codes',
        'mfaSecret',
        'mfaRecoveryCodes',
        'updatedAt',
        'verified',
        'mfaEnabled',
        'emailVerifyCode',
        'profilePublic',
        'activityNotify',
    ];

    const scopes = oauth.scopes as TPermission[];
    if (!checkPermission(scopes, 'account.read.email')) mask.push('email');
    if (!checkPermission(scopes, 'account.read.basic')) mask.push('bio', 'language', 'createdAt');
    if (!checkPermission(scopes, 'account.read.pubkey')) mask.push('pubkey');

    return removeProps(user, mask);
}
