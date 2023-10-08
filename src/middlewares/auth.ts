import { OAuth_App, OAuth_Authorization, User } from '@prisma/client';
import { NextFunction, Request, Response } from 'express';
import { verifyToken } from 'node-2fa';
import createError from '@util/createError';
import { removeProps } from '@util/masker';
import { TPermission, checkPermissions } from '@util/permissions';
import prisma from '@util/prisma';
import { Modify } from '@util/types';

function authorize({
    requiredScopes = [],
    disableBearer = false,
    disableOwner = false,
    requireMfa = false,
}: {
    requiredScopes?: TPermission[];
    disableBearer?: boolean;
    disableOwner?: boolean;
    requireMfa?: boolean;
}) {
    return async (req: Request, res: Response, next: NextFunction) => {
        const [method, token] = req.headers.authorization?.split(' ') || [];
        const mfa = (req.headers['x-mfa'] as string) || '';

        if (!token)
            return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });

        if (method === 'Bearer') {
            if (disableBearer)
                return createError(res, 401, {
                    code: 'invalid_authorization_method',
                    message: 'invalid authorization method',
                    param: 'header:authorization',
                    type: 'authorization',
                });

            const authorization = (await prisma.oAuth_Authorization.findFirst({
                where: {
                    token: token,
                },
                include: {
                    app: true,
                    user: true,
                },
            })) as Modify<
                OAuth_Authorization & {
                    app: OAuth_App;
                    user: User;
                },
                {
                    scopes: TPermission[];
                }
            >;
            if (!authorization)
                return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });
            if (authorization.token_expires < new Date())
                return createError(res, 401, { code: 'expired_authorization_token', message: 'expired authorization token', param: 'header:authorization', type: 'authorization' });
            if (!checkPermissions(authorization.scopes, requiredScopes))
                return createError(res, 403, { code: 'insufficient_permissions', message: 'insufficient permissions', param: 'header:authorization', type: 'authorization' });

            if (requireMfa && (!authorization.user.mfaEnabled || !mfa || !/([0-9]{6})|([a-zA-Z0-9]{16})/.test(mfa)))
                return createError(res, 403, {
                    code: 'mfa_required',
                    message: 'mfa required',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });
            if (requireMfa && !(/([0-9]{6})/.test(mfa) ? verifyToken(authorization.user.mfaSecret, mfa)?.delta === 1 : authorization.user.mfaRecoveryCodes?.includes(mfa)))
                return createError(res, 403, {
                    code: 'invalid_mfa_token',
                    message: 'invalid mfa token',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });

            if (/([a-zA-Z0-9]{16})/.test(mfa))
                authorization.user = await prisma.user.update({
                    where: {
                        id: authorization.user.id,
                    },
                    data: {
                        mfaRecoveryCodes: {
                            set: authorization.user.mfaRecoveryCodes?.filter((code) => code !== mfa),
                        },
                    },
                });

            req.user = removeProps(authorization.user, ['password', 'token']);
            req.oauth = authorization;

            next();
        } else if (method === 'Owner') {
            let user = await prisma.user.findFirst({
                where: {
                    token: token,
                },
            });

            if (!user)
                return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });

            if (!user.verified)
                return createError(res, 401, { code: 'verify_email', message: 'this account is not verified', param: 'header:authorization', type: 'authorization' });

            if (requireMfa && (!user.mfaEnabled || !mfa || !/([0-9]{6})|([a-zA-Z0-9]{16})/.test(mfa)))
                return createError(res, 403, {
                    code: 'mfa_required',
                    message: 'mfa required',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });
            if (requireMfa && !(/([0-9]{6})/.test(mfa) ? verifyToken(user.mfaSecret, mfa)?.delta === 1 : user.mfaRecoveryCodes?.includes(mfa)))
                return createError(res, 403, {
                    code: 'invalid_mfa_token',
                    message: 'invalid mfa token',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });

            if (/([a-zA-Z0-9]{16})/.test(mfa))
                user = await prisma.user.update({
                    where: {
                        id: user.id,
                    },
                    data: {
                        mfaRecoveryCodes: {
                            set: user.mfaRecoveryCodes?.filter((code) => code !== mfa),
                        },
                    },
                });

            req.user = removeProps(user, ['password', 'token']);
            next();
        } else
            return createError(res, 401, { code: 'invalid_authorization_method', message: 'invalid authorization method', param: 'header:authorization', type: 'authorization' });
    };
}

export { authorize };
