import { OAuth_App, OAuth_Authorization, User } from '@prisma/client';
import { NextFunction, Request, Response } from 'express';
import util from 'node:util';
import createError from '../utils/createError';
import { removeProps } from '../utils/masker';
import { TPermission, checkPermissions } from '../utils/permissions';
import prisma from '../utils/prisma';
import { Modify } from '../utils/types';

/**
 *
 * @deprecated Please use `authorize` instead
 */
let authorizeOwner = async function (req: Request, res: Response, next: NextFunction) {
    const [method, token] = req.headers.authorization?.split(' ') || [];

    if (method !== 'Owner')
        return createError(res, 401, { code: 'invalid_authorization_method', message: 'invalid authorization method', param: 'header:authorization', type: 'authorization' });
    if (!token) return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });

    const user = await prisma.user.findFirst({
        where: {
            token: token,
        },
    });
    req.user = removeProps(user, ['password', 'token']);
    next();
};

/**
 *
 * @deprecated Please use `authorize` instead
 */
let authorizeBearer = function (requiredScopes: TPermission[] = []) {
    return async (req: Request, res: Response, next: NextFunction) => {
        const [method, token] = req.headers.authorization?.split(' ') || [];

        if (method !== 'Bearer')
            return createError(res, 401, { code: 'invalid_authorization_method', message: 'invalid authorization method', param: 'header:authorization', type: 'authorization' });
        if (!token)
            return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });

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
        console.log(authorization, token, req.headers.authorization?.split(' '));
        if (!authorization)
            return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });
        if (authorization.token_expires < new Date())
            return createError(res, 401, { code: 'expired_authorization_token', message: 'expired authorization token', param: 'header:authorization', type: 'authorization' });
        if (!checkPermissions(authorization.scopes, requiredScopes))
            return createError(res, 403, { code: 'insufficient_permissions', message: 'insufficient permissions', param: 'header:authorization', type: 'authorization' });

        req.user = removeProps(authorization.user, ['password', 'token']);
        req.oauth = authorization;
        next();
    };
};

function authorize({ requiredScopes = [], disableBearer = false, disableOwner = false }: { requiredScopes?: TPermission[]; disableBearer?: boolean; disableOwner?: boolean }) {
    return async (req: Request, res: Response, next: NextFunction) => {
        const [method, token] = req.headers.authorization?.split(' ') || [];

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

            req.user = removeProps(authorization.user, ['password', 'token']);
            req.oauth = authorization;
            next();
        } else if (method === 'Owner') {
            const user = await prisma.user.findFirst({
                where: {
                    token: token,
                },
            });

            if (!user)
                return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });

            req.user = removeProps(user, ['password', 'token']);
            next();
        } else
            return createError(res, 401, { code: 'invalid_authorization_method', message: 'invalid authorization method', param: 'header:authorization', type: 'authorization' });
    };
}

authorizeBearer = util.deprecate(authorizeBearer, 'authorizeBearer() is deprecated. Use authorize() instead');
authorizeOwner = util.deprecate(authorizeOwner, 'authorizeOwner() is deprecated. Use authorize() instead');

export { authorize, authorizeBearer, authorizeOwner };
