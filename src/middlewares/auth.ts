import { NextFunction, Request, Response } from 'express';
import createError from '../utils/createError';
import { removeProps } from '../utils/masker';
import { checkPermissions } from '../utils/permissions';
import prisma from '../utils/prisma';

export async function authorizeOwner(req: Request, res: Response, next: NextFunction) {
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
}

export function authorizeBearer(requiredScopes: string[] = []) {
    return async (req: Request, res: Response, next: NextFunction) => {
        const [method, token] = req.headers.authorization?.split(' ') || [];

        if (method !== 'Bearer')
            return createError(res, 401, { code: 'invalid_authorization_method', message: 'invalid authorization method', param: 'header:authorization', type: 'authorization' });
        if (!token)
            return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });

        const authorization = await prisma.oAuth_Authorization.findFirst({
            where: {
                token: token,
            },
            include: {
                app: true,
                user: true,
            },
        });
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
}
