import { OAuth_App, OAuth_Authorization, User } from '@prisma/client';
import { NextFunction, Request, Response } from 'express';
import createError from '../utils/createError';
import { createLoginDevice } from '../utils/createLoginDevice';
import { removeProps } from '../utils/masker';
import { TPermission, checkPermissions } from '../utils/permissions';
import prisma from '../utils/prisma';
import { Modify } from '../utils/types';

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

            createLoginDevice(req.ip, req.headers['user-agent'] as string, req.user.id);

            next();
        } else
            return createError(res, 401, { code: 'invalid_authorization_method', message: 'invalid authorization method', param: 'header:authorization', type: 'authorization' });
    };
}

export { authorize };
