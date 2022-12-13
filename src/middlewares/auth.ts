import { NextFunction, Request, Response } from 'express';
import createError from '../utils/createError';
import { removeProps } from '../utils/masker';
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
