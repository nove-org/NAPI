import createError from '@util/createError';
import prisma from '@util/prisma';
import { compareSync } from 'bcrypt';
import { NextFunction, Request, Response } from 'express';

export async function checkAdminPassword(req: Request, res: Response, next: NextFunction) {
    const adminUser = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!req.body?.admin_password?.length || !compareSync(req.body.admin_password, adminUser?.password as string))
        return createError(res, 401, { code: 'unauthorized', message: 'you have to enter a password to perform this action', type: 'authorization', param: 'body:admin_password' });
    else return next();
}
