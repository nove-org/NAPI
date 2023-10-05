import createError from '@util/createError';
import { NextFunction, Request, Response } from 'express';

export function authorizeAdmin(req: Request, res: Response, next: NextFunction) {
    if (req.user && req.user.permissionLevel === 2) return next();
    else createError(res, 404, { code: 'not_found', message: 'this page does not exist', type: 'authorization' });
}
