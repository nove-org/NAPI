import { compareSync } from 'bcrypt';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import createError from '../../../utils/createError';
import createResponse from '../../../utils/createResponse';
import { removeProps } from '../../../utils/masker';
import prisma from '../../../utils/prisma';
import { validate } from '../../../utils/schema';

const router = Router();

router.post(
    '/login',
    validate(
        z.object({
            username: z.string().min(1).max(64),
            password: z.string().min(1).max(64),
        })
    ),
    async (req: Request, res: Response) => {
        const user = await prisma.user.findFirst({
            where: {
                OR: [{ username: req.body.username }, { email: req.body.username }],
            },
        });
        if (!user)
            return createError(res, 404, {
                code: 'user_not_found',
                message: 'user with this username was not found',
                param: 'body:username',
                type: 'authorization',
            });
        if (!compareSync(req.body.password, user.password))
            return createError(res, 401, { code: 'invalid_password', message: 'invalid password', param: 'body:password', type: 'authorization' });
        createResponse(res, 200, removeProps(user, ['password']));
    }
);

export default router;
