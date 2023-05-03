import { compareSync, genSaltSync, hashSync } from 'bcrypt';
import { passwordStrength } from 'check-password-strength';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { AVAILABLE_LANGUAGES_REGEX } from '../../../utils/CONSTS';
import createError from '../../../utils/createError';
import createResponse from '../../../utils/createResponse';
import { randomString } from '../../../utils/crypto';
import { removeProps } from '../../../utils/masker';
import prisma from '../../../utils/prisma';
import { validate } from '../../../utils/schema';
const router = Router();

router.post(
    '/login',
    validate(
        z.object({
            username: z.string().min(1).max(64),
            password: z.string().min(1).max(128),
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

router.post(
    '/register',
    validate(
        z.object({
            email: z.string().min(5).max(128).email(),
            username: z.string().min(3).max(64),
            password: z.string().min(8).max(128),
            language: z.string().regex(AVAILABLE_LANGUAGES_REGEX).min(1).max(5).optional(),
        })
    ),
    async (
        req: Request<
            {},
            {},
            {
                email: string;
                username: string;
                password: string;
                language?: string;
            }
        >,
        res: Response
    ) => {
        if (await prisma.user.count({ where: { email: req.body.email } }))
            return createError(res, 409, {
                code: 'email_already_exists',
                message: 'email already exists',
                param: 'body:email',
                type: 'register',
            });
        if (await prisma.user.count({ where: { username: req.body.username } }))
            return createError(res, 409, {
                code: 'username_already_exists',
                message: 'username already exists',
                param: 'body:username',
                type: 'register',
            });

        if (passwordStrength(req.body.password).id < 2 || req.body.password === req.body.email || req.body.password === req.body.username)
            return createError(res, 400, {
                code: 'weak_password',
                message: 'password is too weak',
                param: 'body:password',
                type: 'register',
            });

        const user = await prisma.user.create({
            data: {
                email: req.body.email,
                username: req.body.username,
                password: hashSync(req.body.password, genSaltSync()),
                bio: "Hey, I'm new here!",
                language: req.body.language || 'en',
                token: randomString(48),
            },
        });

        // TODO: email verification

        createResponse(res, 200, removeProps(user, ['password']));
    }
);

export default router;
