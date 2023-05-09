import { Prisma } from '@prisma/client';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { authorize } from '../../../middlewares/auth';
import { AVAILABLE_LANGUAGES_REGEX } from '../../../utils/CONSTS';
import createError from '../../../utils/createError';
import createResponse from '../../../utils/createResponse';
import { multerUploadSingle } from '../../../utils/multipart';
import prisma, { maskUserMe, maskUserOAuth } from '../../../utils/prisma';
import { validate } from '../../../utils/schema';
import { UAParser } from 'ua-parser-js';

const router = Router();

router.get(
    '/me',
    authorize({
        requiredScopes: ['account.read.basic'],
    }),
    async (req: Request, res: Response) => {
        const user = { avatar: `${process.env.NAPI_URL}/v1/users/${req.user.id}/avatar.webp`, ...req.user };

        if (req.oauth) return createResponse(res, 200, maskUserOAuth(user, req.oauth));
        else createResponse(res, 200, maskUserMe(user));
    }
);

router.patch(
    '/email',
    authorize({
        disableBearer: true,
    }),
    async (req: Request, res: Response) => {
        const { email } = req.body;
        const emailUser = await prisma.user.findFirst({ where: { email } });

        if (emailUser) return createError(res, 400, { message: 'This email is already taken', code: 'taken_email', type: 'validation' });

        const newUser = await prisma.user.update({
            where: { id: req.user.id },
            data: {
                email,
            },
        });

        return createResponse(res, 200, maskUserMe(newUser));
    }
);

router.patch(
    '/me',
    validate(
        z.object({
            username: z.string().min(1).max(24).optional(),
            bio: z.string().min(1).max(256).optional(),
            language: z.string().regex(AVAILABLE_LANGUAGES_REGEX).optional(),
            trackActivity: z.boolean().optional(),
        }),
        'body'
    ),
    authorize({
        requiredScopes: ['account.write.basic'],
        // TODO: Add scopes for each field
        // TODO: Remove this line and actually implement patching user data by OAuth apps
        disableBearer: true,
    }),
    async (req: Request, res: Response) => {
        let data: Prisma.XOR<Prisma.UserUpdateInput, Prisma.UserUncheckedUpdateInput> = {};

        if (req.body.bio?.length) data['bio'] = req.body.bio;
        if (req.body.username?.length) {
            const user = await prisma.user.findFirst({ where: { username: req.body.username } });

            if (user) return createError(res, 400, { message: 'This username is already taken', code: 'taken_username', type: 'validation' });

            data['username'] = req.body.username;
        }
        if (req.body.language?.length) data['language'] = req.body.language;
        if (typeof req.body.trackActivity === 'boolean') data['trackActivity'] = req.body.trackActivity;

        const newUser = await prisma.user.update({
            where: { id: req.user.id },
            data,
        });

        return createResponse(res, 200, maskUserMe(newUser));
    }
);

router.get('/me/activity', authorize({ disableBearer: true }), async (req: Request, res: Response) => {
    if (!(await prisma.user.findFirst({ where: { id: req.user.id } }))?.trackActivity)
        return createError(res, 400, {
            code: 'activity_disabled',
            message: 'Account activity is turned off',
            type: 'request',
        });

    let perPage = parseInt(req.query.perPage as string) || 10;

    if (perPage > 25 || perPage < 1) perPage = 3;

    const devices = await prisma.trackedDevices.findMany({
        where: {
            userId: req.user.id,
        },
        skip: req.query.page ? parseInt(req.query.page.toString()) * perPage : 0,
        take: perPage,
        orderBy: {
            updatedAt: 'desc',
        },
    });

    createResponse(res, 200, devices);
});

router.patch(
    '/avatar',
    authorize({
        requiredScopes: ['account.write.avatar'],
    }),
    multerUploadSingle(),
    validate(z.object({ file: z.any() })),
    async (req: Request, res: Response) => {
        const file = req.file as Express.Multer.File;

        if (!file)
            return createError(res, 400, {
                code: 'invalid_parameter',
                message: 'You have to send an image',
                param: 'body:avatar',
                type: 'validation',
            });

        const newUser = await prisma.user.update({ where: { id: req.user.id }, data: { updatedAt: new Date() } });

        return createResponse(res, 200, maskUserMe(newUser));
    }
);

export default router;
