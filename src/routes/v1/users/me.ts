import { Prisma } from '@prisma/client';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { authorize, authorizeOwner } from '../../../middlewares/auth';
import { AVAILABLE_LANGUAGES_REGEX } from '../../../utils/CONSTS';
import createError from '../../../utils/createError';
import createResponse from '../../../utils/createResponse';
import { removeProps } from '../../../utils/masker';
import { multerUploadSingle } from '../../../utils/multipart';
import { checkPermission } from '../../../utils/permissions';
import prisma from '../../../utils/prisma';
import { validate } from '../../../utils/schema';

const router = Router();

router.get(
    '/me',
    authorize({
        requiredScopes: ['account.read.basic'],
    }),
    async (req: Request, res: Response) => {
        if (!req.oauth || checkPermission(req.oauth.scopes, 'account.read.email'))
            createResponse(res, 200, {
                avatar: `${process.env.NAPI_URL}/v1/users/${req.user.id}/avatar.webp`,
                ...removeProps(req.user, ['password']),
            });
        else createResponse(res, 200, { avatar: `${process.env.NAPI_URL}/v1/users/${req.user.id}/avatar.webp`, ...removeProps(req.user, ['password', 'email']) });
    }
);

router.patch('/email', authorizeOwner, async (req: Request, res: Response) => {
    const { email } = req.body;

    await prisma.user.update({
        where: { id: req.user.id },
        data: {
            email,
        },
    });

    return createResponse(res, 200, removeProps(req.user, ['password', 'token']));
});

router.patch(
    '/me',
    validate(
        z.object({ username: z.string().min(1).max(24).optional(), bio: z.string().min(1).max(256).optional(), language: z.string().regex(AVAILABLE_LANGUAGES_REGEX).optional() }),
        'body'
    ),
    authorizeOwner,
    async (req: Request, res: Response) => {
        let data: Prisma.XOR<Prisma.UserUpdateInput, Prisma.UserUncheckedUpdateInput> = {};

        if (req.body.bio?.length) data['bio'] = req.body.bio;
        if (req.body.username?.length) data['username'] = req.body.username;
        if (req.body.language?.length) data['language'] = req.body.language;

        await prisma.user.update({
            where: { id: req.user.id },
            data,
        });

        return createResponse(res, 200, removeProps(req.user, ['password', 'token']));
    }
);

router.patch('/avatar', authorizeOwner, multerUploadSingle(), validate(z.object({ file: z.any() })), async (req: Request, res: Response) => {
    const file = req.file as Express.Multer.File;

    if (!file)
        return createError(res, 400, {
            code: 'invalid_parameter',
            message: 'You have to send an image',
            param: 'body:avatar',
            type: 'validation',
        });

    return createResponse(res, 200, removeProps(req.user, ['password', 'token']));
});

export default router;