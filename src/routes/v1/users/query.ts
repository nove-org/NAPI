import { Request, Response, Router } from 'express';
import { existsSync } from 'fs';
import { join } from 'path';
import { STORAGE_PATH } from '@util/CONSTS';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import prisma, { maskUserQuery } from '@util/prisma';
import { rateLimit } from '@middleware/ratelimit';
import { getAvatarCode } from '@util/getAvatarCode';

const router = Router();

router.get(
    '/:id',
    rateLimit({
        ipCount: 50,
        keyCount: 50,
    }),
    async (req: Request, res: Response) => {
        const { id } = req.params;

        const user = await prisma.user.findFirst({
            where: { id },
        });

        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', param: 'param:id', type: 'validation' });

        const updatedAtCode = getAvatarCode(new Date(user.updatedAt));

        return createResponse(res, 200, {
            ...maskUserQuery(user),
            avatar: `${process.env.NAPI_URL}/v1/users/${user.id}/avatar.webp?v=${updatedAtCode}`,
        });
    },
);

router.get(
    '/:id/avatar.webp',
    rateLimit({
        ipCount: 500,
        keyCount: 500,
    }),
    async (req: Request, res: Response) => {
        const { id } = req.params;

        const user = await prisma.user.findFirst({
            where: { id },
        });

        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', param: 'param:id', type: 'validation' });

        const path = existsSync(`${STORAGE_PATH}/${id}.webp`) ? `${STORAGE_PATH}/${id}.webp` : `${join(STORAGE_PATH, '..')}/defaults/AVATAR.webp`;

        return res.sendFile(path);
    },
);

export default router;
