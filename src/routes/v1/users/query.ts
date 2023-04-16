import { Request, Response, Router } from 'express';
import { existsSync } from 'fs';
import { join } from 'path';
import { STORAGE_PATH } from '../../../utils/CONSTS';
import createError from '../../../utils/createError';
import createResponse from '../../../utils/createResponse';
import { removeProps } from '../../../utils/masker';
import prisma from '../../../utils/prisma';

const router = Router();

router.get('/:id', async (req: Request, res: Response) => {
    const { id } = req.params;

    const user = await prisma.user.findFirst({
        where: { id },
    });

    if (!user) return createError(res, 400, { code: 'invalid_id', message: 'This user does not exist!', type: 'validation', param: 'param:id' });

    return createResponse(res, 200, { ...removeProps(user, ['password', 'token', 'email']), avatar: `${process.env.NAPI_URL}/v1/users/${user.id}/avatar.webp` });
});

router.get('/:id/avatar.webp', async (req: Request, res: Response) => {
    const { id } = req.params;

    const user = await prisma.user.findFirst({
        where: { id },
    });

    if (!user) return createError(res, 400, { code: 'invalid_id', message: 'This user does not exists!', type: 'validation', param: 'param:id' });

    const path = existsSync(`${STORAGE_PATH}/${id}.webp`) ? `${STORAGE_PATH}/${id}.webp` : `${join(STORAGE_PATH, '..')}/defaults/AVATAR.webp`;

    return res.sendFile(path);
});

export default router;
