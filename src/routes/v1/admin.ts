import { authorize } from '@middleware/auth';
import { authorizeAdmin } from '@middleware/authAdmin';
import prisma from '@util/prisma';
import { Request, Response, Router } from 'express';
import { User } from '@prisma/client';
import { getAvatarCode } from '@util/getAvatarCode';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import emailSender from '@util/emails/sender';
import { validate } from '@util/schema';
import { z } from 'zod';
import { rateLimit } from '@middleware/ratelimit';

interface UserAvatar extends User {
    avatar: string;
}

const router = Router();

router.get(
    '/users',
    rateLimit({
        ipCount: 100,
        keyCount: 50,
    }),
    authorize({ disableBearer: true, requireMfa: true }),
    authorizeAdmin,
    async (req: Request, res: Response) => {
        const usersDB = await prisma.user.findMany({ orderBy: { createdAt: 'desc' } });

        let users: Partial<UserAvatar>[] = [];

        const updatedAtCode = getAvatarCode(new Date(req.user.updatedAt));

        for (const u of usersDB) {
            users.push({
                id: u.id,
                username: u.username,
                permissionLevel: u.permissionLevel,
                disabled: u.disabled,
                avatar: `${process.env.NAPI_URL}/v1/users/${u.id}/avatar.webp?v=${updatedAtCode}`,
                createdAt: u.createdAt,
            });
        }

        return createResponse(res, 200, users);
    },
);

router.patch(
    '/users/:id/delete',
    rateLimit({
        ipCount: 50,
        keyCount: 25,
    }),
    authorize({ disableBearer: true, requireMfa: true }),
    authorizeAdmin,
    validate(z.object({ reason: z.string() })),
    async (req: Request, res: Response) => {
        const { id } = req.params;

        const user = await prisma.user.findFirst({ where: { id } });

        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', param: 'param:id', type: 'validation' });

        if (!req.body.reason?.length) return createError(res, 400, { code: 'invalid_reason', message: 'You have to provide a reason', param: 'body:reason', type: 'validation' });

        const message = await emailSender({
            user,
            file: { name: 'accountDeleted', pubkey: true, vars: { username: user.username, reason: req.body.reason } },
        });

        if (!message) return createError(res, 500, { code: 'could_not_send_mail', message: 'Something went wrong while sending an email message', type: 'internal_error' });

        await prisma.user.delete({ where: { id } });

        return createResponse(res, 200, { success: true });
    },
);

router.post(
    '/users/:id/disable',
    rateLimit({
        ipCount: 50,
        keyCount: 25,
    }),
    authorize({ disableBearer: true, requireMfa: true }),
    authorizeAdmin,
    validate(z.object({ reason: z.string() })),
    async (req: Request, res: Response) => {
        const { id } = req.params;

        const user = await prisma.user.findFirst({ where: { id } });

        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', param: 'param:id', type: 'validation' });

        if (!req.body.reason?.length) return createError(res, 400, { code: 'invalid_reason', message: 'You have to provide a reason', param: 'body:reason', type: 'validation' });

        const message = await emailSender({
            user,
            file: { name: 'accountDisabled', pubkey: true, vars: { username: user.username, reason: req.body.reason } },
        });

        if (!message) return createError(res, 500, { code: 'could_not_send_mail', message: 'Something went wrong while sending an email message', type: 'internal_error' });

        await prisma.user.update({ where: { id }, data: { disabled: true } });

        return createResponse(res, 200, { success: true });
    },
);

router.delete(
    '/users/:id/disable',
    rateLimit({
        ipCount: 50,
        keyCount: 25,
    }),
    authorize({ disableBearer: true, requireMfa: true }),
    authorizeAdmin,
    async (req: Request, res: Response) => {
        const { id } = req.params;

        const user = await prisma.user.findFirst({ where: { id } });

        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', param: 'param:id', type: 'validation' });

        const message = await emailSender({
            user,
            file: { name: 'accountEnabled', pubkey: true, vars: { username: user.username } },
        });

        if (!message) return createError(res, 500, { code: 'could_not_send_mail', message: 'Something went wrong while sending an email message', type: 'internal_error' });

        await prisma.user.update({ where: { id }, data: { disabled: false } });

        return createResponse(res, 200, { success: true });
    },
);

export default router;
