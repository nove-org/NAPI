import { authorize } from '@middleware/auth';
import { authorizeAdmin } from '@middleware/authAdmin';
import prisma from '@util/prisma';
import { Request, Response, Router } from 'express';
import { User } from '@prisma/client';
import { getAvatarCode } from '@util/getAvatarCode';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import { validate } from '@util/schema';
import { z } from 'zod';
import nodemailer from 'nodemailer';
interface UserAvatar extends User {
    avatar: string;
}

const router = Router();

router.get('/users', authorize({ disableBearer: true, requireMfa: true }), authorizeAdmin, async (req: Request, res: Response) => {
    const usersDB = await prisma.user.findMany({ orderBy: { createdAt: 'desc' } });

    let users: Partial<UserAvatar>[] = [];

    const updatedAtCode = getAvatarCode(new Date(req.user.updatedAt));

    for (const u of usersDB) {
        users.push({
            id: u.id,
            username: u.username,
            permissionLevel: u.permissionLevel,
            avatar: `${process.env.NAPI_URL}/v1/users/${req.user.id}/avatar.webp?v=${updatedAtCode}`,
            createdAt: u.createdAt,
        });
    }

    return createResponse(res, 200, users);
});

router.patch(
    '/users/:id/delete',
    authorize({ disableBearer: true, requireMfa: true }),
    authorizeAdmin,
    validate(z.object({ reason: z.string() })),
    async (req: Request, res: Response) => {
        const { id } = req.params;

        const user = await prisma.user.findFirst({ where: { id } });

        if (!user) return createError(res, 400, { code: 'invalid_id', message: 'This user does not exist!', type: 'validation', param: 'param:id' });

        if (!req.body.reason?.length) return createError(res, 400, { code: 'invalid_reason', message: 'You have to provide a reason', type: 'validation', param: 'body:reason' });

        const transporter = nodemailer.createTransport({
            host: process.env.MAIL_HOST,
            port: 465,
            tls: {
                rejectUnauthorized: false,
            },
            auth: {
                user: process.env.MAIL_USERNAME,
                pass: process.env.MAIL_PASSWORD,
            },
        });

        //TODO: HTML to email
        await transporter.sendMail({
            from: process.env.MAIL_USERNAME,
            to: user.email,
            subject: 'account deleted',
            html: `your account has been deleted because of ${req.body.reason}, this action was triggered by: ${req.user.username}`,
        });

        await prisma.user.delete({ where: { id } });

        return createResponse(res, 200, { success: true });
    }
);

router.post(
    '/users/:id/disable',
    authorize({ disableBearer: true, requireMfa: true }),
    authorizeAdmin,
    validate(z.object({ reason: z.string() })),
    async (req: Request, res: Response) => {
        const { id } = req.params;

        const user = await prisma.user.findFirst({ where: { id } });

        if (!user) return createError(res, 400, { code: 'invalid_id', message: 'This user does not exist!', type: 'validation', param: 'param:id' });

        if (!req.body.reason?.length) return createError(res, 400, { code: 'invalid_reason', message: 'You have to provide a reason', type: 'validation', param: 'body:reason' });

        const transporter = nodemailer.createTransport({
            host: process.env.MAIL_HOST,
            port: 465,
            tls: {
                rejectUnauthorized: false,
            },
            auth: {
                user: process.env.MAIL_USERNAME,
                pass: process.env.MAIL_PASSWORD,
            },
        });

        //TODO: HTML to email
        await transporter.sendMail({
            from: process.env.MAIL_USERNAME,
            to: user.email,
            subject: 'account disabled',
            html: `your account has been disabled because of ${req.body.reason}, this action was triggered by: ${req.user.username}`,
        });

        await prisma.user.update({ where: { id }, data: { disabled: true } });

        return createResponse(res, 200, { success: true });
    }
);

router.delete('/users/:id/disable', authorize({ disableBearer: true, requireMfa: true }), authorizeAdmin, async (req: Request, res: Response) => {
    const { id } = req.params;

    const user = await prisma.user.findFirst({ where: { id } });

    if (!user) return createError(res, 400, { code: 'invalid_id', message: 'This user does not exist!', type: 'validation', param: 'param:id' });

    const transporter = nodemailer.createTransport({
        host: process.env.MAIL_HOST,
        port: 465,
        tls: {
            rejectUnauthorized: false,
        },
        auth: {
            user: process.env.MAIL_USERNAME,
            pass: process.env.MAIL_PASSWORD,
        },
    });

    //TODO: HTML to email
    await transporter.sendMail({
        from: process.env.MAIL_USERNAME,
        to: user.email,
        subject: 'account enabled',
        html: `your account has been enabled! 👌👌👌👌, this action was triggered by: ${req.user.username}`,
    });

    await prisma.user.update({ where: { id }, data: { disabled: false } });

    return createResponse(res, 200, { success: true });
});

export default router;
