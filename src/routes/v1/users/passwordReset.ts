import bcrypt from 'bcrypt';
import { passwordStrength } from 'check-password-strength';
import { Request, Response, Router } from 'express';
import nodemailer from 'nodemailer';
import { z } from 'zod';
import { authorize } from '@middleware/auth';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import { randomString } from '@util/crypto';
import prisma, { maskUserMe, getUniqueKey } from '@util/prisma';
import { validate } from '@util/schema';
import { rateLimit } from '@middleware/ratelimit';
import parseHTML from '@util/emails/parser';

const router = Router();

router.post(
    '/passwordRecovery',
    rateLimit({
        ipCount: 3,
        keyCount: 5,
    }),
    validate(z.object({ email: z.string(), newPassword: z.string() })),
    async (req: Request, res: Response) => {
        const { email, newPassword } = req.body;

        const user = await prisma.user.findFirst({ where: { email } });

        if (!user) return createError(res, 404, { code: 'invalid_email', message: 'Account with this email address was not found', param: 'body:email', type: 'validation' });

        if (passwordStrength(newPassword).id < 2 || newPassword === user.email || newPassword === user.username)
            return createError(res, 400, {
                code: 'weak_password',
                message: 'new password is too weak',
                param: 'body:newPassword',
                type: 'validation',
            });

        const data = await prisma.recovery.create({
            data: {
                newPassword: bcrypt.hashSync(newPassword, bcrypt.genSaltSync()),
                userId: user.id,
                code: await getUniqueKey(prisma.recovery, 'code', randomString),
                expiresAt: new Date(Date.now() + 86400000),
            },
        });

        createResponse(res, 200, { success: true });

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

        await transporter.sendMail({
            from: process.env.MAIL_USERNAME,
            to: req.body.email,
            subject: 'Password reset requested',
            html: parseHTML('passwordReset', {
                username: user.username,
                napi: process.env.NAPI_URL,
                code: data.code,
                frontend: process.env.FRONTEND_URL,
            }),
        });
    }
);

router.get(
    '/passwordKey',
    rateLimit({
        ipCount: 5,
        keyCount: 10,
    }),
    async (req: Request, res: Response) => {
        const code = req.query.code as string;

        if (!code) return createError(res, 400, { code: 'invalid_code', message: 'Password recovery code was not provided ', param: 'query:code', type: 'validation' });

        const recovery = await prisma.recovery.findFirst({ where: { code } });

        if (!recovery) return createError(res, 400, { code: 'invalid_code', message: 'Invalid password recovery code was provided ', param: 'query:code', type: 'validation' });

        if (recovery.expiresAt.getTime() < Date.now()) {
            await prisma.recovery.delete({ where: { code: recovery.code } });
            return createError(res, 400, { code: 'invalid_code', message: 'Invalid password recovery code was provided ', param: 'query:code', type: 'validation' });
        }

        const user = await prisma.user.findFirst({ where: { id: recovery.userId } });

        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', type: 'validation' });

        const token = randomString(48);

        await prisma.user.update({ where: { id: user.id }, data: { password: recovery.newPassword, token } });
        await prisma.recovery.delete({ where: { code: recovery.code } });

        return res.redirect(`${process.env.FRONTEND_URL}/account`);
    }
);

router.patch(
    '/password',
    rateLimit({
        ipCount: 5,
        keyCount: 10,
    }),
    validate(z.object({ oldPassword: z.string().min(1).max(128), newPassword: z.string().min(8).max(128) })),
    authorize({
        disableBearer: true,
    }),
    async (req: Request, res: Response) => {
        const { oldPassword, newPassword } = req.body;

        const user = await prisma.user.findFirst({ where: { id: req.user.id } });

        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', type: 'validation' });

        if (!(await bcrypt.compare(oldPassword, user.password))) {
            return createError(res, 401, { code: 'invalid_password', message: 'Invalid old password was provided', param: 'body:oldPassword', type: 'validation' });
        }

        if (newPassword === oldPassword)
            return createError(res, 400, {
                code: 'invalid_password',
                message: 'New password cannot be the same as the current one',
                type: 'validation',
                param: 'body:newPassword',
            });

        if (passwordStrength(req.body.newPassword).id < 2 || req.body.newPassword === req.user.email || req.body.newPassword === req.user.username)
            return createError(res, 400, {
                code: 'weak_password',
                message: 'New password is too weak',
                param: 'body:newPassword',
                type: 'validation',
            });

        const hashedPassword = bcrypt.hashSync(newPassword, bcrypt.genSaltSync());
        const token = randomString(48);

        await prisma.user.update({
            where: { id: req.user.id },
            data: {
                password: hashedPassword,
                token,
            },
        });

        return createResponse(res, 200, { success: true, token, ...maskUserMe(user) });
    }
);

export default router;
