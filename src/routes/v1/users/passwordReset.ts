import bcrypt from 'bcrypt';
import { passwordStrength } from 'check-password-strength';
import { Request, Response, Router } from 'express';
import nodemailer from 'nodemailer';
import { z } from 'zod';
import { authorize } from '../../../middlewares/auth';
import createError from '../../../utils/createError';
import createResponse from '../../../utils/createResponse';
import { randomString } from '../../../utils/crypto';
import prisma, { maskUserMe, getUniqueKey } from '../../../utils/prisma';
import { validate } from '../../../utils/schema';

const router = Router();

router.post('/passwordRecovery', validate(z.object({ email: z.string(), newPassword: z.string() })), async (req: Request, res: Response) => {
    const { email, newPassword } = req.body;

    const user = await prisma.user.findFirst({ where: { email } });

    if (!user) return createError(res, 400, { code: 'invalid_email', message: 'account with this email address was not found', param: 'body:email', type: 'authorization' });

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
        host: 'mail.nove.team',
        port: 465,
        tls: {
            rejectUnauthorized: false,
        },
        auth: {
            user: 'noreply@nove.team',
            pass: process.env.PASSWORD,
        },
    });

    await transporter.sendMail({
        from: 'noreply@nove.team',
        to: req.body.email,
        subject: 'Password reset requested',
        html: `<html style="width: 100%">
            <body style="margin: 0 auto; max-width: 340px; box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.3); background: #e4e4e4">
                <header style="display: flex; align-items: center; font-weight: 700; width: calc(100%-60px); padding: 20px 30px; border-bottom: 1px solid #c4c4c4">
                    <img style="margin-right: 5px" src="https://f.nove.team/nove.png" width="20" height="20" />
                    Nove Group
                </header>
        
                <h1 style="padding: 0 30px">Password reset requested</h1>
                <p style="padding: 0 30px; font-size: 20px; line-height: 1.5; margin: 0; margin-bottom: 40px">
                    Hello, ${user.username}. Your e-mail address has been provided while resetting Nove account password. In order to complete that request please click "Change password" button. If
                    that wasn't you, just ignore this e-mail.
                </p>
                <a style="margin: 0 30px; padding: 10px 15px; border-radius: 5px; font-size: 16px; border: 1px solid indianred; color: black; text-decoration: none" href="https://api.nove.team/v1/users/passwordKey?code=${data.code}"
                    >Change password</a
                >
            </body>
        </html>
        `,
    });
});

router.get('/passwordKey', async (req: Request, res: Response) => {
    const code = req.query.code as string;

    if (!code) return createError(res, 404, { code: 'invalid_code', message: 'invalid password recovery code', param: 'query:code', type: 'authorization' });

    const recovery = await prisma.recovery.findFirst({ where: { code } });

    if (!recovery) return createError(res, 404, { code: 'invalid_code', message: 'invalid password recovery code', param: 'query:code', type: 'authorization' });

    if (recovery.expiresAt.getTime() < Date.now()) {
        await prisma.recovery.delete({ where: { code: recovery.code } });
        return createError(res, 404, { code: 'invalid_code', message: 'invalid password recovery code', param: 'query:code', type: 'authorization' });
    }

    const user = await prisma.user.findFirst({ where: { id: recovery.userId } });

    if (!user)
        return createError(res, 404, {
            code: 'user_not_found',
            message: 'this user was not found',
            param: 'query:code',
            type: 'authorization',
        });

    await prisma.user.update({ where: { id: user.id }, data: { password: recovery.newPassword } });
    await prisma.recovery.delete({ where: { code: recovery.code } });

    return res.redirect('https://nove.team/account');
});

router.patch(
    '/password',
    validate(z.object({ oldPassword: z.string().min(1).max(128), newPassword: z.string().min(8).max(128) })),
    authorize({
        disableBearer: true,
    }),
    async (req: Request, res: Response) => {
        const { oldPassword, newPassword } = req.body;

        const user = await prisma.user.findFirst({ where: { id: req.user.id } });

        if (!user) return createError(res, 500, { code: 'user_not_found', message: 'user not found', type: 'authorization' });

        if (!(await bcrypt.compare(oldPassword, user.password))) {
            return createError(res, 401, { code: 'invalid_password', message: 'invalid password', param: 'body:oldPassword', type: 'authorization' });
        }

        if (newPassword === oldPassword)
            return createError(res, 400, {
                code: 'invalid_password',
                message: 'new password cannot be the same as the current one',
                type: 'validation',
                param: 'body:newPassword',
            });

        if (passwordStrength(req.body.newPassword).id < 2 || req.body.newPassword === req.user.email || req.body.newPassword === req.user.username)
            return createError(res, 400, {
                code: 'weak_password',
                message: 'new password is too weak',
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
