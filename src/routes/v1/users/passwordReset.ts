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
import { rateLimit } from '../../../middlewares/ratelimit';

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
            html: `<center><img src="https://f.nove.team/passwordReset.svg" width="380" height="126" alt="Password reset requested"><div style="margin:10px 0;padding:20px;max-width:340px;width:calc(100% - 20px * 2);background:#ededed;border-radius:25px;font-family:sans-serif;user-select:none;text-align:left"><p style="font-size:17px;line-height:1.5;margin:0;margin-bottom:10px;text-align:left">Hello,&nbsp;<b>${user.username}</b>. Someone requested to reset your Nove account password by providing your e-mail address. In order to approve that request, click the "Reset password" button. If that wasn't you, just ignore this message.</p><a style="display:block;width:fit-content;border-radius:50px;padding:5px 9px;font-size:16px;color:#fff;background:#000;text-decoration:none;text-align:left" href="${process.env.NAPI_URL}/v1/users/passwordKey?code=${data.code}">Reset password</a></div><p style="max-width:380px;width:380px;text-align:left;font-size:14px;opacity:.7;font-family:sans-serif;user-select:none">We create FOSS privacy-respecting software for everyday use.<a href="${process.env.FRONTEND_URL}" target="_blank">Website</a>,<a href="${process.env.FRONTEND_URL}/privacy" target="_blank">Privacy Policy</a></p></center>`,
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
