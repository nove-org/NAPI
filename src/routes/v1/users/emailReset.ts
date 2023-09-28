import { Router, Request, Response } from 'express';
import { authorize } from '../../../middlewares/auth';
import { validate } from '../../../utils/schema';
import { z } from 'zod';
import prisma from '../../../utils/prisma';
import { getUniqueKey } from '../../../utils/prisma';
import { randomString } from '../../../utils/crypto';
import createError from '../../../utils/createError';
import createResponse from '../../../utils/createResponse';
import nodemailer from 'nodemailer';
import { UserEmailChange } from '@prisma/client';
import { rateLimit } from '../../../middlewares/ratelimit';

const router = Router();

router.post(
    '/emailReset',
    rateLimit({
        ipCount: 5,
        keyCount: 10,
    }),
    authorize({ disableBearer: true, requireMfa: false }),
    validate(z.object({ newEmail: z.string() })),
    async (req: Request, res: Response) => {
        const { newEmail } = req.body;

        const emailUser = await prisma.user.findFirst({ where: { email: newEmail } });

        if (emailUser)
            return createError(res, 400, {
                message: 'This email is already taken',
                code: 'taken_email',
                type: 'validation',
            });

        const data = await prisma.userEmailChange.create({
            data: {
                newEmail: newEmail,
                userId: req.user.id,
                expiresAt: new Date(Date.now() + 86400000),
                codeNewMail: await getUniqueKey(prisma.userEmailChange, 'codeNewMail', randomString),
                codeOldMail: await getUniqueKey(prisma.userEmailChange, 'codeOldMail', randomString),
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
            to: req.user.email,
            subject: 'Confirm requested e-mail address change',
            html: `<center><img src="https://f.nove.team/emailReset.svg" width="380" height="126" alt="Confirm requested e-mail address change"><div style="margin:10px 0;padding:20px;max-width:340px;width:calc(100% - 20px * 2);background:#ededed;border-radius:25px;font-family:sans-serif;user-select:none;text-align:left"><p style="font-size:17px;line-height:1.5;margin:0;margin-bottom:10px;text-align:left">Hello,&nbsp;<b>${req.user.username}</b>. Someone requested to change your Nove account e-mail. In order to approve that request, click the "Confirm e-mail change" button. If that wasn't you, just ignore this message.</p><a style="display:block;width:fit-content;border-radius:50px;padding:5px 9px;font-size:16px;color:#fff;background:#000;text-decoration:none;text-align:left" href="${process.env.NAPI_URL}/v1/users/confirmEmailChange?code=${data.codeOldMail}">Confirm e-mail change</a></div><p style="max-width:380px;width:380px;text-align:left;font-size:14px;opacity:.7;font-family:sans-serif;user-select:none">We create FOSS privacy-respecting software for everyday use.<a href="${process.env.FRONTEND_URL}" target="_blank">Website</a>,<a href="${process.env.FRONTEND_URL}/privacy" target="_blank">Privacy Policy</a></p></center>`,
        });

        await transporter.sendMail({
            from: process.env.MAIL_USERNAME,
            to: newEmail,
            subject: 'Confirm requested e-mail address change',
            html: `<center><img src="https://f.nove.team/emailReset.svg" width="380" height="126" alt="Confirm requested e-mail address change"><div style="margin:10px 0;padding:20px;max-width:340px;width:calc(100% - 20px * 2);background:#ededed;border-radius:25px;font-family:sans-serif;user-select:none;text-align:left"><p style="font-size:17px;line-height:1.5;margin:0;margin-bottom:10px;text-align:left">Hello,&nbsp;<b>${req.user.username}</b>. Someone requested to change your Nove account e-mail. In order to approve that request, click the "Confirm e-mail change" button. If that wasn't you, just ignore this message.</p><a style="display:block;width:fit-content;border-radius:50px;padding:5px 9px;font-size:16px;color:#fff;background:#000;text-decoration:none;text-align:left" href="${process.env.NAPI_URL}/v1/users/confirmEmailChange?code=${data.codeNewMail}">Confirm e-mail change</a></div><p style="max-width:380px;width:380px;text-align:left;font-size:14px;opacity:.7;font-family:sans-serif;user-select:none">We create FOSS privacy-respecting software for everyday use.<a href="${process.env.FRONTEND_URL}" target="_blank">Website</a>,<a href="${process.env.FRONTEND_URL}/privacy" target="_blank">Privacy Policy</a></p></center>`,
        });
    }
);

router.get(
    '/confirmEmailChange',
    rateLimit({
        ipCount: 5,
        keyCount: 10,
    }),
    async (req: Request, res: Response) => {
        const code = req.query.code as string;

        const newEmailObject = await prisma.userEmailChange.findFirst({
            where: {
                OR: [{ codeNewMail: code }, { codeOldMail: code }],
            },
        });

        if (!newEmailObject)
            return createError(res, 404, {
                code: 'invalid_code',
                message: 'invalid email change code',
                param: 'query:code',
                type: 'authorization',
            });

        if (code === newEmailObject.codeNewMail)
            await prisma.userEmailChange.update({
                where: { id: newEmailObject.id },
                data: { codeNewMail: '' },
            });
        if (code === newEmailObject.codeOldMail)
            await prisma.userEmailChange.update({
                where: { id: newEmailObject.id },
                data: { codeOldMail: '' },
            });

        const newData = (await prisma.userEmailChange.findFirst({ where: { id: newEmailObject.id } })) as UserEmailChange;

        if (!newData.codeNewMail.length && !newData.codeOldMail.length) {
            await prisma.userEmailChange.delete({
                where: { id: newEmailObject.id },
            });

            await prisma.user.update({ where: { id: req.user.id }, data: { email: newEmailObject.newEmail } });

            return createResponse(res, 200, { success: true });
        }

        return createResponse(res, 200, { text: `you have to verify your ${code === newEmailObject.codeNewMail ? 'old' : 'new'} also` });
    }
);

export default router;
