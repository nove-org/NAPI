import { Router, Request, Response } from 'express';
import { authorize } from '@middleware/auth';
import { validate } from '@util/schema';
import { z } from 'zod';
import prisma from '@util/prisma';
import { getUniqueKey } from '@util/prisma';
import { randomString } from '@util/crypto';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import { User, UserEmailChange } from '@prisma/client';
import { rateLimit } from '@middleware/ratelimit';
import emailSender from '@util/emails/sender';

const router = Router();

router.post(
    '/emailReset',
    rateLimit({
        ipCount: 5,
        keyCount: 10,
    }),
    authorize({ disableBearer: true, checkMfaCode: true }),
    validate(z.object({ newEmail: z.string().min(5).max(128).email() })),
    async (req: Request, res: Response) => {
        const { newEmail } = req.body;

        const emailUser = await prisma.user.findFirst({ where: { email: newEmail } });

        if (emailUser)
            return createError(res, 409, {
                code: 'invalid_email',
                message: 'You cannot use this email',
                param: 'body:newEmail',
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

        const messageToOld = await emailSender({
            user: req.user as User,
            subject: 'Confirm requested email address change',
            file: {
                name: 'emailReset',
                pubkey: true,
                vars: { username: req.user.username, napi: process.env.NAPI_URL, email: data.codeOldMail, content: 'Someone requested to change your Nove account email.' },
            },
        });

        const messageToNew = await emailSender({
            user: req.user as User,
            subject: 'Confirm requested email address change',
            file: {
                name: 'emailReset',
                pubkey: false,
                vars: { username: req.user.username, napi: process.env.NAPI_URL, email: data.codeNewMail, content: 'Someone requested to change their Nove account address to this email.' },
            },
            emailOverride: newEmail,
        });

        if (!messageToOld || !messageToNew) return createError(res, 500, { code: 'could_not_send_mail', message: 'Something went wrong while sending an email message', type: 'internal_error' });

        createResponse(res, 200, { success: true });
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
                message: 'Invalid email change code was provided',
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

        return createResponse(res, 200, { message: `You have to also verify your ${code === newEmailObject.codeNewMail ? 'old' : 'new'} e-mail` });
    }
);

export default router;
