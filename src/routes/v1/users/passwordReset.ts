import { compareSync, genSaltSync, hashSync } from 'bcrypt';
import { passwordStrength } from 'check-password-strength';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { authorize } from '@middleware/auth';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import { randomString } from '@util/crypto';
import prisma, { maskUserMe, getUniqueKey } from '@util/prisma';
import { validate } from '@util/schema';
import { rateLimit } from '@middleware/ratelimit';
import { encryptWithToken } from '@util/tokenEncryption';
import emailSender from '@util/emails/sender';

const router = Router();

router.post(
    '/passwordRecovery',
    rateLimit({
        ipCount: 12,
        keyCount: 3,
    }),
    validate(z.object({ email: z.string().min(5).max(128).email(), newPassword: z.string().min(1) })),
    async (req: Request, res: Response) => {
        const { email, newPassword } = req.body;

        if (passwordStrength(newPassword).id < 2) return createError(res, 400, { code: 'weak_password', message: 'new password is too weak', param: 'body:newPassword', type: 'validation' });

        const user = await prisma.user.findFirst({ where: { email } });
        if (!user) return createResponse(res, 200, { success: true });

        if (newPassword === user.email || newPassword === user.username)
            return createError(res, 400, { code: 'weak_password', message: 'new password is too weak', param: 'body:newPassword', type: 'validation' });

        const code = await getUniqueKey(prisma.recovery, 'code', randomString);

        await prisma.recovery.deleteMany({ where: { userId: user.id } });
        await prisma.recovery.create({
            data: {
                newPassword: hashSync(newPassword, genSaltSync()),
                userId: user.id,
                code: hashSync(code, genSaltSync()),
                expiresAt: new Date(Date.now() + 86400000),
            },
        });

        const message = await emailSender({
            user,
            file: { name: 'passwordReset', pubkey: true, vars: { username: user.username, uid: user.id, napi: process.env.NAPI_URL, code } },
        });
        if (!message) return createError(res, 500, { code: 'could_not_send_mail', message: 'Something went wrong while sending an email message', type: 'internal_error' });

        createResponse(res, 200, { success: true });
    },
);

router.post(
    '/passwordKey',
    rateLimit({
        ipCount: 12,
        keyCount: 3,
    }),
    validate(z.object({ userId: z.string().min(1), password: z.string().min(1).max(128), code: z.string().min(1) })),
    async (req: Request, res: Response) => {
        const { userId, password, code } = req.body;

        const recovery = await prisma.recovery.findFirst({ where: { userId } });
        if (!recovery) return createError(res, 400, { code: 'invalid_code', message: 'Invalid password recovery code was provided ', param: 'query:code', type: 'validation' });
        if (recovery.expiresAt.getTime() < Date.now()) {
            await prisma.recovery.delete({ where: { code: recovery.code } });
            return createError(res, 400, { code: 'invalid_code', message: 'Invalid password recovery code was provided ', param: 'query:code', type: 'validation' });
        }
        if (!compareSync(code, recovery.code)) return createError(res, 400, { code: 'invalid_code', message: 'Invalid password recovery code was provided ', param: 'query:code', type: 'validation' });
        if (!compareSync(password, recovery.newPassword))
            return createError(res, 400, { code: 'invalid_password', message: 'You must re-enter your new password to confirm the change', param: 'body:password', type: 'validation' });

        const user = await prisma.user.findFirst({ where: { id: recovery.userId } });
        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', type: 'validation' });

        const token = randomString(48);

        await prisma.user.update({
            where: { id: user.id },
            data: {
                password: recovery.newPassword,
                token: encryptWithToken(token, password),
                tokenHash: hashSync(token, genSaltSync()),
            },
        });
        await prisma.recovery.delete({ where: { code: recovery.code } });
        await prisma.trackedDevices.deleteMany({ where: { userId: user.id } });

        return createResponse(res, 200, { success: true, token, ...maskUserMe(user) });
    },
);

router.patch(
    '/password',
    rateLimit({
        ipCount: 12,
        keyCount: 3,
    }),
    validate(z.object({ oldPassword: z.string().min(1).max(128), newPassword: z.string().min(8).max(128) })),
    authorize({
        disableBearer: true,
        checkMfaCode: true,
    }),
    async (req: Request, res: Response) => {
        const { oldPassword, newPassword } = req.body;

        const user = await prisma.user.findFirst({ where: { id: req.user.id } });

        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', type: 'validation' });

        if (!compareSync(oldPassword, user.password)) {
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

        const hashedPassword = hashSync(newPassword, genSaltSync());
        const token = randomString(48);

        await prisma.user.update({
            where: { id: req.user.id },
            data: {
                password: hashedPassword,
                token: encryptWithToken(token, req.body.newPassword),
                tokenHash: hashSync(token, genSaltSync()),
            },
        });
        await prisma.trackedDevices.deleteMany({ where: { userId: user.id } });

        return createResponse(res, 200, { success: true, token, ...maskUserMe(user) });
    },
);

export default router;
