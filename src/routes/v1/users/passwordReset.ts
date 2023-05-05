import bcrypt, { compareSync } from 'bcrypt';
import { passwordStrength } from 'check-password-strength';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { authorize } from '../../../middlewares/auth';
import createError from '../../../utils/createError';
import createResponse from '../../../utils/createResponse';
import { randomString } from '../../../utils/crypto';
import prisma, { maskUserMe, getUniqueKey } from '../../../utils/prisma';
import { validate } from '../../../utils/schema';

const router = Router();

router.patch('/passwordRecovery', validate(z.object({ email: z.string() })), async (req: Request, res: Response) => {
    const { email } = req.body;

    const user = await prisma.user.findFirst({ where: { email } });

    if (!user) return createError(res, 400, { code: 'invalid_email', message: 'account with this email address was not found', param: 'body:email', type: 'authorization' });

    const data = await prisma.recovery.create({
        data: { userId: user.id, code: await getUniqueKey(prisma.recovery, 'code', randomString), expiresAt: new Date(Date.now() + 86400000) },
    });

    console.log(data);

    //TODO: send email (/v1/users/passwordkey?code=data.code)

    createResponse(res, 200, { success: true });
});

router.get('/passwordKey', async (req: Request, res: Response) => {
    const code = req.query.code as string;

    console.log(code);

    if (!code) return createError(res, 404, { code: 'invalid_code', message: 'invalid password recovery code', param: 'query:code', type: 'authorization' });

    const recovery = await prisma.recovery.findFirst({ where: { code } });

    if (!recovery) return createError(res, 404, { code: 'invalid_code', message: 'invalid password recovery code', param: 'query:code', type: 'authorization' });

    if (recovery.expiresAt.getTime() < Date.now()) {
        await prisma.recovery.delete({ where: { code: recovery.code } });
        return createError(res, 404, { code: 'invalid_code', message: 'invalid password recovery code', param: 'query:code', type: 'authorization' });
    }

    return createResponse(res, 200, { recoveryKey: code });
});

router.patch('/passwordReset', validate(z.object({ newPassword: z.string(), recoveryKey: z.string() })), async (req: Request, res: Response) => {
    const { newPassword, recoveryKey } = req.body;

    const recovery = await prisma.recovery.findFirst({ where: { code: recoveryKey } });

    if (!recovery) return createError(res, 404, { code: 'invalid_code', message: 'invalid password recovery code', param: 'query:code', type: 'authorization' });

    const user = await prisma.user.findFirst({ where: { id: recovery.userId } });

    if (!user) return createError(res, 400, { code: 'invalid_user', message: 'this account is probably deleted', param: 'query:code', type: 'authorization' });

    const password = bcrypt.hashSync(newPassword, bcrypt.genSaltSync());

    if (compareSync(newPassword, user.password))
        return createError(res, 400, { code: 'invalid_password', message: 'new password cannot be the same as the current one', type: 'validation', param: 'body:password' });

    await prisma.user.update({
        where: { id: recovery.userId },
        data: { password, token: randomString(48) },
    });

    await prisma.recovery.delete({ where: { code: recoveryKey } });

    return createResponse(res, 200, { success: true, ...maskUserMe(user) });
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
