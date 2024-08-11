import { compareSync, genSaltSync, hashSync } from 'bcrypt';
import { passwordStrength } from 'check-password-strength';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { AVAILABLE_LANGUAGES_REGEX, RATELIMIT_IP_WHITELIST } from '@util/CONSTS';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import { randomString } from '@util/crypto';
import { getUniqueKey } from '@util/prisma';
import { verifyToken } from 'node-2fa';
import prisma, { maskUserMe } from '@util/prisma';
import { validate } from '@util/schema';
import axios from 'axios';
import { createLoginDevice } from '@util/createLoginDevice';
import { rateLimit } from '@middleware/ratelimit';
import { decryptWithToken, encryptWithToken } from '@util/tokenEncryption';
import emailSender from '@util/emails/sender';

const router = Router();

router.post(
    '/login',
    rateLimit({
        ipCount: 30,
        keyCount: 30,
    }),
    validate(
        z.object({
            username: z.string().min(1).max(64),
            password: z.string().min(1).max(128),
            address: z.string().optional().min(7).max(15)
        }),
    ),
    async (req: Request, res: Response) => {
        let user = await prisma.user.findFirst({
            where: {
                OR: [{ username: req.body.username }, { email: req.body.username }],
            },
        });
        if (!user)
            return createError(res, 404, {
                code: 'invalid_user',
                message: 'User with this username was not found',
                param: 'body:username',
                type: 'authorization',
            });
        if (!compareSync(req.body.password, user.password))
            return createError(res, 401, { code: 'invalid_password', message: 'Invalid password was provided', param: 'body:password', type: 'authorization' });

        if (user.mfaEnabled) {
            const mfa = (req.headers['x-mfa'] as string) || '';

            if (!mfa || !/([0-9]{6})|([a-zA-Z0-9]{16})/.test(mfa))
                return createError(res, 403, {
                    code: 'mfa_required',
                    message: 'MFA is required',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });

            if (!(/([0-9]{6})/.test(mfa) ? verifyToken(user.mfaSecret, mfa)?.delta === 1 || verifyToken(user.mfaSecret, mfa)?.delta === 0 : user.mfaRecoveryCodes?.includes(mfa)))
                return createError(res, 403, {
                    code: 'invalid_mfa_token',
                    message: `Invalid MFA token was provided (delta ${verifyToken(user.mfaSecret, mfa)?.delta})`,
                    param: 'header:x-mfa',
                    type: 'authorization',
                });

            if (/([a-zA-Z0-9]{16})/.test(mfa))
                await prisma.user.update({
                    where: {
                        id: user.id,
                    },
                    data: {
                        mfaRecoveryCodes: {
                            set: user.mfaRecoveryCodes?.filter((code) => code !== mfa),
                        },
                    },
                });
        }

        if (!user.tokenHash) {
            const newToken = randomString(48);
            user = await prisma.user.update({
                where: { id: user.id },
                data: {
                    token: encryptWithToken(newToken, req.body.password),
                    tokenHash: hashSync(newToken, genSaltSync()),
                },
            });
        }

        let decryptedToken: string;
        try {
            decryptedToken = decryptWithToken(user.token, req.body.password);
        } catch {
            return createError(res, 500, {
                code: 'internal_server_error',
                message: 'Could not decrypt token',
                param: 'body:password',
                type: 'authorization',
            });
        }
        createResponse(res, 200, { ...maskUserMe(user), token: decryptedToken });

        user.token = decryptedToken;
        let ip = req.ip as string;
        if (RATELIMIT_IP_WHITELIST.includes(ip) && req.body.address) ip = req.body.address;
        const devices = await prisma.trackedDevices.findMany({ where: { userId: user.id } });
        const device = devices.find((dev) => decryptWithToken(dev.ip, user!.token) === ip);
        createLoginDevice(ip, req.headers['user-agent'] as string, user);
        if (!device && user.activityNotify) {
            let location = await axios.get(`https://ifconfig.net/json?ip=${ip}`, {
                responseType: 'json',
            });

            await emailSender({
                user,
                subject: 'New login location detected',
                file: {
                    name: 'securityAlert',
                    pubkey: true,
                    vars: {
                        username: user.username,
                        country: location?.data?.country
                            ? location?.data?.region_name
                                ? `${location.data.country}, ${location.data.region_name}`
                                : `somewhere in ${location.data.country}`
                            : 'somewhere (no location data)',
                        ip,
                    },
                },
            });
        }
    },
);

router.post(
    '/register',
    rateLimit({
        ipCount: 10,
        keyCount: 10,
    }),
    validate(
        z.object({
            email: z.string().min(5).max(128).email(),
            username: z
                .string()
                .min(3)
                .max(24)
                .regex(/[a-zA-Z0-9._-]{3,24}$/g)
                .optional(),
            password: z.string().min(8).max(128),
            language: z.string().regex(AVAILABLE_LANGUAGES_REGEX).min(1).max(5).optional(),
        }),
    ),
    async (
        req: Request<
            {},
            {},
            {
                email: string;
                username: string;
                password: string;
                language?: string;
            }
        >,
        res: Response,
    ) => {
        if (await prisma.user.count({ where: { email: req.body.email } }))
            return createError(res, 409, {
                code: 'email_taken',
                message: 'This e-mail is already taken',
                param: 'body:email',
                type: 'register',
            });

        if (await prisma.user.count({ where: { username: req.body.username } }))
            return createError(res, 409, {
                code: 'username_taken',
                message: 'This username is already taken',
                param: 'body:username',
                type: 'register',
            });

        if (passwordStrength(req.body.password).id < 2 || req.body.password === req.body.email || req.body.password === req.body.username)
            return createError(res, 400, {
                code: 'weak_password',
                message: 'Provided password is too weak',
                param: 'body:password',
                type: 'register',
            });

        const verificationCode = await getUniqueKey(prisma.user, 'emailVerifyCode', randomString);
        const generatedToken: string = randomString(48);

        const user = await prisma.user.create({
            data: {
                id: await getUniqueKey(prisma.user, 'id', randomString.bind(null, 8)),
                email: req.body.email,
                username: req.body.username,
                password: hashSync(req.body.password, genSaltSync()),
                bio: "Hey, I'm new here!",
                emailVerifyCode: verificationCode,
                language: req.body.language || 'en-US',
                token: encryptWithToken(generatedToken, req.body.password),
                tokenHash: hashSync(generatedToken, genSaltSync()),
            },
        });

        const message = await emailSender({
            user,
            subject: 'Confirm your e-mail to create Nove account',
            file: { name: 'confirmEmail', pubkey: true, vars: { username: user.username, napi: process.env.NAPI_URL, verificationCode } },
        });

        if (!message) return createError(res, 500, { code: 'could_not_send_mail', message: 'Something went wrong while sending an email message', type: 'internal_error' });

        createResponse(res, 200, { ...maskUserMe(user), token: generatedToken });
    },
);

router.get(
    '/verifyEmail',
    rateLimit({
        ipCount: 20,
        keyCount: 20,
    }),
    async (req: Request, res: Response) => {
        const code = req.query.code as string;

        const user = await prisma.user.findFirst({ where: { emailVerifyCode: code } });

        if (!user)
            return createError(res, 404, {
                code: 'invalid_user',
                message: 'User with this email verification code was not found',
                param: 'query:code',
                type: 'validation',
            });

        await prisma.user.update({
            where: { id: user.id },
            data: {
                emailVerifyCode: '',
                verified: true,
            },
        });

        return res.redirect(`${process.env.FRONTEND_URL}/account`);
    },
);

export default router;
