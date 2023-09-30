import { compareSync, genSaltSync, hashSync } from 'bcrypt';
import { passwordStrength } from 'check-password-strength';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import nodemailer from 'nodemailer';
import { AVAILABLE_LANGUAGES_REGEX } from '@util/CONSTS';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import { randomString } from '@util/crypto';
import { getUniqueKey } from '@util/prisma';
import prisma, { maskUserMe } from '@util/prisma';
import { validate } from '@util/schema';
import axios from 'axios';
import { createLoginDevice } from '@util/createLoginDevice';
import { rateLimit } from '@middleware/ratelimit';

const router = Router();

router.post(
    '/login',
    rateLimit({
        ipCount: 25,
        keyCount: 40,
    }),
    validate(
        z.object({
            username: z.string().min(1).max(64),
            password: z.string().min(1).max(128),
        })
    ),
    async (req: Request, res: Response) => {
        const user = await prisma.user.findFirst({
            where: {
                OR: [{ username: req.body.username }, { email: req.body.username }],
            },
        });
        if (!user)
            return createError(res, 404, {
                code: 'user_not_found',
                message: 'user with this username was not found',
                param: 'body:username',
                type: 'authorization',
            });
        if (!compareSync(req.body.password, user.password))
            return createError(res, 401, { code: 'invalid_password', message: 'invalid password', param: 'body:password', type: 'authorization' });

        createResponse(res, 200, maskUserMe(user, true));

        const device = await prisma.trackedDevices.findFirst({ where: { ip: req.ip } });
        if (!device) {
            createLoginDevice(req.ip || 'Could not resolve device IP', req.headers['user-agent'] as string, user.id, user.trackActivity);

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

            let location = await axios.get(`https://ifconfig.net/json?ip=${req.ip}`, {
                responseType: 'json',
            });

            await transporter.sendMail({
                from: process.env.MAIL_USERNAME,
                to: user.email,
                subject: 'New login location detected',
                html: `<center><img src="https://f.nove.team/newLocation.svg" width="380" height="126" alt="New login location detected"><div style="margin:10px 0;padding:20px;max-width:340px;width:calc(100% - 20px * 2);background:#ededed;border-radius:25px;font-family:sans-serif;user-select:none;text-align:left"><p style="font-size:17px;line-height:1.5;margin:0;margin-bottom:10px;text-align:left">Hello,&nbsp;<b>${
                    user.username
                }</b>. Someone just logged in to your Nove account from&nbsp;<b>${
                    location.data.country + (location.data.region_name ? `, ${location.data.region_name}` : '')
                }</b>&nbsp;(${
                    req.ip
                }). If that was you, ignore this e-mail. Otherwise, change your password immediately.</p><a style="display:block;width:fit-content;border-radius:50px;padding:5px 9px;font-size:16px;color:#fff;background:#000;text-decoration:none;text-align:left" href="${
                    process.env.FRONTEND_URL
                }/account/security">Change your password</a></div><p style="max-width:380px;width:380px;text-align:left;font-size:14px;opacity:.7;font-family:sans-serif;user-select:none">We create FOSS privacy-respecting software for everyday use.<a href="${
                    process.env.FRONTEND_URL
                }" target="_blank">Website</a>,<a href="${process.env.FRONTEND_URL}/privacy" target="_blank">Privacy Policy</a></p></center>`,
            });
        }
    }
);

router.post(
    '/register',
    rateLimit({
        ipCount: 10,
        keyCount: 15,
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
        })
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
        res: Response
    ) => {
        if (await prisma.user.count({ where: { email: req.body.email } }))
            return createError(res, 409, {
                code: 'email_already_exists',
                message: 'email already exists',
                param: 'body:email',
                type: 'register',
            });

        if (await prisma.user.count({ where: { username: req.body.username } }))
            return createError(res, 409, {
                code: 'username_already_exists',
                message: 'username already exists',
                param: 'body:username',
                type: 'register',
            });

        if (passwordStrength(req.body.password).id < 2 || req.body.password === req.body.email || req.body.password === req.body.username)
            return createError(res, 400, {
                code: 'weak_password',
                message: 'password is too weak',
                param: 'body:password',
                type: 'register',
            });

        const verificationCode = await getUniqueKey(prisma.user, 'emailVerifyCode', randomString);

        const user = await prisma.user.create({
            data: {
                id: await getUniqueKey(prisma.user, 'id', randomString.bind(null, 8)),
                email: req.body.email,
                username: req.body.username,
                password: hashSync(req.body.password, genSaltSync()),
                bio: "Hey, I'm new here!",
                emailVerifyCode: verificationCode,
                language: req.body.language || 'en',
                token: randomString(48),
            },
        });
        createResponse(res, 200, maskUserMe(user, true));

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
            subject: 'Confirm your e-mail to create Nove account',
            html: `<center><img src="https://f.nove.team/confirmEmail.svg" width="380" height="126" alt="Confirm your e-mail to create new Nove account"><div style="margin:10px 0;padding:20px;max-width:340px;width:calc(100% - 20px * 2);background:#ededed;border-radius:25px;font-family:sans-serif;user-select:none;text-align:left"><p style="font-size:17px;line-height:1.5;margin:0;margin-bottom:10px;text-align:left">Hello,&nbsp;<b>${user.username}</b>. Your e-mail address has been provided while creating a new Nove account. In order to confirm that request, please click the "Approve" button. If that wasn't you, just ignore this e-mail.</p><a style="display:block;width:fit-content;border-radius:50px;padding:5px 9px;font-size:16px;color:#fff;background:#000;text-decoration:none;text-align:left" href="${process.env.NAPI_URL}/v1/users/verifyEmail?code=${verificationCode}">Approve</a></div><p style="max-width:380px;width:380px;text-align:left;font-size:14px;opacity:.7;font-family:sans-serif;user-select:none">We create FOSS privacy-respecting software for everyday use.<a href="${process.env.FRONTEND_URL}" target="_blank">Website</a>,<a href="${process.env.FRONTEND_URL}/privacy" target="_blank">Privacy Policy</a></p></center>`,
        });
    }
);

router.get(
    '/verifyEmail',
    rateLimit({
        ipCount: 2,
        keyCount: 3,
    }),
    async (req: Request, res: Response) => {
        const code = req.query.code as string;

        const user = await prisma.user.findFirst({ where: { emailVerifyCode: code } });

        if (!user)
            return createError(res, 404, {
                code: 'user_not_found',
                message: 'user with this email verification code was not found',
                param: 'query:code',
                type: 'authorization',
            });

        await prisma.user.update({
            where: { id: user.id },
            data: {
                emailVerifyCode: '',
                verified: true,
            },
        });

        return res.redirect(`${process.env.FRONTEND_URL}/account`);
    }
);

export default router;
