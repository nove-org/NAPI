import { OAuth_App, OAuth_Authorization, User } from '@prisma/client';
import { NextFunction, Request, Response } from 'express';
import { verifyToken } from 'node-2fa';
import axios from 'axios';
import createError from '../utils/createError';
import { createLoginDevice } from '../utils/createLoginDevice';
import { removeProps } from '../utils/masker';
import { TPermission, checkPermissions } from '../utils/permissions';
import nodemailer from 'nodemailer';
import prisma from '../utils/prisma';
import { Modify } from '../utils/types';

function authorize({
    requiredScopes = [],
    disableBearer = false,
    disableOwner = false,
    requireMfa = false,
}: {
    requiredScopes?: TPermission[];
    disableBearer?: boolean;
    disableOwner?: boolean;
    requireMfa?: boolean;
}) {
    return async (req: Request, res: Response, next: NextFunction) => {
        const [method, token] = req.headers.authorization?.split(' ') || [];
        const mfa = (req.headers['x-mfa'] as string) || '';

        if (!token)
            return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });

        if (method === 'Bearer') {
            if (disableBearer)
                return createError(res, 401, {
                    code: 'invalid_authorization_method',
                    message: 'invalid authorization method',
                    param: 'header:authorization',
                    type: 'authorization',
                });

            const authorization = (await prisma.oAuth_Authorization.findFirst({
                where: {
                    token: token,
                },
                include: {
                    app: true,
                    user: true,
                },
            })) as Modify<
                OAuth_Authorization & {
                    app: OAuth_App;
                    user: User;
                },
                {
                    scopes: TPermission[];
                }
            >;
            if (!authorization)
                return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });
            if (authorization.token_expires < new Date())
                return createError(res, 401, { code: 'expired_authorization_token', message: 'expired authorization token', param: 'header:authorization', type: 'authorization' });
            if (!checkPermissions(authorization.scopes, requiredScopes))
                return createError(res, 403, { code: 'insufficient_permissions', message: 'insufficient permissions', param: 'header:authorization', type: 'authorization' });

            if (requireMfa && (!authorization.user.mfaEnabled || !mfa || !/([0-9]{6})|([a-zA-Z0-9]{16})/.test(mfa)))
                return createError(res, 403, {
                    code: 'mfa_required',
                    message: 'mfa required',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });
            if (requireMfa && !(/([0-9]{6})/.test(mfa) ? verifyToken(authorization.user.mfaSecret, mfa)?.delta !== 0 : authorization.user.mfaRecoveryCodes?.includes(mfa)))
                return createError(res, 403, {
                    code: 'invalid_mfa_token',
                    message: 'invalid mfa token',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });

            if (/([a-zA-Z0-9]{16})/.test(mfa))
                authorization.user = await prisma.user.update({
                    where: {
                        id: authorization.user.id,
                    },
                    data: {
                        mfaRecoveryCodes: {
                            set: authorization.user.mfaRecoveryCodes?.filter((code) => code !== mfa),
                        },
                    },
                });

            req.user = removeProps(authorization.user, ['password', 'token']);
            req.oauth = authorization;

            next();
        } else if (method === 'Owner') {
            let user = await prisma.user.findFirst({
                where: {
                    token: token,
                },
            });

            if (!user)
                return createError(res, 401, { code: 'invalid_authorization_token', message: 'invalid authorization token', param: 'header:authorization', type: 'authorization' });

            if (!user.verified)
                return createError(res, 401, { code: 'verify_email', message: 'this account is not verified', param: 'header:authorization', type: 'authorization' });

            if (requireMfa && (!user.mfaEnabled || !mfa || !/([0-9]{6})|([a-zA-Z0-9]{16})/.test(mfa)))
                return createError(res, 403, {
                    code: 'mfa_required',
                    message: 'mfa required',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });
            if (requireMfa && !(/([0-9]{6})/.test(mfa) ? verifyToken(user.mfaSecret, mfa)?.delta !== 0 : user.mfaRecoveryCodes?.includes(mfa)))
                return createError(res, 403, {
                    code: 'invalid_mfa_token',
                    message: 'invalid mfa token',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });

            if (/([a-zA-Z0-9]{16})/.test(mfa))
                user = await prisma.user.update({
                    where: {
                        id: user.id,
                    },
                    data: {
                        mfaRecoveryCodes: {
                            set: user.mfaRecoveryCodes?.filter((code) => code !== mfa),
                        },
                    },
                });

            req.user = removeProps(user, ['password', 'token']);
            createLoginDevice(req.ip || 'Could not resolve device IP', req.headers['user-agent'] as string, req.user.id, req.user.trackActivity);
            const device = await prisma.trackedDevices.findFirst({ where: { ip: req.ip } });
            if (!device) {
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
                    to: req.user.email,
                    subject: 'New login location detected',
                    html: `<center><img src="https://f.nove.team/newLocation.svg" width="380" height="126" alt="New login location detected"><div style="margin:10px 0;padding:20px;max-width:340px;width:calc(100% - 20px * 2);background:#ededed;border-radius:25px;font-family:sans-serif;user-select:none;text-align:left"><p style="font-size:17px;line-height:1.5;margin:0;margin-bottom:10px;text-align:left">Hello,&nbsp;<b>${req.user.username}</b>. Someone just logged in to your Nove account from&nbsp;<b>${location.data.country}, ${location.data.region_name}</b>&nbsp;(${req.ip}). If that was you, ignore this e-mail. Otherwise, change your password immediately.</p><a style="display:block;width:fit-content;border-radius:50px;padding:5px 9px;font-size:16px;color:#fff;background:#000;text-decoration:none;text-align:left" href="${process.env.FRONTEND_URL}/account/security">Change your password</a></div><p style="max-width:380px;width:380px;text-align:left;font-size:14px;opacity:.7;font-family:sans-serif;user-select:none">We create FOSS privacy-respecting software for everyday use.<a href="${process.env.FRONTEND_URL}" target="_blank">Website</a>,<a href="${process.env.FRONTEND_URL}/privacy" target="_blank">Privacy Policy</a></p></center>`,
                });
            }
            next();
        } else
            return createError(res, 401, { code: 'invalid_authorization_method', message: 'invalid authorization method', param: 'header:authorization', type: 'authorization' });
    };
}

export { authorize };
