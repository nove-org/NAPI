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

                let location = await axios.get(`https://ifconfig.net/json?ip=${req.ip}`, {
                    responseType: 'json',
                });

                await transporter.sendMail({
                    from: 'noreply@nove.team',
                    to: req.user.email,
                    subject: 'New login location detected',
                    html: `<html style="width: 100%">
                        <body style="margin: 0 auto; max-width: 340px; box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.3); background: #e4e4e4">
                            <header style="display: flex; align-items: center; font-weight: 700; width: calc(100%-60px); padding: 20px 30px; border-bottom: 1px solid #c4c4c4">
                                <img style="margin-right: 5px" src="https://f.nove.team/assets/nove.png" width="20" height="20" />
                                Nove Group
                            </header>
                    
                            <h1 style="padding: 0 30px">New login location detected</h1>
                            <p style="padding: 0 30px; font-size: 20px; line-height: 1.5; margin: 0; margin-bottom: 40px">
                                Hello, ${req.user.username}. Someone tried to log in to your account from ${location.data.country}, ${location.data.region_name} (${req.ip}). That request has been blocked. In order to add this address to whitelist
                                click "Reset password" button. If that wasn't you, change your credentials immediately.
                            </p>
                            <a style="margin: 0 30px; padding: 10px 15px; border-radius: 5px; font-size: 16px; border: 1px solid indianred; color: black; text-decoration: none" href="https://nove.team/account/security">Reset password</a>
                        </body>
                    </html>
                    `,
                });
            }
            next();
        } else
            return createError(res, 401, { code: 'invalid_authorization_method', message: 'invalid authorization method', param: 'header:authorization', type: 'authorization' });
    };
}

export { authorize };
