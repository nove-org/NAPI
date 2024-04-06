import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { authorize } from '@middleware/auth';
import createResponse from '@util/createResponse';
import { randomString } from '@util/crypto';
import prisma, { getUniqueKey } from '@util/prisma';
import { validate } from '@util/schema';
import { rateLimit } from '@middleware/ratelimit';
import createError from '@util/createError';

const router = Router();

router.get(
    '/authorize',
    rateLimit({
        ipCount: 6000,
        keyCount: 2000,
    }),
    validate(
        z.object({
            client_id: z.string().min(1).max(64),
            redirect_uri: z.string().min(1).max(256).url(),
            response_type: z.string().min(1).max(64),
            scope: z.string().min(1).max(1024),
            state: z.string().min(1).max(256).optional(),
        }),
        'query',
    ),
    async (req: Request, res: Response) => {
        const client = await prisma.oAuth_App.findFirst({
            where: {
                client_id: req.query.client_id?.toString() || '',
            },
        });
        if (!client) return res.status(400).send('invalid client_id');
        if (!client.redirect_uris.includes(req.query.redirect_uri as string))
            return createError(res, 400, { code: 'invalid_redirect_uri', message: 'Invalid redirection URL was provided', param: 'query:redirect_uri', type: 'validation' });
        if (req.query.response_type !== 'code')
            return createError(res, 400, { code: 'invalid_response_type', message: 'Invalid response code was provided', param: 'query:response_type', type: 'validation' });

        res.render('v1/oauth2/authorize', {
            client,
            scope: req.query.scope?.toString().split(' ') || [],
        });
    },
);

router.post(
    '/authorize',
    rateLimit({
        ipCount: 6000,
        keyCount: 2000,
    }),
    authorize({
        disableBearer: true,
    }),
    validate(
        z.object({
            client_id: z.string().min(1).max(64),
            scope: z.string().min(1).max(1024),
        }),
    ),
    async (req: Request, res: Response) => {
        const client = await prisma.oAuth_App.findFirst({
            where: {
                client_id: req.body.client_id?.toString() || '',
            },
        });
        if (!client) return createError(res, 400, { code: 'invalid_client_id', message: 'Invalid client Id was provided', param: 'query:client_id', type: 'validation' });

        const code = await prisma.oAuth_Code.create({
            data: {
                code: await getUniqueKey(prisma.oAuth_Code, 'code', () => randomString(64)),
                app_id: client.client_id,
                scopes: req.body.scope?.toString().split(' ') || [],
                user_id: req.user.id,
            },
        });
        createResponse(res, 200, {
            code: code.code,
        });
    },
);

router.post(
    '/token',
    rateLimit({
        ipCount: 10000,
        keyCount: 5000,
    }),
    validate(
        z.object({
            client_id: z.string().min(1).max(64),
            scope: z.string().min(1).max(1024),
            code: z.string().min(1).max(1024).optional(),
            refresh_token: z.string().min(1).max(1024).optional(),
            redirect_uri: z.string().min(1).max(1024).optional(),
            grant_type: z.string().min(1).max(1024),
            client_secret: z.string().min(1).max(1024),
        }),
        'query',
    ),
    async (req: Request, res: Response) => {
        // * I set TOKEN_LIFETIME for 30 days because I think that's pretty optimal date and allows users to stay signed in for 30 days.
        // * As by this change we can use OAuth2 system properly in our applications.
        // TODO: If a user doesn't want the app to access their data they should be able to revoke app authorization.
        const TOKEN_LIFETIME = 30 * 24 * 60 * 60 * 1000;

        const client = await prisma.oAuth_App.findFirst({
            where: {
                client_id: req.query.client_id?.toString() || '',
            },
        });
        if (!client) return createError(res, 400, { code: 'invalid_client_id', message: 'Invalid client Id was provided', param: 'query:client_id', type: 'validation' });
        if (client.client_secret !== req.query.client_secret?.toString())
            return createError(res, 400, { code: 'invalid_client_id', message: 'Invalid client Id was provided', param: 'query:client_id', type: 'validation' });
        if (!client.redirect_uris.includes(req.query.redirect_uri?.toString() as string))
            return createError(res, 400, { code: 'invalid_redirect_uri', message: 'Invalid redirection URL was provided', param: 'query:redirect_uri', type: 'validation' });
        if (req.query.grant_type?.toString() !== 'authorization_code')
            return createError(res, 400, { code: 'invalid_grant_type', message: 'Invalid grant type was provided', param: 'query:grant_type', type: 'validation' });

        if (req.query.code?.toString()) {
            const code = await prisma.oAuth_Code.findFirst({
                where: {
                    code: req.query.code?.toString() || '',
                },
            });
            if (!code) return createError(res, 400, { code: 'invalid_code', message: 'Invalid code was provided', param: 'query:code', type: 'validation' });
            if (code.app_id !== client.client_id) return createError(res, 400, { code: 'invalid_code', message: 'Invalid code was provided', param: 'query:code', type: 'validation' });
            if (code.scopes.join(' ') !== req.query.scope?.toString())
                return createError(res, 400, { code: 'invalid_scope', message: 'Invalid scope was provided', param: 'query:scope', type: 'validation' });

            const authorization = await prisma.oAuth_Authorization.create({
                data: {
                    user_id: code.user_id,
                    app_id: client.client_id,
                    scopes: code.scopes,
                    redirect_uri: req.query.redirect_uri?.toString() || '',
                    token: randomString(64),
                    token_expires: new Date(Date.now() + TOKEN_LIFETIME),
                    refresh_token: randomString(64),
                },
            });
            await prisma.oAuth_Code.delete({
                where: {
                    code: req.query.code?.toString() || '',
                },
            });

            createResponse(res, 200, {
                access_token: authorization.token,
                token_type: 'Bearer',
                expires_in: authorization.token_expires.getTime() - Date.now(),
                scope: encodeURIComponent(authorization.scopes.join(' ')),
                refresh_token: authorization.refresh_token,
            });
        } else if (req.query.refresh_token?.toString()) {
            let authorization = await prisma.oAuth_Authorization.findFirst({
                where: {
                    refresh_token: req.query.refresh_token?.toString() || '',
                },
            });
            if (!authorization) return createError(res, 400, { code: 'invalid_refresh_token', message: 'Invalid refresh token was provided', param: 'query:refresh_token', type: 'validation' });
            if (authorization.app_id !== client.client_id)
                return createError(res, 400, { code: 'invalid_refresh_token', message: 'Invalid refresh token was provided', param: 'query:refresh_token', type: 'validation' });
            if (authorization.scopes.join(' ') !== req.query.scope?.toString())
                return createError(res, 400, { code: 'invalid_scope', message: 'Invalid scope was provided', param: 'query:scope', type: 'validation' });

            authorization.token = randomString(64);
            authorization.token_expires = new Date(Date.now() + TOKEN_LIFETIME);
            authorization.refresh_token = randomString(64);

            authorization = await prisma.oAuth_Authorization.update({
                where: {
                    id: authorization.id,
                },
                data: {
                    token: randomString(64),
                    token_expires: new Date(Date.now() + TOKEN_LIFETIME),
                    refresh_token: randomString(64),
                },
            });

            createResponse(res, 200, {
                access_token: authorization.token,
                token_type: 'Bearer',
                expires_in: authorization.token_expires.getTime() - Date.now(),
                scope: encodeURIComponent(authorization.scopes.join(' ')),
                refresh_token: authorization.refresh_token,
            });
        } else return createError(res, 400, { code: 'invalid_token', message: 'You have to provide a code orp refresh_token', param: 'query:code', type: 'validation' });
    },
);

export default router;
