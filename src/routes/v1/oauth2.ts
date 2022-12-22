import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { authorizeOwner } from '../../middlewares/auth';
import createResponse from '../../utils/createResponse';
import { randomString } from '../../utils/crypto';
import prisma, { getUniqueKey } from '../../utils/prisma';
import { validate } from '../../utils/schema';

const router = Router();

router.get(
    '/authorize',
    // TODO: visually pleasing error page
    validate(
        z.object({
            client_id: z.string().min(1).max(64),
            redirect_uri: z.string().min(1).max(256).url(),
            response_type: z.string().min(1).max(64),
            scope: z.string().min(1).max(1024),
            state: z.string().min(1).max(256).optional(),
        }),
        'query'
    ),
    async (req: Request, res: Response) => {
        const client = await prisma.oAuth_App.findFirst({
            where: {
                client_id: req.query.client_id?.toString() || '',
            },
        });
        // TODO: visually pleasing error page
        if (!client) return res.status(400).send('invalid client_id');

        res.render('v1/oauth2/authorize', {
            client,
            scope: req.query.scope?.toString().split(' ') || [],
        });
    }
);

// (todo for both routes below)
// TODO: better error formats
// TODO: figure out proper length for client_id, client_secret, etc.
// TODO: figure out a safe length for code, token, etc.
// TODO: figure out proper expiration time for token

router.post(
    '/authorize',
    authorizeOwner,
    validate(
        z.object({
            client_id: z.string().min(1).max(64),
            scope: z.string().min(1).max(1024),
        })
    ),
    async (req: Request, res: Response) => {
        const client = await prisma.oAuth_App.findFirst({
            where: {
                client_id: req.body.client_id?.toString() || '',
            },
        });
        // TODO: visually pleasing error page
        if (!client) return res.status(400).send('invalid client_id');

        const code = await prisma.oAuth_Code.create({
            data: {
                code: await getUniqueKey(prisma.oAuth_Code, 'code', () => randomString(64)),
                app_id: client.client_id,
                scopes: req.body.scope?.toString().split(' ') || [],
                user_id: req.user.id,
            },
        });
        console.log(code);
        createResponse(res, 200, {
            code: code.code,
        });
    }
);

router.post(
    '/token',
    validate(
        z.object({
            client_id: z.string().min(1).max(64),
            scope: z.string().min(1).max(1024),
            code: z.string().min(1).max(1024),
            redirect_uri: z.string().min(1).max(1024),
            grant_type: z.string().min(1).max(1024),
            client_secret: z.string().min(1).max(1024),
        }),
        'query'
    ),
    async (req: Request, res: Response) => {
        const client = await prisma.oAuth_App.findFirst({
            where: {
                client_id: req.body.client_id?.toString() || '',
            },
        });
        if (!client) return res.status(400).send('invalid client_id');
        if (client.client_secret !== req.query.client_secret?.toString()) return res.status(400).send('invalid client_id');
        if (!client.redirect_uris.includes(req.query.redirect_uri?.toString() as string)) return res.status(400).send('invalid redirect_uri');
        if (req.query.grant_type?.toString() !== 'authorization_code') return res.status(400).send('invalid grant_type');

        const code = await prisma.oAuth_Code.findFirst({
            where: {
                code: req.query.code?.toString() || '',
            },
        });
        if (!code) return res.status(400).send('invalid code');
        if (code.app_id !== client.client_id) return res.status(400).send('invalid code');
        if (code.scopes.join(' ') !== req.query.scope?.toString()) return res.status(400).send('invalid scope');

        const authorization = await prisma.oAuth_Authorization.create({
            data: {
                user_id: code.user_id,
                app_id: client.client_id,
                scopes: code.scopes,
                redirect_uri: req.query.redirect_uri?.toString() || '',
                token: randomString(64),
                token_expires: new Date(Date.now() + 3600 * 1000),
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
    }
);

export default router;
