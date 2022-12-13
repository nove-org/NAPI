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

export default router;
