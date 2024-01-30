import { OAuth_App, Prisma } from '@prisma/client';
import { Request, Response, Router } from 'express';
import { z } from 'zod';
import { compareSync } from 'bcrypt';
import { authorize } from '@middleware/auth';
import { AVAILABLE_LANGUAGES_REGEX } from '@util/CONSTS';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import { removeProps } from '@util/masker';
import { multerUploadSingle } from '@util/multipart';
import prisma, { maskUserMe, maskUserOAuth } from '@util/prisma';
import { validate } from '@util/schema';
import { getAvatarCode } from '@util/getAvatarCode';
import { decryptWithToken } from '@util/tokenEncryption';

const router = Router();

router.get(
    '/me',
    // rateLimit({
    //     ipCount: 500,
    //     keyCount: 800,
    // }),
    authorize({ requiredScopes: ['account.read.basic'] }),
    async (req: Request, res: Response) => {
        const updatedAtCode = getAvatarCode(new Date(req.user.updatedAt));

        const user = { avatar: `${process.env.NAPI_URL}/v1/users/${req.user.id}/avatar.webp?v=${updatedAtCode}`, ...req.user };

        if (req.oauth) return createResponse(res, 200, maskUserOAuth(user, req.oauth));
        else createResponse(res, 200, maskUserMe(user));
    }
);

router.patch(
    '/me',
    // rateLimit({
    //     ipCount: 75,
    //     keyCount: 100,
    // }),
    validate(
        z.object({
            username: z
                .string()
                .min(3)
                .max(24)
                .regex(/[a-zA-Z0-9._-]{3,24}$/g)
                .optional(),
            bio: z.string().min(1).max(256).optional(),
            language: z.string().regex(AVAILABLE_LANGUAGES_REGEX).optional(),
            trackActivity: z.boolean().optional(),
            profilePublic: z.boolean().optional(),
            activityNotify: z.boolean().optional(),
            pubkey: z.string().min(1).optional(),
        }),
        'body'
    ),
    authorize({ disableBearer: true }),
    async (req: Request, res: Response) => {
        let data: Prisma.XOR<Prisma.UserUpdateInput, Prisma.UserUncheckedUpdateInput> = {};

        if (req.body.bio?.length) data['bio'] = req.body.bio;
        if (req.body.pubkey?.length) {
            const pubkey = req.body.pubkey as string;

            if (!(pubkey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----\n') && pubkey.endsWith('\n-----END PGP PUBLIC KEY BLOCK-----')) && pubkey !== 'false')
                return createError(res, 403, { code: 'invalid_pgp_key', message: 'Please provide a valid PGP key', param: 'body:pubkey', type: 'validation' });

            data['pubkey'] = pubkey !== 'false' ? req.body.pubkey : '';
        }
        if (req.body.username?.length) {
            const user = await prisma.user.findFirst({ where: { username: req.body.username } });

            if (user) return createError(res, 409, { code: 'username_taken', message: 'This username is already taken', param: 'body:username', type: 'validation' });

            data['username'] = req.body.username;
        }
        if (req.body.language?.length) data['language'] = req.body.language;
        if (typeof req.body.trackActivity === 'boolean') {
            data['trackActivity'] = req.body.trackActivity;

            await prisma.trackedDevices.deleteMany({ where: { userId: req.user.id } });
        }
        if (typeof req.body.activityNotify === 'boolean') data['activityNotify'] = req.body.activityNotify;
        if (typeof req.body.profilePublic === 'boolean') data['profilePublic'] = req.body.profilePublic;

        const newUser = await prisma.user.update({
            where: { id: req.user.id },
            data,
        });

        return createResponse(res, 200, maskUserMe(newUser));
    }
);

router.patch(
    '/me/avatar',
    // rateLimit({
    //     ipCount: 50,
    //     keyCount: 75,
    // }),
    authorize({ disableBearer: true }),
    multerUploadSingle(),
    validate(z.object({ file: z.any() })),
    async (req: Request, res: Response) => {
        const file = req.file as Express.Multer.File;

        if (!file)
            return createError(res, 400, {
                code: 'invalid_parameter',
                message: 'You have to send a valid image file',
                param: 'body:avatar',
                type: 'validation',
            });

        const newUser = await prisma.user.update({ where: { id: req.user.id }, data: { updatedAt: new Date() } });

        return createResponse(res, 200, maskUserMe(newUser));
    }
);

router.get(
    '/me/activity',
    // rateLimit({
    //     ipCount: 100,
    //     keyCount: 150,
    // }),
    authorize({ disableBearer: true }),
    async (req: Request, res: Response) => {
        if (!(await prisma.user.findFirst({ where: { id: req.user.id } }))?.trackActivity)
            return createError(res, 403, {
                code: 'activity_disabled',
                message: 'Account activity is disabled',
                type: 'request',
            });

        let perPage = Math.abs(parseInt(req.query.perPage as string)) || 10;
        if (perPage > 25 || perPage < 1) perPage = 3;

        const devices = await prisma.trackedDevices.findMany({
            where: {
                userId: req.user.id,
            },
            skip: req.query.page ? parseInt(req.query.page.toString()) * perPage : 0,
            take: perPage,
            orderBy: {
                updatedAt: 'desc',
            },
        });

        const decryptionToken: string = (req.headers['authorization'] as string).split(' ')[1];

        devices.map((dev, i) => {
            devices[i].ip = decryptWithToken(dev.ip, decryptionToken);
            devices[i].device = decryptWithToken(dev.device, decryptionToken);
            devices[i].os_name = decryptWithToken(dev.os_name, decryptionToken);
            devices[i].os_version = decryptWithToken(dev.os_version, decryptionToken);
        });

        createResponse(res, 200, devices);
    }
);

router.get(
    '/me/connections',
    // rateLimit({
    //     ipCount: 100,
    //     keyCount: 150,
    // }),
    authorize({ disableBearer: true }),
    async (req: Request, res: Response) => {
        const oauth2 = await prisma.oAuth_Authorization.findMany({ where: { user_id: req.user.id }, include: { app: true } });
        const apps: OAuth_App[] = [];

        createResponse(
            res,
            200,
            oauth2.map((x) => removeProps(x, ['token', 'refresh_token', 'app.client_secret']))
        );
    }
);

router.post(
    '/me/delete',
    // rateLimit({
    //     ipCount: 3,
    //     keyCount: 5,
    // }),
    validate(z.object({ password: z.string().min(1).max(128) })),
    authorize({ disableBearer: true, checkMfaCode: true }),
    async (req: Request, res: Response) => {
        const { password } = req.body;

        const user = await prisma.user.findFirst({ where: { id: req.user.id } });

        if (!user) return createError(res, 404, { code: 'invalid_user', message: 'This user does not exist', type: 'authorization' });

        if (!compareSync(password, user.password))
            return createError(res, 401, { code: 'invalid_password', message: 'Invalid password was provided', param: 'body:password', type: 'validation' });

        await prisma.user.delete({ where: { id: user.id } });

        createResponse(res, 200, { success: true });
    }
);

export default router;
