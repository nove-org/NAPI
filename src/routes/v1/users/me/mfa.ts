import { Request, Response, Router } from 'express';
import { generateSecret, verifyToken } from 'node-2fa';
import { z } from 'zod';
import { authorize } from '@middleware/auth';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import { randomString } from '@util/crypto';
import prisma from '@util/prisma';
import { validate } from '@util/schema';

const router = Router();

router.patch(
    '/mfa',
    validate(
        z.object({
            cancel: z.boolean().optional(),
        }),
        'body'
    ),
    authorize({
        disableBearer: true,
    }),
    async (req: Request, res: Response) => {
        if (req.user.mfaSecret) {
            const mfa = req.headers['x-mfa'] as string;

            if (/[a-zA-Z0-9]{16}/.test(mfa) && req.user.mfaRecoveryCodes?.includes(mfa) && req.user.mfaEnabled) {
                await prisma.user.update({
                    where: { id: req.user.id },
                    data: {
                        mfaEnabled: false,
                        mfaSecret: '',
                        mfaRecoveryCodes: [],
                    },
                });

                return createResponse(res, 200, { message: 'MFA is now disabled', enabled: false });
            }

            if (req.body.cancel && !req.body.mfaEnabled) {
                await prisma.user.update({
                    where: { id: req.user.id },
                    data: {
                        mfaEnabled: false,
                        mfaSecret: '',
                        mfaRecoveryCodes: [],
                    },
                });

                return createResponse(res, 200, { message: 'MFA is now disabled', enabled: false });
            } else if (req.body.cancel)
                return createError(res, 403, {
                    code: 'cannot_cancel',
                    message: 'You cannot cancel setup because it was either not initialized or you already completed it',
                    param: 'body:cancel',
                    type: 'validation',
                });

            if (!mfa || !/[0-9]{6}/.test(mfa))
                return createError(res, 403, {
                    code: 'mfa_required',
                    message: 'mfa required',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });
            if (verifyToken(req.user.mfaSecret, mfa)?.delta !== 0)
                return createError(res, 403, {
                    code: 'invalid_mfa_token',
                    message: 'invalid mfa token',
                    param: 'header:x-mfa',
                    type: 'authorization',
                });

            await prisma.user.update({
                where: { id: req.user.id },
                data: {
                    mfaEnabled: !req.user.mfaEnabled,
                    mfaSecret: req.user.mfaEnabled ? '' : req.user.mfaSecret,
                    mfaRecoveryCodes: req.user.mfaEnabled ? [] : req.user.mfaRecoveryCodes,
                },
            });

            return createResponse(res, 200, { message: `MFA is now ${req.user.mfaEnabled ? 'disabled' : 'enabled'}`, enabled: !req.user.mfaEnabled });
        } else {
            const newSecret = generateSecret({ name: 'Nove Account', account: req.user.username });
            const newCodes = Array.from({ length: 10 }, () => randomString(16));

            await prisma.user.update({
                where: { id: req.user.id },
                data: {
                    mfaEnabled: false,
                    mfaSecret: newSecret.secret,
                    mfaRecoveryCodes: newCodes,
                },
            });

            return createResponse(res, 200, { secret: newSecret, codes: newCodes });
        }
    }
);

router.get(
    '/mfa/securityCodes',
    authorize({
        disableBearer: true,
        requireMfa: true,
    }),
    async (req: Request, res: Response) => {
        createResponse(res, 200, req.user.mfaRecoveryCodes);
    }
);

export default router;
