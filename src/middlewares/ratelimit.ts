import { Request, Response } from 'express';
import { RATELIMIT_IP_WHITELIST } from '@util/CONSTS';
import erl, { Options } from 'express-rate-limit';
import createError from '@util/createError';
import { randomString } from '@util/crypto';

// TODO: implement https://www.npmjs.com/package/rate-limit-redis
const DEFAULT_ERL_OPTIONS: Partial<Options> = {
    windowMs: 10 * 60 * 1000,
    limit: 500,
    standardHeaders: true,
    legacyHeaders: false,
    message: (req: Request, res: Response) => {
        createError(res, 429, {
            code: 'rate_limit',
            message: 'Too many requests, please try again later.',
            type: 'misc',
        });
    },
    // TODO: fix permissionLevel check (req.user is always undefined)
    skip: (req: Request, res: Response) => (req.user ? req.user.permissionLevel == 2 : false),
};

const keyLimiterGenerator = (req: Request) => req.headers['authorization']?.split(' ')[1] || (RATELIMIT_IP_WHITELIST.includes(req.ip as string) ? randomString(48) : (req.ip as string));
const ipLimiterGenerator = (req: Request) => (RATELIMIT_IP_WHITELIST.includes(req.ip as string) ? randomString(48) : (req.ip as string));

export function rateLimit(
    options: Partial<{
        keyCount: number;
        ipCount: number;
        keyTime: number;
        ipTime: number;
    }> = {},
) {
    let out = [];
    if (options.keyCount || options.keyTime)
        out[0] = erl({
            keyGenerator: keyLimiterGenerator,
            ...DEFAULT_ERL_OPTIONS,
            windowMs: options.keyTime || DEFAULT_ERL_OPTIONS.windowMs,
            limit: options.keyCount || DEFAULT_ERL_OPTIONS.limit,
        });
    if (options.ipCount || options.ipTime)
        out[1] = erl({
            keyGenerator: ipLimiterGenerator,
            ...DEFAULT_ERL_OPTIONS,
            windowMs: options.ipTime || DEFAULT_ERL_OPTIONS.windowMs,
            limit: options.ipCount || DEFAULT_ERL_OPTIONS.limit,
        });

    return out;
}
