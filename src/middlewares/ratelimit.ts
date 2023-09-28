import { Request, Response } from 'express';
import erl, { Options } from 'express-rate-limit';
import createError from '../utils/createError';

// TODO: implement https://www.npmjs.com/package/rate-limit-redis
const DEFAULT_ERL_OPTIONS: Partial<Options> = {
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: (req: Request, res: Response) => {
        createError(res, 429, {
            code: 'rate_limit',
            message: 'too many requests, please try again later',
            type: 'misc',
        });
    },
    skip: (req: Request, res: Response) => (req.user ? req.user.permissionLevel == 2 : false),
};

const keyLimiterGenerator = (req: Request) => req.headers['authorization'] || '';
const ipLimiterGenerator = (req: Request) => req.ip;

const keyLimiter = erl({ keyGenerator: keyLimiterGenerator, ...DEFAULT_ERL_OPTIONS });
const ipLimiter = erl({ keyGenerator: ipLimiterGenerator, ...DEFAULT_ERL_OPTIONS });

export function rateLimit(
    options: Partial<{
        keyCount: number;
        ipCount: number;
        keyTime: number;
        ipTime: number;
    }> = {}
) {
    let out = [keyLimiter, ipLimiter];
    if (options.keyCount || options.keyTime)
        out[0] = erl({
            keyGenerator: keyLimiterGenerator,
            ...DEFAULT_ERL_OPTIONS,
            windowMs: options.keyTime || DEFAULT_ERL_OPTIONS.windowMs,
            max: options.keyCount || DEFAULT_ERL_OPTIONS.max,
        });
    if (options.ipCount || options.ipTime)
        out[1] = erl({
            keyGenerator: ipLimiterGenerator,
            ...DEFAULT_ERL_OPTIONS,
            windowMs: options.ipTime || DEFAULT_ERL_OPTIONS.windowMs,
            max: options.ipCount || DEFAULT_ERL_OPTIONS.max,
        });
    return out;
}
