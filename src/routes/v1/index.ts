import { Request, Response, Router } from 'express';
import oauth2 from './oauth2';
import users from './users';
import admin from './admin';
import createResponse from '@util/createResponse';
import { AVAILABLE_LANGUAGES } from '@util/CONSTS';

const router = Router();

router.use('/oauth2', oauth2);
router.use('/users', users);
router.use('/admin', admin);
router.get('/languages', (_req: Request, res: Response) => {
    return createResponse(res, 200, { AVAILABLE_LANGUAGES });
});

export default router;
