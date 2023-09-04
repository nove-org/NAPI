import { Request, Response, Router } from 'express';
import oauth2 from './oauth2';
import users from './users';
import createResponse from 'utils/createResponse';
import { AVAILABLE_LANGUAGES } from 'utils/CONSTS';

const router = Router();

router.use('/oauth2', oauth2);
router.use('/users', users);
router.get('/languages', (_req: Request, res: Response) => {
    return createResponse(res, 200, { AVAILABLE_LANGUAGES });
});

export default router;
