import { Router } from 'express';
import oauth2 from './oauth2';
import users from './users';

const router = Router();

router.use('/oauth2', oauth2);
router.use('/users', users);

export default router;
