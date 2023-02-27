import { Router } from 'express';
import v1 from './v1';
import error from './error';

const router = Router();

router.use('/error', error);
router.use('/v1', v1);

export default router;
