import { Router } from 'express';
import auth from './auth';
import me from './me';
import passwordReset from './passwordReset';
import query from './query';

const router = Router();

router.use('/', auth);
router.use('/', me);
router.use('/', passwordReset);
router.use('/', query);

export default router;
