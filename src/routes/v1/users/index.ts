import { Router } from 'express';
import auth from './auth';
import me from './me/main';
import mfa from './me/mfa';
import passwordReset from './passwordReset';
import emailReset from './emailReset';
import query from './query';

const router = Router();

router.use('/', auth);
router.use('/', passwordReset);
router.use('/', emailReset);
router.use('/', query);
router.use('/me', me);
router.use('/me', mfa);

export default router;
