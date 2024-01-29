import { Router } from 'express';
import auth from './auth';
import me from './me';
import mfa from './mfa';
import passwordReset from './passwordReset';
import emailReset from './emailReset';
import query from './query';

const router = Router();

router.use('/', auth);
router.use('/', passwordReset);
router.use('/', emailReset);
router.use('/', me);
router.use('/', mfa);
router.use('/', query);

export default router;
