import { Router } from 'express';
import v1 from './v1';
import localStorage from './localStorage';

const router = Router();

router.use('/v1', v1);
router.use('/ls', localStorage); //! hotfix for not accessible localStorage

export default router;
