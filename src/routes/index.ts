import { Router } from 'express';
import v1 from './v1';
import error from './error';

const router = Router();

router.use('/v1', v1);

//! This is just for testing purposes, please change it ASAP to proper error handler
router.use('/error', error);

export default router;
