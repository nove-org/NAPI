import { Request, Response, Router } from 'express';

const router = Router();

//! This is just for testing purposes, please change it ASAP to proper error handler

router.get('/', (req: Request, res: Response) => {
    res.render('error');
});

export default router;
