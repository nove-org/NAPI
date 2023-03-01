import { Request, Response, Router } from 'express';

const router = Router();

//! This is just for testing purposes, please change it ASAP to proper error handler

router.get('/error', (req: Request, res: Response) => {
    res.render('error');
});

router.get('/confirmEmail', (req: Request, res: Response) => {
    res.render('confirmEmail');
});

router.get('/register', (req: Request, res: Response) => {
    res.render('register');
});

export default router;
