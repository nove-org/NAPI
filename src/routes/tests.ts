import { Request, Response, Router } from 'express';

const router = Router();

//! This is just for testing purposes, please change it ASAP to proper error handler

router.get('/error', (req: Request, res: Response) => {
    res.render('error');
});

router.get('/confirmEmail', (req: Request, res: Response) => {
    res.render('confirmEmail');
});

router.get('/emailRecovery', (req: Request, res: Response) => {
    res.render('emailRecovery');
});

router.get('/register', (req: Request, res: Response) => {
    res.render('register');
});

router.get('/passwordReset', (req: Request, res: Response) => {
    res.render('passwordReset');
});

export default router;
