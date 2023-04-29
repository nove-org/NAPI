//! hotfix for not accessible localStorage

import { Request, Response, Router } from 'express';
const router = Router();

router.get('/', (req: Request, res: Response) => {
    res.render('ls');
});

export default router;
