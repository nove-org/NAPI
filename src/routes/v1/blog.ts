import { authorize } from '@middleware/auth';
import { authorizeAdmin } from '@middleware/authAdmin';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import prisma from '@util/prisma';
import { validate } from '@util/schema';
import { Request, Response, Router } from 'express';
import { getAvatarCode } from '@util/getAvatarCode';
import { z } from 'zod';

const router = Router();

router.post('/create', authorize({ disableBearer: true }), authorizeAdmin, validate(z.object({ text: z.string(), title: z.string() })), async (req: Request, res: Response) => {
    const newPost = await prisma.blogPost.create({
        data: {
            authorId: req.user.id,
            text: req.body.text,
            title: req.body.title,
        },
    });

    return createResponse(res, 200, newPost);
});

router.patch(
    '/:id',
    authorize({ disableBearer: true }),
    authorizeAdmin,
    validate(
        z.object({
            text: z.string().optional(),
            title: z.string().optional(),
            allow_comments: z.boolean().optional(),
        })
    ),
    async (req: Request, res: Response) => {
        const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

        if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', type: 'validation', param: 'id' });

        const updatedPost = await prisma.blogPost.update({
            where: { id: post.id },
            data: {
                text: req.body.text ? req.body.text : post.text,
                title: req.body.title ? req.body.title : post.title,
                commentsAllowed: typeof req.body?.allow_comments === 'boolean' ? req.body.allow_comments : post.commentsAllowed,
            },
        });

        return createResponse(res, 200, updatedPost);
    }
);

router.get('/:id/', async (req: Request, res: Response) => {
    const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

    if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', type: 'validation', param: 'id' });

    return createResponse(res, 200, post);
});

router.get('/', async (req: Request, res: Response) => {
    const posts = await prisma.blogPost.findMany();

    return createResponse(res, 200, posts);
});

router.delete('/:id', authorize({ disableBearer: true }), authorizeAdmin, async (req: Request, res: Response) => {
    const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

    if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', type: 'validation', param: 'id' });

    await prisma.blogPost.delete({ where: { id: post.id } });

    await prisma.blogComment.deleteMany({ where: { blogPostId: post.id } });

    return createResponse(res, 200, { success: true });
});

router.post('/:id/comment', authorize({ disableBearer: true }), validate(z.object({ text: z.string().min(2).max(400) })), async (req: Request, res: Response) => {
    const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

    if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', type: 'validation', param: 'id' });

    const updatedAtCode = getAvatarCode(new Date(req.user.updatedAt));

    const comment = await prisma.blogComment.create({
        data: {
            authorId: req.user.id,
            authorUsername: req.user.username,
            authorAvatar: `${process.env.NAPI_URL}/v1/users/${req.user.id}/avatar.webp?v=${updatedAtCode}`,
            text: req.body.text,
            blogPostId: post.id,
        },
    });

    return createResponse(res, 200, comment);
});

router.patch('/:id/comment/:comment_id', authorize({ disableBearer: true }), validate(z.object({ text: z.string().min(2).max(400) })), async (req: Request, res: Response) => {
    const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

    if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', type: 'validation', param: 'id' });

    const comment = await prisma.blogComment.findFirst({ where: { blogPostId: post.id, id: req.params.comment_id } });

    if (!comment) return createError(res, 404, { code: 'invalid_comment', message: 'this comment does not exist', type: 'validation', param: 'comment_id' });

    if (comment.authorId !== req.user.id) return createError(res, 401, { code: 'insufficient_permissions', message: 'you can only edit your comments', type: 'validation' });

    const newComment = await prisma.blogComment.update({ where: { id: comment.id }, data: { text: req.body.text } });

    return createResponse(res, 200, newComment);
});

router.delete('/:id/comment/:comment_id', authorize({ disableBearer: true }), async (req: Request, res: Response) => {
    const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

    if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', type: 'validation', param: 'id' });

    const comment = await prisma.blogComment.findFirst({ where: { blogPostId: post.id, id: req.params.comment_id } });

    if (!comment) return createError(res, 404, { code: 'invalid_comment', message: 'this comment does not exist', type: 'validation', param: 'comment_id' });

    if (comment.authorId !== req.user.id && req.user.permissionLevel !== 2)
        return createError(res, 401, { code: 'insufficient_permissions', message: 'you can only delete your comments', type: 'validation' });

    await prisma.blogComment.delete({ where: { id: req.body.comment_id } });

    return createResponse(res, 200, { success: true });
});

export default router;
