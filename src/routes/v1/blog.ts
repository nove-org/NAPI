import { authorize } from '@middleware/auth';
import { authorizeAdmin } from '@middleware/authAdmin';
import createError from '@util/createError';
import createResponse from '@util/createResponse';
import prisma from '@util/prisma';
import { validate } from '@util/schema';
import { Request, Response, Router } from 'express';
import { getAvatarCode } from '@util/getAvatarCode';
import { rateLimit } from '@middleware/ratelimit';
import { z } from 'zod';
import { BlogComment, BlogPost, User } from '@prisma/client';

const router = Router();

interface CommentAuthor extends BlogComment {
    authorUsername: string;
    authorAvatar: string;
}

interface PostAuthor extends BlogPost {
    authorUsername: string;
    authorAvatar: string;
}

router.get(
    '/',
    rateLimit({
        ipCount: 250,
        keyCount: 100,
    }),
    async (req: Request, res: Response) => {
        const prismaPosts = await prisma.blogPost.findMany();

        let posts: PostAuthor[] = [];

        for (const element of prismaPosts) {
            const postUser = await prisma.user.findUnique({ where: { id: element.authorId } });

            if (!postUser) return;

            posts.push({
                authorUsername: postUser.username,
                authorAvatar: `${process.env.NAPI_URL}/v1/users/${postUser.id}/avatar.webp`,
                ...element,
            });
        }

        return createResponse(res, 200, posts);
    }
);

router.post('/create', authorize({ disableBearer: true }), authorizeAdmin, validate(z.object({ text: z.string(), title: z.string() })), async (req: Request, res: Response) => {
    const updatedAtCode = getAvatarCode(new Date(req.user.updatedAt));

    const newPost = await prisma.blogPost.create({
        data: {
            authorId: req.user.id,
            text: req.body.text,
            title: req.body.title,
        },
    });

    return createResponse(res, 200, newPost);
});

router.get(
    '/:id',
    rateLimit({
        ipCount: 200,
        keyCount: 100,
    }),
    async (req: Request, res: Response) => {
        const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

        if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', param: 'params:id', type: 'validation' });

        const user = await prisma.user.findUnique({ where: { id: post.authorId } });

        if (!user) return createError(res, 404, { code: 'invalid_post', message: 'User that posted this does not exist anymore', param: 'params:id', type: 'validation' });

        const prismaComments = await prisma.blogComment.findMany({ where: { blogPostId: post.id } });

        let comments: CommentAuthor[] = [];

        for (const element of prismaComments) {
            const commentUser = await prisma.user.findUnique({ where: { id: element.authorId } });

            if (!commentUser) return;

            comments.push({
                authorUsername: commentUser.username,
                authorAvatar: `${process.env.NAPI_URL}/v1/users/${commentUser.id}/avatar.webp`,
                ...element,
            });
        }

        return createResponse(res, 200, {
            authorUsername: user.username,
            authorAvatar: `${process.env.NAPI_URL}/v1/users/${user.id}/avatar.webp`,
            comments,
            ...post,
        });
    }
);

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

        if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', param: 'params:id', type: 'validation' });

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

router.delete('/:id', authorize({ disableBearer: true }), authorizeAdmin, async (req: Request, res: Response) => {
    const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

    if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', param: 'params:id', type: 'validation' });

    await prisma.blogPost.delete({ where: { id: post.id } });

    await prisma.blogComment.deleteMany({ where: { blogPostId: post.id } });

    return createResponse(res, 200, { success: true });
});

router.post(
    '/:id/comment',
    rateLimit({
        ipCount: 3,
        keyCount: 3,
    }),
    authorize({ disableBearer: true }),
    validate(z.object({ text: z.string().min(2).max(400) })),
    async (req: Request, res: Response) => {
        const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

        if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', param: 'params:id', type: 'validation' });

        const comment = await prisma.blogComment.create({
            data: {
                authorId: req.user.id,
                text: req.body.text,
                blogPostId: post.id,
            },
        });

        return createResponse(res, 200, comment);
    }
);

router.patch(
    '/:id/comment/:comment_id',
    rateLimit({
        ipCount: 100,
        keyCount: 100,
    }),
    authorize({ disableBearer: true }),
    validate(z.object({ text: z.string().min(2).max(400) })),
    async (req: Request, res: Response) => {
        const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

        if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', param: 'params:id', type: 'validation' });

        const comment = await prisma.blogComment.findFirst({ where: { blogPostId: post.id, id: req.params.comment_id } });

        if (!comment) return createError(res, 404, { code: 'invalid_comment', message: 'This comment does not exist', param: 'params:comment_id', type: 'validation' });

        if (comment.authorId !== req.user.id) return createError(res, 403, { code: 'insufficient_permissions', message: 'You can only edit your comments', type: 'validation' });

        const newComment = await prisma.blogComment.update({ where: { id: comment.id }, data: { text: req.body.text } });

        return createResponse(res, 200, newComment);
    }
);

router.delete(
    '/:id/comment/:comment_id',
    rateLimit({
        ipCount: 100,
        keyCount: 100,
    }),
    authorize({ disableBearer: true }),
    async (req: Request, res: Response) => {
        const post = await prisma.blogPost.findUnique({ where: { id: req.params.id } });

        if (!post) return createError(res, 404, { code: 'invalid_post', message: 'This post does not exist', param: 'params:id', type: 'validation' });

        const comment = await prisma.blogComment.findFirst({ where: { blogPostId: post.id, id: req.params.comment_id } });

        if (!comment) return createError(res, 404, { code: 'invalid_comment', message: 'This comment does not exist', param: 'params:comment_id', type: 'validation' });

        if (comment.authorId !== req.user.id && req.user.permissionLevel !== 2)
            return createError(res, 403, { code: 'insufficient_permissions', message: 'You can only delete your comments', type: 'validation' });

        await prisma.blogComment.delete({ where: { id: req.params.comment_id } });

        return createResponse(res, 200, { success: true });
    }
);

export default router;
