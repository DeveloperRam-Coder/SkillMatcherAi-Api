import express from 'express';
import { body } from 'express-validator';
import {
  registerUser,
  loginUser,
  getCurrentUser,
  refreshToken,
  logoutUser,
} from '../controllers/auth.controller.js';
import { protect } from '../middlewares/auth.middleware.js';

const router = express.Router();

router.post(
  '/register',
  [
    body('name').optional().isString().trim(),
    body('email').isEmail().withMessage('Valid email required'),
    body('password').isString().isLength({ min: 1 }).withMessage('Password is required'),
    body('role').optional().isString()
  ],
  registerUser
);
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid email required'),
    body('password').isString().withMessage('Password required')
  ],
  loginUser
);
router.get('/me', protect, getCurrentUser);
router.post('/refresh', refreshToken);
router.post('/logout', logoutUser);

export default router;