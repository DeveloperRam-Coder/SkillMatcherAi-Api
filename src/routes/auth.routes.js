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
    body('name').isString().trim().isLength({ min: 2 }).withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email required'),
    body('password').isStrongPassword({ minLength: 6 }).withMessage('Strong password required'),
    body('role').optional().isIn(['admin', 'candidate', 'interviewer']).withMessage('Invalid role')
  ],
  registerUser
);
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid email required'),
    body('password').isString().isLength({ min: 6 }).withMessage('Password required')
  ],
  loginUser
);
router.get('/me', protect, getCurrentUser);
router.post('/refresh', refreshToken);
router.post('/logout', logoutUser);

export default router;