import jwt from 'jsonwebtoken';

// Provide development fallbacks to prevent crashes if env is missing
const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';
const JWT_EXPIRE = process.env.JWT_EXPIRE || '1d';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'dev-jwt-refresh-secret';
const JWT_REFRESH_EXPIRE = process.env.JWT_REFRESH_EXPIRE || '7d';

// Generate JWT
export const generateToken = (id) => {
  return jwt.sign({ id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRE,
  });
};

export const generateRefreshToken = (id) => {
  return jwt.sign({ id }, JWT_REFRESH_SECRET, {
    expiresIn: JWT_REFRESH_EXPIRE,
  });
};