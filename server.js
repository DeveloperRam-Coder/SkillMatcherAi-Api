import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import morgan from 'morgan';
import { connectDB } from './src/config/db.js';
import cookieParser from 'cookie-parser';
import authRoutes from './src/routes/auth.routes.js';
import userRoutes from './src/routes/user.routes.js';
import { errorHandler } from './src/middlewares/error.middleware.js';

// Load environment variables
dotenv.config();

// Connect to database
connectDB();

const app = express();

// Middleware
app.use(express.json());

// CORS configuration: support multiple allowed origins via env (comma-separated)
const allowedOrigins = (process.env.CLIENT_ORIGINS || process.env.CLIENT_ORIGIN || 'http://localhost:5173,http://localhost:8080')
  .split(',')
  .map((o) => o.trim());

const corsOptions = {
  origin: (origin, callback) => {
    // Allow non-browser clients or same-origin requests with no Origin header
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`Not allowed by CORS: ${origin}`));
  },
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(cookieParser());

// Logging middleware in development
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Health check route
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});

// Error handling middleware
app.use(errorHandler);

// Handle 404 routes
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
});