import express from 'express';
import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import { sanitizeInput } from './middleware/validation.js';
import authRoutes from './routes/auth.routes.js';
import adminRoutes from './routes/admin.routes.js';
import studentRoutes from './routes/student.routes.js';
import prisma from './utils/prisma.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Parse allowed origins from env dynamically
const allowedOrigins = [
  process.env.CLIENT_URL,
  process.env.FRONTEND_URL,
  'http://localhost:5173',
  'http://127.0.0.1:5173'
].filter(Boolean) // Remove undefined/null
 .flatMap(url => url.split(',').map(u => u.trim()));

// Security headers via Helmet
app.use(helmet({
  contentSecurityPolicy: isProduction ? undefined : false,
  crossOriginEmbedderPolicy: false,
}));

// Rate limiting to prevent brute-force attacks
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, message: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware
app.use(generalLimiter);
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    
    const cleanOrigin = origin.replace(/\/$/, '');
    const cleanAllowedOrigins = allowedOrigins.map(url => url.replace(/\/$/, ''));
    
    if (cleanAllowedOrigins.includes(cleanOrigin)) {
      return callback(null, true);
    }
    
    // Dynamically allow any Vercel preview deployments to prevent CORS errors on new builds
    if (cleanOrigin.endsWith('.vercel.app')) {
      return callback(null, true);
    }
    
    return callback(new Error('Not allowed by CORS: ' + origin));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Compression
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Apply XSS sanitization globally
app.use(sanitizeInput);



// Health check
app.get('/api/health', async (req, res) => {
  try {
    // Ping DB to keep Neon Serverless connection active
    await prisma.$queryRaw`SELECT 1`;
    console.log(`[PING] Health check received at ${new Date().toLocaleTimeString()}`);
    res.json({ status: 'ok', message: 'MSEC ERP Server is running', db: 'connected', timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('[PING] Database connection failed:', error.message);
    res.status(500).json({ status: 'error', message: 'Database connection failed' });
  }
});

// Routes
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/student', studentRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  const statusCode = err.status || 500;
  const isServerError = statusCode >= 500;

  if (isServerError) {
    console.error(`[ERROR] ${new Date().toISOString()}:`, err.stack);
  }

  res.status(statusCode).json({
    success: false,
    message: isServerError ? 'An internal server error occurred' : err.message,
    ...(isProduction ? {} : { stack: err.stack })
  });
});

// 404 handler for API routes
app.use('/api', (req, res) => {
  res.status(404).json({ success: false, message: 'API Route not found' });
});

// Serve frontend static files for offline/combined deployments
const clientDistPath = path.join(__dirname, '../../client/dist');
app.use(express.static(clientDistPath));

app.get('*', (req, res) => {
  res.sendFile(path.join(clientDistPath, 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 MSEC ERP Server running on port ${PORT}`);
  console.log(`📦 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 Allowed origins: ${allowedOrigins.join(', ')}`);
});

export default app;
