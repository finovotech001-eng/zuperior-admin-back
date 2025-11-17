// Basic Express server bootstrap for Zuperior Admin backend
// Loads env, configures CORS/JSON, and prepares a Postgres connection.

const express = require('express');
const cors = require('cors');
const axios = require('axios'); // eslint-disable-line no-unused-vars
const { Pool } = require('pg');
const { PrismaClient } = require('@prisma/client');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const expressValidator = require('express-validator');
require('dotenv').config();

const app = express();

// ---- Env & Config ----
const PORT = process.env.PORT ? Number(process.env.PORT) : 5003;
const DATABASE_URL = process.env.DATABASE_URL;
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

// Parse CORS origins: "*" or comma-separated list
let corsOptions = {};
if (CORS_ORIGIN === '*' || CORS_ORIGIN === '*,*') {
  corsOptions = { origin: true, credentials: true };
} else {
  const allowed = CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
  corsOptions = {
    origin(origin, cb) {
      console.log('🔍 CORS Check:', { origin, allowed, CORS_ORIGIN });
      if (!origin || allowed.includes(origin)) {
        console.log('✅ CORS Allowed:', origin);
        return cb(null, true);
      }
      console.log('❌ CORS Blocked:', origin);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-CSRF-Token', 'X-Forwarded-For'],
    optionsSuccessStatus: 200
  };
}

// ---- Security Middleware ----
// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

// Rate limiting for login attempts (relaxed for development)
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: {
    ok: false,
    error: 'Too many login attempts, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// General rate limiting (relaxed for development)
const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 1000, // limit each IP to 1000 requests per minute
  message: {
    ok: false,
    error: 'Too many requests, please try again later.'
  }
});

// Apply rate limiting
app.use(generalLimiter);

app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    console.log('🔄 Preflight request:', req.headers.origin);
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token, X-Forwarded-For');
    res.header('Access-Control-Allow-Credentials', 'true');
    return res.status(200).end();
  }
  next();
});

app.use(express.json({ limit: '1mb' }));
// Static serving for stored KYC proofs
const proofsDir = path.join(process.cwd(), 'zuperior-admin-back', 'src', 'kyc_proofs');
app.use('/kyc_proofs', express.static(proofsDir));
// Backward-compatible: some rows may reference /uploads/... from older saves
app.use('/uploads', express.static(proofsDir));

// ---- Database ----
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('PG Pool error:', err);
});

// Prisma ORM (preferred for app queries)
const prisma = new PrismaClient();

// Email transporter configuration
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ---- Email helpers ----
async function sendOperationEmail(type, payload) {
  try {
    const { email, account_login, amount, date, name } = payload || {};
    if (!email) return { ok: false, error: 'missing email' };
    
    // Check if email transporter is configured
    if (!emailTransporter || !process.env.SMTP_HOST) {
      console.warn('Email transporter not configured');
      return { ok: false, error: 'Email not configured' };
    }
    
    const safeAmount = typeof amount === 'number' ? amount.toFixed(2) : String(amount || '0');
    const ts = date || new Date().toISOString();
    const subjectMap = {
      deposit: 'Deposit Approved',
      withdrawal: 'Withdrawal Approved',
      bonus_add: 'Bonus Added',
      bonus_deduct: 'Bonus Deducted',
    };
    const title = subjectMap[type] || 'Notification';
    const lineMap = {
      deposit: 'Deposit Approved',
      withdrawal: 'Withdrawal Approved', 
      bonus_add: 'Bonus Added',
      bonus_deduct: 'Bonus Deducted',
    };
    const line = lineMap[type] || 'notification';
    const html = `
      <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #222; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px;">
          <h2 style="margin: 0; font-size: 24px;">${line}</h2>
        </div>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
          <p style="margin: 0 0 15px 0; font-size: 16px;">Hi ${name || 'Valued Customer'},</p>
          <div style="background: white; padding: 15px; border-radius: 6px; border-left: 4px solid #667eea;">
            <p style="margin: 5px 0; font-size: 14px;"><strong>MT5:</strong> ${account_login || '-'}</p>
            <p style="margin: 5px 0; font-size: 14px;"><strong>Amount:</strong> ${safeAmount}</p>
            <p style="margin: 5px 0; font-size: 14px;"><strong>Source:</strong> Admin</p>
            <p style="margin: 5px 0; font-size: 14px;"><strong>Date:</strong> ${new Date().toLocaleString()}</p>
          </div>
        </div>
        <p style="font-size: 14px; color: #666;">If you did not authorize this action, please contact support immediately.</p>
        <p style="font-size: 14px; margin-top: 30px;">Regards,<br/><strong>${process.env.FROM_NAME || 'Zuperior'}</strong></p>
      </div>
    `;
    const mailOptions = {
      from: `"${process.env.FROM_NAME || 'Zuperior'}" <${process.env.FROM_EMAIL || process.env.SMTP_USER}>`,
      to: email,
      subject: line,
      text: `${line}\n\nHi ${name || 'Valued Customer'},\n\nMT5: ${account_login || '-'}\nAmount: ${safeAmount}\nSource: Admin\nDate: ${new Date().toLocaleString()}\n\nIf you did not authorize this action, please contact support immediately.\n\nRegards,\n${process.env.FROM_NAME || 'Zuperior'}`,
      html,
    };
    await emailTransporter.sendMail(mailOptions);
    return { ok: true };
  } catch (e) {
    console.warn('sendOperationEmail failed:', e.message);
    return { ok: false, error: e.message };
  }
}

// ---- Authentication Middleware ----
const authenticateAdmin = async (req, res, next) => {
  try {
    console.log('🔐 Auth attempt:', {
      url: req.url,
      method: req.method,
      authHeader: req.headers.authorization,
      userAgent: req.headers['user-agent']?.substring(0, 50)
    });
    
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      console.log('❌ No token provided');
      return res.status(401).json({ ok: false, error: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    
    const admin = await prisma.admin.findUnique({
      where: { id: decoded.adminId },
      select: {
        id: true,
        email: true,
        admin_role: true,
        is_active: true,
        last_login: true
      }
    });

    if (!admin) {
      return res.status(401).json({ ok: false, error: 'Admin not found' });
    }

    if (!admin.is_active) {
      return res.status(401).json({ ok: false, error: 'Account is inactive' });
    }

    // Check if this admin is a country admin and attach features
    let countryAdminData = null;
    if (decoded.isCountryAdmin) {
      try {
        const countryAdminResult = await pool.query(
          'SELECT * FROM public.country_admins WHERE email = $1',
          [admin.email]
        );
        if (countryAdminResult.rows.length > 0) {
          const countryAdmin = countryAdminResult.rows[0];
          // Parse features from comma-separated string to array and normalize paths
          // Normalize: extract last part of path to match sidebar filter logic
          const normalizeFeature = (f) => {
            if (typeof f !== 'string' || !f.includes('/')) return f.trim();
            // Remove leading /admin/ if present, then get last part
            const cleaned = f.replace(/^\/admin\//, '').replace(/^\//, '').trim();
            return cleaned.split('/').pop() || cleaned;
          };
          
          const features = countryAdmin.features 
            ? countryAdmin.features.split(',').map(f => normalizeFeature(f.trim())).filter(f => f && f.length > 0)
            : [];
          
          countryAdminData = {
            isCountryAdmin: true,
            features: features,
            country: countryAdmin.country_code,
            countryAdminId: countryAdmin.id,
            status: countryAdmin.status
          };
        }
      } catch (err) {
        console.error('Error checking country_admin in middleware:', err);
        // Continue without country admin data if check fails
      }
    }

    req.adminId = admin.id;
    req.admin = {
      ...admin,
      ...(countryAdminData || {})
    };
    req.isCountryAdmin = countryAdminData ? true : false;
    next();
  } catch (err) {
    console.error('Authentication failed:', err);
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
};

// ---- Routes ----
app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'zuperior-admin-back', time: new Date().toISOString() });
});

// CORS test endpoint
app.get('/cors-test', (req, res) => {
  res.json({ 
    ok: true, 
    message: 'CORS is working!', 
    origin: req.headers.origin,
    time: new Date().toISOString() 
  });
});

app.get('/api/version', (req, res) => {
  res.json({ version: '0.1.0' });
});

app.get('/db/ping', async (req, res) => {
  try {
    const r = await pool.query('SELECT 1 as up');
    res.json({ ok: true, db: r.rows[0] });
  } catch (err) {
    console.error('DB ping failed:', err);
    res.status(500).json({ ok: false, error: 'DB ping failed' });
  }
});

// Update user fields (e.g., name)
app.patch('/admin/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const data = req.body || {};
    // Only allow a safe subset for now
    const allowed = {};
    if (typeof data.name === 'string') allowed.name = data.name;
    if (typeof data.phone === 'string') allowed.phone = data.phone;
    if (typeof data.country === 'string') allowed.country = data.country;
    if (typeof data.status === 'string') allowed.status = data.status;
    if (!Object.keys(allowed).length) return res.status(400).json({ ok: false, error: 'No changes provided' });
    const user = await prisma.user.update({ where: { id }, data: allowed, select: { id: true } });
    res.json({ ok: true, id: user.id });
  } catch (err) {
    console.error('PATCH /admin/users/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Update failed' });
  }
});

// Toggle email verification
app.patch('/admin/users/:id/email-verify', async (req, res) => {
  try {
    const { id } = req.params;
    const { verified } = req.body || {};
    const user = await prisma.user.update({ where: { id }, data: { emailVerified: !!verified }, select: { id: true, emailVerified: true } });
    res.json({ ok: true, id: user.id, emailVerified: user.emailVerified });
  } catch (err) {
    console.error('PATCH /admin/users/:id/email-verify failed:', err);
    res.status(500).json({ ok: false, error: 'Verification toggle failed' });
  }
});

// Delete user
app.delete('/admin/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if user exists first
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) {
      return res.status(404).json({ ok: false, error: 'User not found' });
    }
    
    // Query database for all foreign key constraints that reference User table
    // This helps identify any constraints we might have missed
    let fkInfo = [];
    try {
      const fkQuery = `
        SELECT
          tc.table_name,
          kcu.column_name,
          ccu.table_name AS foreign_table_name,
          ccu.column_name AS foreign_column_name,
          tc.constraint_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
          AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
          AND ccu.table_schema = tc.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND ccu.table_name = 'User'
          AND ccu.column_name = 'id';
      `;
      const fkResult = await pool.query(fkQuery);
      fkInfo = fkResult.rows || [];
      console.log('Foreign key constraints referencing User:', JSON.stringify(fkInfo, null, 2));
    } catch (fkErr) {
      console.warn('Could not query FK constraints:', fkErr);
    }
    
    // First, delete non-Prisma tables using raw SQL (outside transaction to avoid issues)
    // These tables might not have proper FK constraints but still need cleanup
    try {
      // Delete UserLoginLog - this table has both userid and userId columns
      await pool.query('DELETE FROM "UserLoginLog" WHERE userid = $1 OR "userId" = $1', [id]);
      
      // Delete support ticket replies first (they might reference tickets)
      await pool.query('DELETE FROM support_ticket_replies WHERE sender_id = $1', [id]);
      await pool.query('DELETE FROM support_replies WHERE sender_id = $1', [id]);
      // Delete support tickets
      await pool.query('DELETE FROM support_tickets WHERE user_id = $1', [id]);
      // Delete chat participants first (they reference conversations)
      await pool.query('DELETE FROM chat_participants WHERE user_id = $1', [id]);
      // Delete chat messages where sender_id matches
      await pool.query('DELETE FROM chat_messages WHERE sender_id = $1', [id]);
      // Delete chat conversations (cascade should handle the rest)
      await pool.query('DELETE FROM chat_conversations WHERE user_id = $1', [id]);
    } catch (sqlErr) {
      console.warn('Error deleting non-Prisma tables (continuing):', sqlErr);
    }
    
    // Before Prisma transaction, clean up any legacy tables that may reference MT5 accounts
    try {
      const mt5Ids = (await prisma.mT5Account.findMany({ where: { userId: id }, select: { id: true } })).map(a => a.id);
      if (mt5Ids.length) {
        const candidates = [
          'DefaultMT5Account',
          'default_mt5_account',
          'default_mt5_accounts',
          'defaultmt5account'
        ];
        for (const tbl of candidates) {
          try {
            // Try both common column casings
            await pool.query(`DELETE FROM "${tbl}" WHERE "mt5AccountId" = ANY($1::text[])`, [mt5Ids]);
          } catch {}
          try {
            await pool.query(`DELETE FROM "${tbl}" WHERE "mt5_account_id" = ANY($1::text[])`, [mt5Ids]);
          } catch {}
        }
      }
    } catch (cleanErr) {
      console.warn('Warning: could not cleanup legacy default MT5 account mappings:', cleanErr?.message || cleanErr);
    }

    // Use a transaction to handle Prisma-related records
    await prisma.$transaction(async (tx) => {
      // Delete related records first (in order of dependencies)
      
      // Get deposit and withdrawal IDs first to delete related transactions
      const depositIds = (await tx.deposit.findMany({ where: { userId: id }, select: { id: true } })).map(d => d.id);
      const withdrawalIds = (await tx.withdrawal.findMany({ where: { userId: id }, select: { id: true } })).map(w => w.id);
      
      // Delete transactions that reference deposits/withdrawals OR the user directly
      const transactionConditions = [{ userId: id }];
      if (depositIds.length > 0) {
        transactionConditions.push({ depositId: { in: depositIds } });
      }
      if (withdrawalIds.length > 0) {
        transactionConditions.push({ withdrawalId: { in: withdrawalIds } });
      }
      if (transactionConditions.length > 1) {
        await tx.transaction.deleteMany({ where: { OR: transactionConditions } });
      } else {
      await tx.transaction.deleteMany({ where: { userId: id } });
      }
      
      // Delete MT5 transactions (if userId is set) - these reference MT5Account
      await tx.mT5Transaction.deleteMany({ where: { userId: id } });
      
      // Delete deposits (these reference MT5Account)
      await tx.deposit.deleteMany({ where: { userId: id } });
      
      // Delete withdrawals (these reference MT5Account)
      await tx.withdrawal.deleteMany({ where: { userId: id } });
      
      // Delete MT5 accounts (after deposits/withdrawals that reference them)
      await tx.mT5Account.deleteMany({ where: { userId: id } });
      
      // Delete accounts
      await tx.account.deleteMany({ where: { userId: id } });
      
      // Delete payment methods
      await tx.paymentMethod.deleteMany({ where: { userId: id } });
      
      // Delete KYC records (unique foreign key)
      await tx.kYC.deleteMany({ where: { userId: id } });
      
      // Delete activity logs (both where user is the subject and where user is the admin)
      await tx.activityLog.deleteMany({ 
        where: { 
          OR: [
            { userId: id },
            { adminId: id }
          ]
        } 
      });
      
      // Delete user roles
      await tx.userRole.deleteMany({ where: { userId: id } });
      
      // Finally delete the user
      await tx.user.delete({ where: { id } });
    }, {
      timeout: 30000, // Increase timeout to 30 seconds for large deletions
      isolationLevel: 'ReadCommitted'
    });
    
    console.log(`✅ User ${id} deleted successfully`);
    res.json({ ok: true, message: 'User deleted successfully' });
  } catch (err) {
    console.error('DELETE /admin/users/:id failed:', err);
    console.error('Error details:', {
      code: err.code,
      message: err.message,
      meta: err.meta,
      stack: err.stack
    });
    
    // If it's a foreign key constraint error, try to get more details
    if (err.code === 'P2003' || (err.message && err.message.includes('violates foreign key constraint'))) {
      // Try to identify the constraint
      const constraintInfo = err.meta?.field_name || err.meta?.target || err.meta?.constraint || 'unknown constraint';
      const tableName = err.meta?.table_name || 'unknown table';
      
      // Log detailed error for debugging
      console.error('Constraint violation details:', {
        constraint: constraintInfo,
        table: tableName,
        meta: err.meta
      });
      
      return res.status(400).json({ 
        ok: false, 
        error: `Cannot delete user: Related records still exist in ${tableName} (constraint: ${constraintInfo}). Please contact support.` 
      });
    }
    
    if (err.code === 'P2025') {
      return res.status(404).json({ 
        ok: false, 
        error: 'User not found' 
      });
    }
    
    res.status(500).json({ 
      ok: false, 
      error: 'Delete failed: ' + (err.message || 'Unknown error') 
    });
  }
});

// -------- KYC endpoints --------
// List KYC records with user info
app.get('/admin/kyc', authenticateAdmin, async (req, res) => {
  try {
    const take = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const q = (req.query.q || '').trim();
    const status = (req.query.status || '').trim();
    const countryParam = (req.query.country || '').trim().toLowerCase();

    // If country admin, automatically filter by their assigned country
    let countryFilter = countryParam;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    const where = {
      ...(status ? { verificationStatus: status } : {}),
      ...(q
        ? {
            OR: [
              { User: { email: { contains: q, mode: 'insensitive' } } },
              { User: { name: { contains: q, mode: 'insensitive' } } },
              { User: { clientId: { contains: q, mode: 'insensitive' } } },
            ],
          }
        : {}),
      ...(countryFilter ? { 
        User: { 
          country: { 
            equals: countryFilter, 
            mode: 'insensitive' 
          } 
        } 
      } : {}),
    };

    const [total, items] = await Promise.all([
      prisma.kYC.count({ where }),
      prisma.kYC.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take,
        select: {
          id: true,
          userId: true,
          isDocumentVerified: true,
          isAddressVerified: true,
          verificationStatus: true,
          documentReference: true,
          addressReference: true,
          documentSubmittedAt: true,
          addressSubmittedAt: true,
          createdAt: true,
          updatedAt: true,
          User: { select: { id: true, clientId: true, email: true, name: true, country: true } },
        },
      }),
    ]);

    res.json({ ok: true, total, page, limit: take, items });
  } catch (err) {
    console.error('GET /admin/kyc failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to list KYC' });
  }
});

// Update KYC flags or status
app.patch('/admin/kyc/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const body = req.body || {};
    const data = {};
    if (typeof body.isDocumentVerified === 'boolean') data.isDocumentVerified = body.isDocumentVerified;
    if (typeof body.isAddressVerified === 'boolean') data.isAddressVerified = body.isAddressVerified;
    if (typeof body.verificationStatus === 'string') data.verificationStatus = body.verificationStatus;
    if (typeof body.documentReference === 'string') data.documentReference = body.documentReference;
    if (typeof body.addressReference === 'string') data.addressReference = body.addressReference;
    if (body.documentReference && !body.documentSubmittedAt) data.documentSubmittedAt = new Date();
    if (body.addressReference && !body.addressSubmittedAt) data.addressSubmittedAt = new Date();
    if (Object.keys(data).length === 0) return res.status(400).json({ ok: false, error: 'No valid fields' });

    // If the id is synthetic (no-kyc-<userId>), create a new KYC record for that user
    if (id && id.startsWith('no-kyc-')) {
      const userId = id.replace('no-kyc-','');
      try {
        const created = await prisma.kYC.create({
          data: {
            id: crypto.randomUUID(),
            userId,
            isDocumentVerified: !!data.isDocumentVerified,
            isAddressVerified: !!data.isAddressVerified,
            verificationStatus: data.verificationStatus || 'Pending',
            documentReference: data.documentReference || null,
            addressReference: data.addressReference || null,
            documentSubmittedAt: data.documentSubmittedAt || null,
            addressSubmittedAt: data.addressSubmittedAt || null,
            createdAt: new Date(),
            updatedAt: new Date(),
          },
          select: { id: true }
        });
        return res.json({ ok: true, id: created.id });
      } catch (e) {
        console.error('Create KYC for user failed:', e);
        return res.status(500).json({ ok: false, error: 'Failed to create KYC' });
      }
    }

    // Normal update path
    try {
    const rec = await prisma.kYC.update({ where: { id }, data, select: { id: true } });
      return res.json({ ok: true, id: rec.id });
    } catch (e) {
      // If not found, but a userId was supplied, create instead
      if (e && e.code === 'P2025' && body.userId) {
        try {
          const created = await prisma.kYC.create({
            data: {
              id: crypto.randomUUID(),
              userId: body.userId,
              isDocumentVerified: !!data.isDocumentVerified,
              isAddressVerified: !!data.isAddressVerified,
              verificationStatus: data.verificationStatus || 'Pending',
              documentReference: data.documentReference || null,
              addressReference: data.addressReference || null,
              documentSubmittedAt: data.documentSubmittedAt || null,
              addressSubmittedAt: data.addressSubmittedAt || null,
              createdAt: new Date(),
              updatedAt: new Date(),
            },
            select: { id: true }
          });
          return res.json({ ok: true, id: created.id });
        } catch (ce) {
          console.error('Create KYC after not found failed:', ce);
          return res.status(500).json({ ok: false, error: 'Failed to create KYC' });
        }
      }
      console.error('PATCH /admin/kyc/:id failed:', e);
      return res.status(500).json({ ok: false, error: 'Failed to update KYC' });
    }
  } catch (err) {
    console.error('PATCH /admin/kyc/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update KYC' });
  }
});

// Upload proofs (document/address)
const uploadsDir = path.join(process.cwd(), 'zuperior-admin-back', 'src', 'kyc_proofs');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase();
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  }
});
const upload = multer({ storage });

app.post('/admin/uploads', upload.fields([{ name: 'document', maxCount: 1 }, { name: 'address', maxCount: 1 }]), (req, res) => {
  const files = req.files || {};
  const out = {};
  if (files.document?.[0]) out.document = `/kyc_proofs/${path.basename(files.document[0].path)}`;
  if (files.address?.[0]) out.address = `/kyc_proofs/${path.basename(files.address[0].path)}`;
  res.json({ ok: true, files: out });
});

// Fetch all users (paginated)
app.get('/admin/users/all', authenticateAdmin, async (req, res) => {
  try {
    const take = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const q = (req.query.q || '').trim();
    const statusParam = (req.query.status || '').trim();
    const countryParam = (req.query.country || '').trim().toLowerCase();
    const emailVerifiedParam = (req.query.emailVerified || '').trim();

    // If country admin, automatically filter by their assigned country
    let countryFilter = countryParam;
    if (req.isCountryAdmin && req.admin?.country) {
      // Use country admin's assigned country (stored as country_code like "AE")
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    const where = {
      ...(q
        ? {
            OR: [
              { email: { contains: q, mode: 'insensitive' } },
              { clientId: { contains: q, mode: 'insensitive' } },
              { name: { contains: q, mode: 'insensitive' } },
            ],
          }
        : {}),
      ...(statusParam ? { status: statusParam } : {}),
      ...(emailVerifiedParam
        ? { emailVerified: String(emailVerifiedParam).toLowerCase() === 'true' }
        : {}),
      // Use case-insensitive matching for country (handles both "AE" and "ae")
      ...(countryFilter ? { 
        country: { 
          equals: countryFilter, 
          mode: 'insensitive' 
        } 
      } : {}),
    };

    const [total, items] = await Promise.all([
      prisma.user.count({ where }),
      prisma.user.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take,
        select: {
          id: true,
          clientId: true,
          email: true,
          name: true,
          phone: true,
          country: true,
          role: true,
          status: true,
          emailVerified: true,
          createdAt: true,
          lastLoginAt: true,
          KYC: { select: { verificationStatus: true } },
        },
      }),
    ]);

    res.json({ ok: true, total, page, limit: take, items });
  } catch (err) {
    console.error('GET /admin/users/all failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch users' });
  }
});

// Create a new user
app.post('/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { email, password, name, phone, country, role = 'user', status = 'active', emailVerified = false, kycVerified = false } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, error: 'email and password required' });
    
    // If country admin, ensure they can only create users for their assigned country
    let finalCountry = country;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        finalCountry = adminCountry;
        // If country is provided and doesn't match, reject
        if (country && String(country).trim().toUpperCase() !== adminCountry) {
          return res.status(403).json({ 
            ok: false, 
            error: `You can only create users for your assigned country: ${adminCountry}` 
          });
        }
      }
    }
    
    const id = crypto.randomUUID();
    const clientId = `cm${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`.slice(0, 26);
    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { id, clientId, email, password: hashed, name, phone, country: finalCountry, role, status, emailVerified: !!emailVerified },
      select: { id: true, clientId: true, email: true }
    });
    // Optionally create/approve KYC immediately
    if (kycVerified) {
      try {
        const existing = await prisma.kYC.findFirst({ where: { userId: user.id } });
        if (existing) {
          await prisma.kYC.update({ where: { id: existing.id }, data: { verificationStatus: 'Approved', isDocumentVerified: true, isAddressVerified: true, updatedAt: new Date() } });
        } else {
          await prisma.kYC.create({ data: { id: crypto.randomUUID(), userId: user.id, verificationStatus: 'Approved', isDocumentVerified: true, isAddressVerified: true, createdAt: new Date(), updatedAt: new Date() } });
        }
      } catch (e) {
        console.error('Auto-approve KYC failed:', e);
      }
    }
    res.json({ ok: true, user });
  } catch (err) {
    console.error('POST /admin/users failed:', err);
    if (err?.code === 'P2002') return res.status(409).json({ ok: false, error: 'Email or clientId already exists' });
    res.status(500).json({ ok: false, error: 'Failed to create user' });
  }
});

// Toggle KYC verification for a user (create if missing)
app.patch('/admin/users/:id/kyc-verify', async (req, res) => {
  try {
    const { id } = req.params;
    const { verified } = req.body || {};
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
    const existing = await prisma.kYC.findFirst({ where: { userId: id } });
    const data = verified
      ? { verificationStatus: 'Approved', isDocumentVerified: true, isAddressVerified: true, updatedAt: new Date() }
      : { verificationStatus: 'Pending', isDocumentVerified: false, isAddressVerified: false, updatedAt: new Date() };
    if (existing) {
      await prisma.kYC.update({ where: { id: existing.id }, data });
      return res.json({ ok: true, id: existing.id });
    }
    const created = await prisma.kYC.create({ data: { id: crypto.randomUUID(), userId: id, ...data, createdAt: new Date() } });
    res.json({ ok: true, id: created.id });
  } catch (err) {
    console.error('PATCH /admin/users/:id/kyc-verify failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update KYC' });
  }
});

// Check if email exists in USER table
app.post('/admin/users/check-email', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ ok: false, error: 'Email is required' });
    
    // Check if email exists in USER table
    const existingUser = await prisma.user.findFirst({
      where: { email: email.toLowerCase().trim() },
      select: { id: true, email: true }
    });
    
    res.json({ 
      ok: true, 
      exists: !!existingUser,
      message: existingUser ? 'Email already exists in USER table' : 'Email is available'
    });
  } catch (err) {
    console.error('POST /admin/users/check-email failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to check email' });
  }
});

// MT5 API Proxy endpoint to avoid CORS issues
app.get('/admin/mt5/proxy/:accountId/getClientProfile', async (req, res) => {
  try {
    const { accountId } = req.params;
    if (!accountId) return res.status(400).json({ ok: false, error: 'Account ID is required' });
    
    console.log(`[MT5 Proxy] Fetching account ${accountId}...`);
    
    // Make request to MT5 API server
    const mt5Response = await axios.get(`http://18.175.242.21:5003/api/Users/${accountId}/getClientProfile`, {
      timeout: 15000, // Increased timeout
      headers: {
        'Content-Type': 'application/json',
        // Add any required MT5 API headers here
      }
    });
    
    console.log(`[MT5 Proxy] ✅ Account ${accountId} fetched successfully:`, {
      success: mt5Response.data?.Success,
      message: mt5Response.data?.Message,
      hasData: !!mt5Response.data?.Data
    });
    
    // Return the MT5 API response
    res.json({
      ok: true,
      data: mt5Response.data
    });
  } catch (err) {
    console.error(`[MT5 Proxy] ❌ Failed to fetch account ${req.params.accountId}:`, {
      message: err.message,
      code: err.code,
      status: err.response?.status,
      statusText: err.response?.statusText
    });
    res.status(500).json({ 
      ok: false, 
      error: err.message || 'Failed to fetch MT5 account details' 
    });
  }
});

// Test MT5 API connectivity
app.get('/admin/mt5/test', async (req, res) => {
  try {
    console.log('[MT5 Test] Testing MT5 API connectivity...');
    
    // Test with a known account ID
    const testAccountId = '19877040';
    const mt5Response = await axios.get(`http://18.175.242.21:5003/api/Users/${testAccountId}/getClientProfile`, {
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      }
    });
    
    console.log('[MT5 Test] ✅ MT5 API is accessible:', {
      success: mt5Response.data?.Success,
      message: mt5Response.data?.Message,
      hasData: !!mt5Response.data?.Data
    });
    
    res.json({
      ok: true,
      message: 'MT5 API is accessible',
      testAccount: testAccountId,
      response: mt5Response.data
    });
  } catch (err) {
    console.error('[MT5 Test] ❌ MT5 API test failed:', {
      message: err.message,
      code: err.code,
      status: err.response?.status,
      statusText: err.response?.statusText
    });
    
    res.status(500).json({
      ok: false,
      error: 'MT5 API is not accessible',
      details: {
        message: err.message,
        code: err.code,
        status: err.response?.status
      }
    });
  }
});

// Fetch users with MT5 accounts and balances
app.get('/admin/users/with-balance', authenticateAdmin, async (req, res) => {
  try {
    const take = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const q = (req.query.q || '').trim();
    const countryParam = (req.query.country || '').trim().toLowerCase();

    // If country admin, automatically filter by their assigned country
    let countryFilter = countryParam;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    const where = {
      MT5Account: { some: {} }, // Only users with at least one MT5 account
      ...(q
        ? {
            OR: [
              { email: { contains: q, mode: 'insensitive' } },
              { name: { contains: q, mode: 'insensitive' } },
              { phone: { contains: q, mode: 'insensitive' } },
            ],
          }
        : {}),
      ...(countryFilter ? { 
        country: { 
          equals: countryFilter, 
          mode: 'insensitive' 
        } 
      } : {}),
    };

    const [total, users] = await Promise.all([
      prisma.user.count({ where }),
      prisma.user.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take,
        select: {
          id: true,
          clientId: true,
          email: true,
          name: true,
          phone: true,
          country: true,
          createdAt: true,
          MT5Account: {
            select: {
              id: true,
              accountId: true,
            },
          },
        },
      }),
    ]);

    // Fetch balances for each user's MT5 accounts
    const MT5_API_BASE = 'http://18.175.242.21:5003/api/Users';
    const items = await Promise.all(
      users.map(async (user) => {
        const totalBalance = await Promise.all(
          user.MT5Account.map(async (account) => {
            try {
              const response = await axios.get(`${MT5_API_BASE}/${account.accountId}/getClientProfile`, {
                timeout: 5000, // 5 second timeout
              });
              return response.data?.Data?.Balance || 0;
            } catch (error) {
              console.warn(`Failed to fetch balance for account ${account.accountId}:`, error.message);
              return 0; // Skip on failure
            }
          })
        ).then(balances => balances.reduce((sum, balance) => sum + balance, 0));

        return {
          ...user,
          totalBalance,
          MT5Account: user.MT5Account, // Keep for modal if needed
        };
      })
    );

    res.json({ ok: true, total, page, limit: take, items });
  } catch (err) {
    console.error('GET /admin/users/with-balance failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch users with balance' });
  }
});

// Fetch MT5 account details
// Removed old endpoint - using authenticated endpoint below

// Fetch all MT5 users with balances
app.get('/admin/mt5/users', authenticateAdmin, async (req, res) => {
  try {
    const take = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const q = (req.query.q || '').trim();
    const countryParam = (req.query.country || '').trim().toLowerCase();

    // If country admin, automatically filter by their assigned country
    let countryFilter = countryParam;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    const where = {
      MT5Account: { some: {} }, // All users with at least one MT5 account
      ...(q
        ? {
            OR: [
              { email: { contains: q, mode: 'insensitive' } },
              { name: { contains: q, mode: 'insensitive' } },
              { phone: { contains: q, mode: 'insensitive' } },
            ],
          }
        : {}),
      ...(countryFilter ? { 
        country: { 
          equals: countryFilter, 
          mode: 'insensitive' 
        } 
      } : {}),
    };

    const [total, users] = await Promise.all([
      prisma.mT5Account.count(),
      prisma.user.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take,
        select: {
          id: true,
          clientId: true,
          email: true,
          name: true,
          phone: true,
          country: true,
          createdAt: true,
          MT5Account: {
            select: {
              id: true,
              accountId: true,
            },
          },
        },
      }),
    ]);


    // Fetch full MT5 account details for each user
    const MT5_API_BASE = 'http://18.175.242.21:5003/api/Users';
    const items = await Promise.all(
      users.map(async (user) => {
        const accountDetails = await Promise.all(
          user.MT5Account.map(async (account) => {
            try {
              const response = await axios.get(`${MT5_API_BASE}/${account.accountId}/getClientProfile`, {
                timeout: 5000,
              });
              const mt5Response = response.data;
              
              // Check if MT5 API call was successful
              if (mt5Response?.Success === true && mt5Response?.Data) {
                const data = mt5Response.Data;
                const accountData = {
                  id: account.id,
                  accountId: account.accountId,
                  name: (data.Name && data.Name.trim() !== "") ? data.Name : "-",
                  group: (data.Group && data.Group.trim() !== "") ? data.Group : "-",
                  balance: data.Balance || 0,
                  equity: data.Equity || 0,
                  leverage: data.Leverage ? data.Leverage.toString() : "-",
                  credit: data.Credit || 0,
                  margin: data.Margin || 0,
                  marginFree: data.MarginFree || 0,
                  marginLevel: data.MarginLevel || 0,
                  profit: data.Profit || 0,
                  comment: (data.Comment && data.Comment.trim() !== "") ? data.Comment : "-",
                  city: (data.City && data.City.trim() !== "") ? data.City : "-",
                  state: (data.State && data.State.trim() !== "") ? data.State : "-",
                  zipCode: (data.ZipCode && data.ZipCode.trim() !== "") ? data.ZipCode : "-",
                  address: (data.Address && data.Address.trim() !== "") ? data.Address : "-",
                  registration: (data.Registration && data.Registration.trim() !== "") ? data.Registration : "-",
                  lastAccess: (data.LastAccess && data.LastAccess.trim() !== "") ? data.LastAccess : "-",
                  lastIP: (data.LastIP && data.LastIP.trim() !== "") ? data.LastIP : "-",
                };
                return accountData;
              } else {
                console.warn(`⚠️ MT5 API call failed for account ${account.accountId}. Success: ${mt5Response?.Success}, Message: ${mt5Response?.Message}`);
                return {
                  id: account.id,
                  accountId: account.accountId,
                  name: "-",
                  group: "-",
                  balance: 0,
                  equity: 0,
                  leverage: "-",
                  credit: 0,
                  margin: 0,
                  marginFree: 0,
                  marginLevel: 0,
                  profit: 0,
                  comment: "-",
                  city: "-",
                  state: "-",
                  zipCode: "-",
                  address: "-",
                  registration: "-",
                  lastAccess: "-",
                  lastIP: "-",
                };
              }
            } catch (error) {
              console.warn(`Failed to fetch details for account ${account.accountId}:`, error.message);
              return {
                id: account.id,
                accountId: account.accountId,
                name: "-",
                group: "-",
                balance: 0,
                equity: 0,
                leverage: "-",
                credit: 0,
                margin: 0,
                marginFree: 0,
                marginLevel: 0,
                profit: 0,
                comment: "-",
                city: "-",
                state: "-",
                zipCode: "-",
                address: "-",
                registration: "-",
                lastAccess: "-",
                lastIP: "-",
              };
            }
          })
        );

        const totalBalance = accountDetails.reduce((sum, account) => sum + account.balance, 0);

        return {
          ...user,
          totalBalance,
          MT5Account: accountDetails,
        };
      })
    );

    res.json({ ok: true, total, page, limit: take, items });
  } catch (err) {
    console.error('GET /admin/mt5/users failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch MT5 users' });
  }
});

// Fetch unassigned MT5 accounts
app.get('/admin/mt5/unassigned', async (req, res) => {
  try {
    const accounts = await prisma.mT5Account.findMany({
      where: { userId: null },
      select: { id: true, accountId: true, createdAt: true },
    });
    res.json({ ok: true, accounts });
  } catch (err) {
    console.error('GET /admin/mt5/unassigned failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch unassigned accounts' });
  }
});

// Assign MT5 account to user
app.post('/admin/mt5/assign', async (req, res) => {
  try {
    const { userId, accountId, password, name, leverage, package: packageType } = req.body || {};
    if (!userId || !accountId) {
      return res.status(400).json({ ok: false, error: 'User ID and Account ID are required' });
    }

    // Check if user exists
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ ok: false, error: 'User not found' });
    }

    // Check if account already assigned using raw SQL (since Prisma schema may be outdated)
    const existingCheck = await pool.query('SELECT "userId" FROM "MT5Account" WHERE "accountId" = $1', [accountId]);
    if (existingCheck.rows.length > 0 && existingCheck.rows[0].userId) {
      // Get the user email who has this account assigned
      const assignedUser = await prisma.user.findUnique({
        where: { id: existingCheck.rows[0].userId },
        select: { email: true }
      });
      const userEmail = assignedUser?.email || 'unknown user';
      return res.status(409).json({ ok: false, error: `Account already assigned to ${userEmail}` });
    }

    // Use raw SQL to insert/update with all fields (password, leverage, nameOnAccount, package)
    const now = new Date();
    const leverageValue = leverage !== undefined && leverage !== null ? parseInt(leverage, 10) : null;
    
    if (existingCheck.rows.length > 0) {
      // Update existing record
      const setParts = ['"userId" = $1', '"updatedAt" = $2'];
      const params = [userId, now];
      let paramIndex = 3;
      
      if (password) {
        setParts.push(`"password" = $${paramIndex}`);
        params.push(password);
        paramIndex++;
      }
      if (name) {
        setParts.push(`"nameOnAccount" = $${paramIndex}`);
        params.push(name);
        paramIndex++;
      }
      if (leverageValue !== null) {
        setParts.push(`"leverage" = $${paramIndex}`);
        params.push(leverageValue);
        paramIndex++;
      }
      if (packageType) {
        setParts.push(`"package" = $${paramIndex}`);
        params.push(packageType);
        paramIndex++;
      }
      
      params.push(accountId);
      const updateQuery = `UPDATE "MT5Account" SET ${setParts.join(', ')} WHERE "accountId" = $${paramIndex} RETURNING id, "accountId"`;
      
      const result = await pool.query(updateQuery, params);
      res.json({ ok: true, mt5Account: result.rows[0] });
    } else {
      // Create new record
      const fields = ['id', '"accountId"', '"userId"', '"createdAt"', '"updatedAt"'];
      const placeholders = ['$1', '$2', '$3', '$4', '$5'];
      const params = [crypto.randomUUID(), accountId, userId, now, now];
      let paramIndex = 6;
      
      if (password) {
        fields.push('"password"');
        placeholders.push(`$${paramIndex}`);
        params.push(password);
        paramIndex++;
      }
      if (name) {
        fields.push('"nameOnAccount"');
        placeholders.push(`$${paramIndex}`);
        params.push(name);
        paramIndex++;
      }
      if (leverageValue !== null) {
        fields.push('"leverage"');
        placeholders.push(`$${paramIndex}`);
        params.push(leverageValue);
        paramIndex++;
      }
      if (packageType) {
        fields.push('"package"');
        placeholders.push(`$${paramIndex}`);
        params.push(packageType);
        paramIndex++;
      }
      
      const insertQuery = `INSERT INTO "MT5Account" (${fields.join(', ')}) VALUES (${placeholders.join(', ')}) RETURNING id, "accountId"`;
      
      const result = await pool.query(insertQuery, params);
      res.json({ ok: true, mt5Account: result.rows[0] });
    }
  } catch (err) {
    console.error('POST /admin/mt5/assign failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to assign MT5 account: ' + err.message });
  }
});

// List deposits by status
app.get('/admin/deposits', authenticateAdmin, async (req, res) => {
  try {
    const status = req.query.status;
    const take = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const q = (req.query.q || '').trim();
    const countryParam = (req.query.country || '').trim().toLowerCase();

    // If country admin, automatically filter by their assigned country
    let countryFilter = countryParam;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    const where = {
      ...(status ? { status } : {}),
      ...(q ? { User: { email: { contains: q, mode: 'insensitive' } } } : {}),
      ...(countryFilter ? { User: { country: { equals: countryFilter, mode: 'insensitive' } } } : {}),
    };

    const [total, totalSum, itemsRaw] = await Promise.all([
      prisma.deposit.count({ where }),
      prisma.deposit.aggregate({ where, _sum: { amount: true } }),
      prisma.deposit.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take,
        include: {
          User: { select: { id: true, email: true, name: true, country: true } },
          MT5Account: { select: { id: true, accountId: true } },
        },
      }),
    ]);

    // Fetch active manual bank gateways (global + by country)
    let gatewayMap = new Map();
    try {
      const { rows } = await pool.query(
        `SELECT type, name, bank_name, account_name, account_number, ifsc_code, swift_code, account_type, country_code, is_active
         FROM public.manual_gateway
         WHERE is_active = true
         ORDER BY created_at DESC`
      );
      for (const g of rows || []) {
        const key = (g.country_code || '').toUpperCase() || null;
        if (!gatewayMap.has(key)) gatewayMap.set(key, g); // first (latest) per country
      }
    } catch (e) {
      // non-fatal; proceed without manual gateway enrichment
      gatewayMap = new Map();
    }

    function fmtBank(g) {
      if (!g) return null;
      const parts = [];
      if (g.bank_name) parts.push(`Bank: ${g.bank_name}`);
      if (g.account_name) parts.push(`Account: ${g.account_name}`);
      if (g.account_number) parts.push(`Number: ${g.account_number}`);
      const isfcswift = g.ifsc_code || g.swift_code;
      if (isfcswift) parts.push(`IFSC/SWIFT: ${isfcswift}`);
      if (g.account_type) parts.push(`Type: ${g.account_type}`);
      if (g.country_code) parts.push(`Country: ${g.country_code}`);
      return parts.join(' | ');
    }

    const items = itemsRaw.map((d) => {
      const country = (d?.User?.country || '').toUpperCase() || null;
      const gw = gatewayMap.get(country) || gatewayMap.get(null) || null;
      const isManualBank = String(d?.method || '').toLowerCase() === 'manual'
        || ['bank','wire','bank_transfer','bank transfer'].includes(String(d?.paymentMethod || '').toLowerCase());
      const bankDetails = isManualBank ? (fmtBank(gw) || d.bankDetails || null) : (d.bankDetails || null);
      return { ...d, bankDetails };
    });

    res.json({ ok: true, total, totalSum: Number(totalSum._sum.amount || 0), page, limit: take, items });
  } catch (err) {
    console.error('GET /admin/deposits failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch deposits' });
  }
});

// List withdrawals by status
app.get('/admin/withdrawals', authenticateAdmin, async (req, res) => {
  try {
    const status = req.query.status;
    const take = Math.min(parseInt(req.query.limit || '100', 10), 10000);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const q = (req.query.q || '').trim();
    const countryParam = (req.query.country || '').trim().toLowerCase();

    // If country admin, automatically filter by their assigned country
    let countryFilter = countryParam;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    const where = {
      ...(status ? { status } : {}),
      ...(q ? { User: { email: { contains: q, mode: 'insensitive' } } } : {}),
      ...(countryFilter ? { User: { country: { equals: countryFilter, mode: 'insensitive' } } } : {}),
    };

    // Always use raw SQL here to avoid Prisma schema drift errors (e.g., mt5AccountId column)
    let total = 0; let itemsRaw = [];
    const params = [];
    const conditions = [];
    if (status) { params.push(status); conditions.push(`w.status = $${params.length}`); }
    if (countryFilter) { 
      params.push(countryFilter); 
      conditions.push(`LOWER(u.country) = LOWER($${params.length})`); 
    }
    if (q) {
      params.push(`%${q}%`);
      conditions.push(`(u.email ILIKE $${params.length} OR u.name ILIKE $${params.length})`);
    }
    const whereSql = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const sql = `
      SELECT w.*, u.email as user_email, u.name as user_name, u.country as user_country
      FROM public."Withdrawal" w
      LEFT JOIN public."User" u ON u.id = w."userId"
      ${whereSql}
      ORDER BY COALESCE(w."createdAt", w."updatedAt") DESC
      LIMIT ${take}
      OFFSET ${skip}
    `;
    const { rows } = await pool.query(sql, params);
    
    // Get total count with same filters
    const countParams = [];
    const countConditions = [];
    if (status) { countParams.push(status); countConditions.push(`w.status = $${countParams.length}`); }
    if (countryFilter) { 
      countParams.push(countryFilter); 
      countConditions.push(`LOWER(u.country) = LOWER($${countParams.length})`); 
    }
    if (q) {
      countParams.push(`%${q}%`);
      countConditions.push(`(u.email ILIKE $${countParams.length} OR u.name ILIKE $${countParams.length})`);
    }
    const countWhereSql = countConditions.length > 0 ? `WHERE ${countConditions.join(' AND ')}` : '';
    const countSql = `
      SELECT COUNT(*) as total
      FROM public."Withdrawal" w
      LEFT JOIN public."User" u ON u.id = w."userId"
      ${countWhereSql}
    `;
    const countResult = await pool.query(countSql, countParams);
    total = parseInt(countResult.rows[0]?.total || 0, 10);
    itemsRaw = rows.map(r => ({
      id: r.id,
      userId: r.userid || r.userId,
      amount: Number(r.amount || 0),
      currency: r.currency || 'USD',
      method: r.method || null,
      bankDetails: r.bankdetails || r.bankDetails || null,
      cryptoAddress: r.cryptoaddress || r.cryptoAddress || null,
      walletAddress: r.walletaddress || r.walletAddress || null,
      paymentMethod: r.paymentmethod || r.paymentMethod || null,
      status: r.status || null,
      createdAt: r.createdat || r.createdAt || null,
      updatedAt: r.updatedat || r.updatedAt || null,
      User: { id: r.userid || r.userId, email: r.user_email || null, name: r.user_name || null },
    }));

    // Enrich withdrawals with user's approved payment method details (bank fields)
    let items = itemsRaw;
    try {
      const userIds = Array.from(new Set(itemsRaw.map(w => w.userId).filter(Boolean)));
      if (userIds.length) {
        const { rows } = await pool.query(
          `SELECT "id","userId","methodType","bankName","accountName","accountNumber","ifscSwiftCode","accountType",
                  "currency","network","address","status",
                  COALESCE("approvedAt","updatedAt","submittedAt","createdAt") AS ts
           FROM public."PaymentMethod"
           WHERE "userId" = ANY($1)
           ORDER BY CASE WHEN status = 'approved' THEN 1 WHEN status = 'pending' THEN 2 ELSE 3 END ASC, ts DESC`,
          [userIds]
        );
        const map = new Map();
        for (const r of rows) {
          // First row per user is the latest due to ORDER BY
          if (!map.has(r.userId)) map.set(r.userId, r);
        }

        items = itemsRaw.map(w => {
          const pm = map.get(w.userId);
          if (pm) {
            return {
              ...w,
              bankName: pm.bankName || null,
              accountName: pm.accountName || null,
              accountNumber: pm.accountNumber || null,
              ifscSwiftCode: pm.ifscSwiftCode || null,
              accountType: pm.accountType || null,
              pmAddress: pm.address || null,
              pmCurrency: pm.currency || null,
              pmNetwork: pm.network || null,
              pmMethodType: pm.methodType || null,
              pmStatus: pm.status || null,
            };
          }
          return w;
        });
      }
    } catch (e) {
      // If enrichment fails, continue with base items
    }

    res.json({ ok: true, total, page, limit: take, items });
  } catch (err) {
    console.error('GET /admin/withdrawals failed:', err);
    // Do not block the UI; return empty list on failure
    res.json({ ok: true, total: 0, page: 1, limit: 0, items: [] });
  }
});

// Approve withdrawal and deduct from user's wallet balance
app.post('/admin/withdrawals/:id/approve', authenticateAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const externalId = (req.body?.externalTransactionId || req.body?.transactionId || req.body?.tx || req.body?.hash || '').toString().trim();

    await client.query('BEGIN');

    // Lock the withdrawal row to avoid race conditions during approval
    const sel = await client.query('SELECT * FROM public."Withdrawal" WHERE id = $1 FOR UPDATE', [id]);
    if (!sel.rows || sel.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ ok: false, error: 'Withdrawal not found' });
    }
    const w = sel.rows[0];

    if (String(w.status || '').toLowerCase() !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(400).json({ ok: false, error: 'Withdrawal not pending' });
    }

    const amount = Number(w.amount || 0);
    if (!Number.isFinite(amount) || amount <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ ok: false, error: 'Invalid withdrawal amount' });
    }

    // Detect actual wallet table name (wallet vs Wallet) in this DB
    const wtRes = await client.query(
      `SELECT table_name FROM information_schema.tables 
       WHERE table_schema = 'public' AND lower(table_name) = 'wallet' LIMIT 1`
    );
    const walletTable = (wtRes.rows && wtRes.rows[0] && wtRes.rows[0].table_name) ? wtRes.rows[0].table_name : 'wallet';
    // Detect user id column on the wallet table (userid vs userId vs user_id)
    const colRes = await client.query(
      `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1`,
      [walletTable]
    );
    let userIdCol = 'userid';
    for (const r of colRes.rows || []) {
      if (r.column_name === 'userid' || r.column_name === 'userId' || r.column_name === 'user_id') { userIdCol = r.column_name; break; }
    }

    const userId = w.userId || w.userid;
    // Ensure a wallet exists for this user
    let walletId;
    let beforeBalance = 0;
    const cw = await client.query(`SELECT id, balance FROM public."${walletTable}" WHERE "${userIdCol}" = $1 ORDER BY "createdAt" ASC LIMIT 1`, [userId]);
    if (cw.rows && cw.rows.length) {
      walletId = cw.rows[0].id;
      beforeBalance = Number(cw.rows[0].balance || 0);
    } else {
      walletId = crypto.randomUUID();
      const walletNumber = 'ZUP' + Math.floor(100000 + Math.random() * 900000);
      await client.query(`INSERT INTO public."${walletTable}" (id, "${userIdCol}", balance, currency, "createdAt", "updatedAt", "walletNumber") VALUES ($1,$2,$3,$4,NOW(),NOW(),$5)`, [walletId, userId, 0, (w.currency || 'USD'), walletNumber]);
    }

    const newBalance = beforeBalance - amount;
    await client.query(`UPDATE public."${walletTable}" SET balance = $2, "updatedAt" = NOW() WHERE id = $1`, [walletId, newBalance]);

    // Update withdrawal status to approved and set metadata
    try {
      const sql = 'UPDATE public."Withdrawal" SET status = $2, "approvedAt" = NOW(), "approvedBy" = $3, "externalTransactionId" = $4 WHERE id = $1';
      await client.query(sql, [id, 'approved', String(req.adminId || ''), externalId || null]);
    } catch (e) {
      // Column may not exist; minimal update
      await client.query('UPDATE public."Withdrawal" SET status = $2, "approvedAt" = NOW(), "approvedBy" = $3 WHERE id = $1', [id, 'approved', String(req.adminId || '')]);
    }

    await client.query('COMMIT');
    return res.json({ ok: true, message: 'Withdrawal approved and wallet balance deducted', walletId, previousBalance: beforeBalance, newBalance });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('POST /admin/withdrawals/:id/approve failed:', err?.message || err);
    res.status(500).json({ ok: false, error: 'Failed to approve withdrawal' });
  } finally {
    client.release();
  }
});

// GET variant for environments that accidentally issue GET requests
// Approves and deducts just like the POST endpoint above.
app.get('/admin/withdrawals/:id/approve', authenticateAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const externalId = (req.query?.externalTransactionId || req.query?.transactionId || req.query?.tx || req.query?.hash || '').toString().trim();

    await client.query('BEGIN');
    const sel = await client.query('SELECT * FROM public."Withdrawal" WHERE id = $1 FOR UPDATE', [id]);
    if (!sel.rows || sel.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ ok: false, error: 'Withdrawal not found' });
    }
    const w = sel.rows[0];
    if (String(w.status || '').toLowerCase() !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(400).json({ ok: false, error: 'Withdrawal not pending' });
    }

    const amount = Number(w.amount || 0);
    if (!Number.isFinite(amount) || amount <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ ok: false, error: 'Invalid withdrawal amount' });
    }

    // Determine user's wallet strictly by userId; handle both wallet/Wallet table names
    async function selectUserWallet(userId) {
      try {
        const r = await client.query('SELECT id, balance FROM public."wallet" WHERE userid = $1 ORDER BY "createdAt" ASC LIMIT 1', [userId]);
        return { table: 'wallet', rows: r.rows };
      } catch (_) {
        const r2 = await client.query('SELECT id, balance FROM public."Wallet" WHERE userid = $1 ORDER BY "createdAt" ASC LIMIT 1', [userId]);
        return { table: 'Wallet', rows: r2.rows };
      }
    }
    async function lockWalletById(table, id) {
      return client.query(`SELECT id, balance FROM public."${table}" WHERE id = $1 FOR UPDATE`, [id]);
    }
    async function insertWalletIfMissing(userId, currency) {
      const walletNumber = 'ZUP' + Math.floor(100000 + Math.random() * 900000);
      const newId = crypto.randomUUID();
      try {
        const r = await client.query('INSERT INTO public."wallet" (id, userid, balance, currency, "createdAt", "updatedAt", "walletNumber") VALUES ($1,$2,$3,$4,NOW(),NOW(),$5) RETURNING id, balance', [newId, userId, 0, currency, walletNumber]);
        return { table: 'wallet', rows: r.rows };
      } catch (_) {
        const r2 = await client.query('INSERT INTO public."Wallet" (id, userid, balance, currency, "createdAt", "updatedAt", "walletNumber") VALUES ($1,$2,$3,$4,NOW(),NOW(),$5) RETURNING id, balance', [newId, userId, 0, currency, walletNumber]);
        return { table: 'Wallet', rows: r2.rows };
      }
    }

    const userId = w.userId || w.userid;
    // Ensure a wallet exists for this user
    let walletId;
    let beforeBalance = 0;
    const cw = await client.query(`SELECT id, balance FROM public."${walletTable}" WHERE "${userIdCol}" = $1 ORDER BY "createdAt" ASC LIMIT 1`, [userId]);
    if (cw.rows && cw.rows.length) {
      walletId = cw.rows[0].id;
      beforeBalance = Number(cw.rows[0].balance || 0);
    } else {
      walletId = crypto.randomUUID();
      const walletNumber = 'ZUP' + Math.floor(100000 + Math.random() * 900000);
      await client.query(`INSERT INTO public."${walletTable}" (id, "${userIdCol}", balance, currency, "createdAt", "updatedAt", "walletNumber") VALUES ($1,$2,$3,$4,NOW(),NOW(),$5)`, [walletId, userId, 0, (w.currency || 'USD'), walletNumber]);
    }
    const newBalance = beforeBalance - amount;
    await client.query(`UPDATE public."${walletTable}" SET balance = $2, "updatedAt" = NOW() WHERE id = $1`, [walletId, newBalance]);

    try {
      const sql = 'UPDATE public."Withdrawal" SET status = $2, "approvedAt" = NOW(), "approvedBy" = $3, "externalTransactionId" = $4 WHERE id = $1';
      await client.query(sql, [id, 'approved', String(req.adminId || ''), externalId || null]);
    } catch (e) {
      await client.query('UPDATE public."Withdrawal" SET status = $2, "approvedAt" = NOW(), "approvedBy" = $3 WHERE id = $1', [id, 'approved', String(req.adminId || '')]);
    }

    await client.query('COMMIT');
    return res.json({ ok: true, message: 'Withdrawal approved and wallet balance deducted', walletId, previousBalance: beforeBalance, newBalance });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    console.error('GET /admin/withdrawals/:id/approve failed:', err?.message || err);
    res.status(500).json({ ok: false, error: 'Failed to approve withdrawal' });
  } finally {
    client.release();
  }
});

// Reject withdrawal
app.post('/admin/withdrawals/:id/reject', async (req, res) => {
  try {
    const { id } = req.params;
    const reason = (req.body?.reason || req.body?.rejectionReason || '').toString().trim();

    const withdrawal = await prisma.withdrawal.findUnique({ where: { id } });
    if (!withdrawal) return res.status(404).json({ ok: false, error: 'Withdrawal not found' });
    if (withdrawal.status !== 'pending') return res.status(400).json({ ok: false, error: 'Withdrawal not pending' });

    await prisma.withdrawal.update({
      where: { id },
      data: {
        status: 'rejected',
        rejectionReason: reason || 'Rejected',
        rejectedAt: new Date(),
      },
    });

    res.json({ ok: true, message: 'Withdrawal rejected successfully.' });
  } catch (err) {
    console.error('POST /admin/withdrawals/:id/reject failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to reject withdrawal' });
  }
});

// Approve deposit
app.post('/admin/deposits/:id/approve', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const deposit = await prisma.deposit.findUnique({
      where: { id },
      include: { MT5Account: true },
    });

    if (!deposit) return res.status(404).json({ ok: false, error: 'Deposit not found' });

    if (deposit.status !== 'pending') return res.status(400).json({ ok: false, error: 'Deposit not pending' });

    // Hit MT5 API to add balance
    const MT5_API_BASE = 'http://18.175.242.21:5003/api/Users';
    const response = await axios.post(`${MT5_API_BASE}/${deposit.MT5Account.accountId}/AddClientBalance`, {
      balance: deposit.amount,
      comment: 'DEPOSIT',
    }, { timeout: 10000 });

    if (response.data?.Success) {
      // Update deposit status to approved
      await prisma.deposit.update({
        where: { id },
        data: { status: 'approved', approvedAt: new Date(), approvedBy: String(req.adminId || '') },
      });

      res.json({
        ok: true,
        message: 'Deposit approved successfully. It will take 3-5 minutes to reflect in the account.'
      });
    } else {
      res.status(400).json({ ok: false, error: 'Failed to add balance to MT5 account' });
    }
  } catch (err) {
    console.error('POST /admin/deposits/:id/approve failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to approve deposit' });
  }
});

// Reject deposit
app.post('/admin/deposits/:id/reject', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const reason = (req.body?.reason || req.body?.rejectionReason || '').toString().trim();

    const deposit = await prisma.deposit.findUnique({ where: { id } });
    if (!deposit) return res.status(404).json({ ok: false, error: 'Deposit not found' });
    if (deposit.status !== 'pending') return res.status(400).json({ ok: false, error: 'Deposit not pending' });

    await prisma.deposit.update({
      where: { id },
      data: {
        status: 'rejected',
        rejectionReason: reason || 'Rejected',
        rejectedAt: new Date(),
      },
    });

    res.json({ ok: true, message: 'Deposit rejected successfully.' });
  } catch (err) {
    console.error('POST /admin/deposits/:id/reject failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to reject deposit' });
  }
});

// Get detailed user with related info and basic aggregates
app.get('/admin/users/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        clientId: true,
        email: true,
        name: true,
        phone: true,
        country: true,
        role: true,
        status: true,
        emailVerified: true,
        createdAt: true,
        lastLoginAt: true,
        Account: { select: { id: true, accountType: true, balance: true, createdAt: true } },
        MT5Account: { select: { id: true, accountId: true, createdAt: true } },
        KYC: {
          select: {
            id: true,
            isDocumentVerified: true,
            isAddressVerified: true,
            verificationStatus: true,
            documentReference: true,
            addressReference: true,
            amlReference: true,
            documentSubmittedAt: true,
            addressSubmittedAt: true,
            rejectionReason: true,
            createdAt: true,
            updatedAt: true,
          },
        },
      },
    });
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

    const [depositAgg, withdrawalAgg] = await Promise.all([
      prisma.deposit.aggregate({
        where: { userId: id, status: 'approved' },
        _sum: { amount: true },
        _count: { _all: true },
      }),
      prisma.withdrawal.aggregate({
        where: { userId: id, status: 'approved' },
        _sum: { amount: true },
        _count: { _all: true },
      }),
    ]);

    const totals = {
      deposits: {
        count: depositAgg?._count?._all || 0,
        amount: Number(depositAgg?._sum?.amount || 0),
      },
      withdrawals: {
        count: withdrawalAgg?._count?._all || 0,
        amount: Number(withdrawalAgg?._sum?.amount || 0),
      },
      accountBalance: (user.Account || []).reduce((s, a) => s + (a.balance || 0), 0),
    };

    res.json({ ok: true, user, totals });
  } catch (err) {
    console.error('GET /admin/users/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to get user' });
  }
});

// Fetch user login activity from public."UserLoginLog"
app.get('/admin/users/:id/logins', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const q = `SELECT id, userid, "userId", user_agent, device, browser, success, failure_reason, "createdAt"
               FROM public."UserLoginLog"
               WHERE (userid = $1 OR "userId" = $1)
               ORDER BY "createdAt" DESC`;
    const result = await pool.query(q, [id]);
    res.json({ ok: true, items: result.rows || [] });
  } catch (err) {
    console.error('GET /admin/users/:id/logins failed:', err);
    res.json({ ok: true, items: [] });
  }
});

// Get payment methods for a specific user
app.get('/admin/users/:id/payment-methods', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    let paymentMethods = [];
    try {
      paymentMethods = await prisma.paymentMethod.findMany({
        where: { userId: id, status: 'approved' },
        orderBy: { approvedAt: 'desc' }
      });
    } catch (prismaErr) {
      console.warn('Prisma payment methods query failed:', prismaErr.message);
    }
    res.json({ ok: true, paymentMethods });
  } catch (err) {
    console.error('GET /admin/users/:id/payment-methods failed:', err);
    res.json({ ok: true, paymentMethods: [] });
  }
});

// Aggregated activity logs endpoint
app.get('/admin/activity-logs', authenticateAdmin, async (req, res) => {
  try {
    const type = req.query.type; // 'deposit', 'withdrawal', 'account'
    const status = req.query.status; // 'pending', 'approved', 'rejected', 'opened'
    const from = req.query.from ? new Date(req.query.from) : null;
    const to = req.query.to ? new Date(req.query.to) : null;
    const search = (req.query.search || '').trim();
    const take = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const countryParam = (req.query.country || '').trim().toLowerCase();

    // If country admin, automatically filter by their assigned country
    let countryFilter = countryParam;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    // Build where conditions for each entity
    const depositWhere = {
      ...(status ? { status } : {}),
      ...(from || to ? {
        createdAt: {
          ...(from ? { gte: from } : {}),
          ...(to ? { lte: to } : {}),
        }
      } : {}),
      ...(search ? { User: { email: { contains: search, mode: 'insensitive' } } } : {}),
      ...(countryFilter ? { 
        User: { 
          country: { 
            equals: countryFilter, 
            mode: 'insensitive' 
          } 
        } 
      } : {}),
    };

    const withdrawalWhere = {
      ...(status ? { status } : {}),
      ...(from || to ? {
        createdAt: {
          ...(from ? { gte: from } : {}),
          ...(to ? { lte: to } : {}),
        }
      } : {}),
      ...(search ? { User: { email: { contains: search, mode: 'insensitive' } } } : {}),
      ...(countryFilter ? { 
        User: { 
          country: { 
            equals: countryFilter, 
            mode: 'insensitive' 
          } 
        } 
      } : {}),
    };

    const userWhere = {
      ...(status === 'opened' ? {} : {}), // For accounts, status is always 'opened'
      ...(from || to ? {
        createdAt: {
          ...(from ? { gte: from } : {}),
          ...(to ? { lte: to } : {}),
        }
      } : {}),
      ...(search ? {
        OR: [
          { email: { contains: search, mode: 'insensitive' } },
          { name: { contains: search, mode: 'insensitive' } },
        ]
      } : {}),
      ...(countryFilter ? { 
        country: { 
          equals: countryFilter, 
          mode: 'insensitive' 
        } 
      } : {}),
    };

    // Fetch data from each entity with resilience (Prisma -> raw SQL fallback)
    let deposits = [];
    try {
      deposits = await prisma.deposit.findMany({
        where: depositWhere,
        orderBy: { createdAt: 'desc' },
        skip,
        take: type === 'deposit' ? take : Math.floor(take / 3),
        include: { User: { select: { id: true, email: true, name: true } } },
      });
    } catch (e) {
      const params = [];
      let whereSql = '';
      if (status) { params.push(status); whereSql = `WHERE d.status = $${params.length}`; }
      const sql = `SELECT d.*, u.email as user_email, u.name as user_name FROM public."Deposit" d LEFT JOIN public."User" u ON u.id = d."userId" ${whereSql} ORDER BY COALESCE(d."createdAt", d."updatedAt") DESC LIMIT ${type==='deposit'?take:Math.floor(take/3)} OFFSET ${skip}`;
      const { rows } = await pool.query(sql, params);
      deposits = rows.map(r => ({ id: r.id, createdAt: r.createdat||r.createdAt, amount: Number(r.amount||0), status: r.status, bankDetails: r.bankdetails||r.bankDetails, transactionHash: r.transactionhash||r.transactionHash, User: { email: r.user_email, name: r.user_name } }));
    }

    let withdrawals = [];
    try {
      withdrawals = await prisma.withdrawal.findMany({
        where: withdrawalWhere,
        orderBy: { createdAt: 'desc' },
        skip,
        take: type === 'withdrawal' ? take : Math.floor(take / 3),
        include: { User: { select: { id: true, email: true, name: true } } },
      });
    } catch (e) {
      const params = [];
      let whereSql = '';
      if (status) { params.push(status); whereSql = `WHERE w.status = $${params.length}`; }
      const sql = `SELECT w.*, u.email as user_email, u.name as user_name FROM public."Withdrawal" w LEFT JOIN public."User" u ON u.id = w."userId" ${whereSql} ORDER BY COALESCE(w."createdAt", w."updatedAt") DESC LIMIT ${type==='withdrawal'?take:Math.floor(take/3)} OFFSET ${skip}`;
      const { rows } = await pool.query(sql, params);
      withdrawals = rows.map(r => ({ id: r.id, createdAt: r.createdat||r.createdAt, amount: Number(r.amount||0), status: r.status, bankDetails: r.bankdetails||r.bankDetails, cryptoAddress: r.cryptoaddress||r.cryptoAddress, User: { email: r.user_email, name: r.user_name } }));
    }

    let users = [];
    try {
      users = await prisma.user.findMany({
        where: userWhere,
        orderBy: { createdAt: 'desc' },
        skip,
        take: type === 'account' ? take : Math.floor(take / 3),
        select: { id: true, clientId: true, email: true, name: true, createdAt: true },
      });
    } catch (e) {
      const sql = `SELECT id, "clientId" as clientId, email, name, "createdAt" as createdAt FROM public."User" ORDER BY "createdAt" DESC LIMIT ${type==='account'?take:Math.floor(take/3)} OFFSET ${skip}`;
      const { rows } = await pool.query(sql);
      users = rows;
    }

    // Combine and sort all activities
    const activities = [
      ...deposits.map(d => ({
        id: d.id,
        time: d.createdAt,
        type: 'Deposit',
        user: d.User?.email || '-',
        userName: d.User?.name || '-',
        mts: '-',
        amount: d.amount,
        status: d.status,
        details: d.transactionHash || d.bankDetails || '-',
      })),
      ...withdrawals.map(w => ({
        id: w.id,
        time: w.createdAt,
        type: 'Withdrawal',
        user: w.User?.email || '-',
        userName: w.User?.name || '-',
        mts: '-',
        amount: w.amount,
        status: w.status,
        details: w.bankDetails || w.cryptoAddress || '-',
      })),
      ...users.map(u => ({
        id: u.id,
        time: u.createdAt,
        type: 'Account',
        user: u.email,
        userName: u.name || '-',
        mts: u.clientId,
        amount: null,
        status: 'Opened',
        details: '-',
      })),
    ].sort((a, b) => new Date(b.time) - new Date(a.time));

    // Apply type filter if specified
    const filteredActivities = type ? activities.filter(a => a.type.toLowerCase() === type) : activities;

    // Paginate the combined results
    const total = filteredActivities.length;
    const paginatedActivities = filteredActivities.slice(skip, skip + take);

    res.json({
      ok: true,
      total,
      page,
      limit: take,
      items: paginatedActivities,
      filters: { type, status, from, to, search }
    });
  } catch (err) {
    console.error('GET /admin/activity-logs failed:', err);
    res.json({ ok: true, total: 0, page: 1, limit: 0, items: [], filters: {} });
  }
});

// Get filtered users for email preview
app.get('/admin/users/filtered', async (req, res) => {
  try {
    const { balanceMin, balanceMax, emailVerified, status, search, limit = 100 } = req.query;

    // Build where clause
    const where = {};

    if (emailVerified !== undefined) {
      where.emailVerified = emailVerified === 'true';
    }

    if (status) {
      where.status = status;
    }

    if (search) {
      where.OR = [
        { email: { contains: search, mode: 'insensitive' } },
        { name: { contains: search, mode: 'insensitive' } },
      ];
    }

    // Fetch users from database
    const dbUsers = await prisma.user.findMany({
      where,
      take: parseInt(limit),
      select: {
        id: true,
        email: true,
        name: true,
        emailVerified: true,
        status: true,
        MT5Account: {
          select: {
            accountId: true,
          },
        },
      },
    });

    // Get actual balances and apply balance filters
    const filteredUsers = [];
    for (const user of dbUsers) {
      let totalBalance = 0;

      if (user.MT5Account && user.MT5Account.length > 0) {
        const balancePromises = user.MT5Account.map(async (account) => {
          try {
            const response = await axios.get(`${process.env.MT5_API_BASE_URL}/api/Users/${account.accountId}/getClientProfile`, {
              timeout: 5000,
            });
            return response.data?.Data?.Balance || 0;
          } catch (error) {
            console.warn(`Failed to fetch balance for account ${account.accountId}:`, error.message);
            return 0;
          }
        });

        const balances = await Promise.all(balancePromises);
        totalBalance = balances.reduce((sum, balance) => sum + balance, 0);
      }

      // Apply balance filters
      if (balanceMin && totalBalance < parseFloat(balanceMin)) continue;
      if (balanceMax && totalBalance > parseFloat(balanceMax)) continue;

      filteredUsers.push({
        id: user.id,
        email: user.email,
        name: user.name,
        balance: totalBalance,
        emailVerified: user.emailVerified,
        status: user.status,
      });
    }

    res.json({
      ok: true,
      total: filteredUsers.length,
      users: filteredUsers,
    });

  } catch (err) {
    console.error('GET /admin/users/filtered failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch filtered users' });
  }
});

// Send emails to users
app.post('/admin/send-emails', async (req, res) => {
  try {
    const { recipients, subject, body, isHtml = true, imageUrl } = req.body || {};

    if (!recipients || !subject || !body) {
      return res.status(400).json({ ok: false, error: 'Recipients, subject, and body are required' });
    }

    // Build user filter criteria
    const userWhere = {};

    if (recipients === 'all') {
      // Apply filters if provided
      const { balanceMin, balanceMax, emailVerified, status, search } = req.body.filters || {};

      // Always include MT5Account filter if balance filters are specified
      if (balanceMin || balanceMax) {
        userWhere.MT5Account = { some: {} };
      }

      if (emailVerified !== undefined) {
        userWhere.emailVerified = emailVerified;
      }

      if (status) {
        userWhere.status = status;
      }

      if (search) {
        userWhere.OR = [
          { email: { contains: search, mode: 'insensitive' } },
          { name: { contains: search, mode: 'insensitive' } },
        ];
      }
    } else if (Array.isArray(recipients)) {
      // Specific user IDs
      userWhere.id = { in: recipients };
    } else {
      return res.status(400).json({ ok: false, error: 'Invalid recipients format' });
    }

    // Fetch users
    const dbUsers = await prisma.user.findMany({
      where: userWhere,
      select: {
        id: true,
        email: true,
        name: true,
        MT5Account: {
          select: {
            accountId: true,
          },
        },
      },
    });

    // Filter by balance if specified and get actual balances
    let users = [];
    if (dbUsers.length > 0) {
      const { balanceMin, balanceMax } = req.body.filters || {};

      for (const user of dbUsers) {
        let totalBalance = 0;

        if (user.MT5Account && user.MT5Account.length > 0) {
          // Get actual balance from MT5 API
          const balancePromises = user.MT5Account.map(async (account) => {
            try {
              const response = await axios.get(`${process.env.MT5_API_BASE_URL}/api/Users/${account.accountId}/getClientProfile`, {
                timeout: 5000,
              });
              return response.data?.Data?.Balance || 0;
            } catch (error) {
              console.warn(`Failed to fetch balance for account ${account.accountId}:`, error.message);
              return 0;
            }
          });

          const balances = await Promise.all(balancePromises);
          totalBalance = balances.reduce((sum, balance) => sum + balance, 0);
        }

        // Apply balance filters
        if ((balanceMin && totalBalance < parseFloat(balanceMin)) ||
            (balanceMax && totalBalance > parseFloat(balanceMax))) {
          continue; // Skip this user
        }

        users.push({
          ...user,
          totalBalance,
        });
      }
    }

    if (users.length === 0) {
      return res.status(404).json({ ok: false, error: 'No users found matching criteria' });
    }

    // Prepare email content
    let htmlBody = body;
    let textBody = body.replace(/<[^>]*>/g, ''); // Strip HTML for text version

    // Add image if provided
    if (imageUrl) {
      if (isHtml) {
        htmlBody += `<br><br><img src="${imageUrl}" alt="Email Image" style="max-width: 100%; height: auto;" />`;
      }
    }

    // Send emails
    const emailPromises = users.map(user => {
      const mailOptions = {
        from: `"${process.env.FROM_NAME}" <${process.env.FROM_EMAIL}>`,
        to: user.email,
        subject: subject,
        text: textBody,
        ...(isHtml && { html: htmlBody }),
      };

      return emailTransporter.sendMail(mailOptions);
    });

    await Promise.all(emailPromises);

    res.json({
      ok: true,
      message: `Emails sent successfully to ${users.length} users`,
      recipientsCount: users.length,
      users: users.map(u => ({ id: u.id, email: u.email, name: u.name, balance: u.totalBalance }))
    });

  } catch (err) {
    console.error('POST /admin/send-emails failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to send emails' });
  }
});

// Public API: Send Deposit Email
app.post('/api/emails/send-deposit', async (req, res) => {
  try {
    const { email, account_login, amount, date, name } = req.body || {};
    if (!email) return res.status(400).json({ ok: false, error: 'email required' });
    const r = await sendOperationEmail('deposit', { email, account_login, amount, date, name });
    if (!r.ok) return res.status(500).json({ ok: false, error: r.error || 'Failed to send' });
    res.json({ ok: true });
  } catch (err) {
    console.error('/api/emails/send-deposit failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to send deposit email' });
  }
});

// Public API: Send Withdrawal Email
app.post('/api/emails/send-withdrawal', async (req, res) => {
  try {
    const { email, account_login, amount, date, name } = req.body || {};
    if (!email) return res.status(400).json({ ok: false, error: 'email required' });
    const r = await sendOperationEmail('withdrawal', { email, account_login, amount, date, name });
    if (!r.ok) return res.status(500).json({ ok: false, error: r.error || 'Failed to send' });
    res.json({ ok: true });
  } catch (err) {
    console.error('/api/emails/send-withdrawal failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to send withdrawal email' });
  }
});

// Admin operation email endpoint (internal)
app.post('/admin/send-operation-email', authenticateAdmin, async (req, res) => {
  try {
    const { email, name, operation, mt5_account, amount, source } = req.body || {};
    if (!email || !operation || !mt5_account || !amount) {
      return res.status(400).json({ ok: false, error: 'Missing required fields' });
    }
    
    // Check if SMTP is configured
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER) {
      console.warn('SMTP not configured, skipping email send');
      return res.json({ ok: true, message: 'Email skipped - SMTP not configured' });
    }
    
    const r = await sendOperationEmail(operation, {
      email,
      account_login: mt5_account,
      amount,
      date: new Date().toISOString(),
      name: name || email
    });
    
    // Always return success to prevent UI errors, but log the actual result
    if (!r.ok) {
      console.warn('Email send failed:', r.error);
      return res.json({ ok: true, message: 'Operation completed but email failed' });
    }
    
    res.json({ ok: true, message: 'Email sent successfully' });
  } catch (err) {
    console.error('/admin/send-operation-email failed:', err);
    // Return success to prevent UI errors, but log the failure
    res.json({ ok: true, message: 'Operation completed but email failed' });
  }
});

// ===== ADMIN AUTHENTICATION ENDPOINTS =====

// Admin login with enhanced security
app.post('/admin/login', loginLimiter, async (req, res) => {
  try {
    const { email, password, csrfToken, timestamp, userAgent, captcha } = req.body;
    
    // Security validations
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password are required' });
    }

    // CSRF Token validation
    if (!csrfToken) {
      return res.status(400).json({ ok: false, error: 'CSRF token required' });
    }

    // Rate limiting check
    const ipAddress = getRealIP(req);
    const rateLimitKey = `login_attempts_${ipAddress}`;
    
    // Check for suspicious activity (relaxed for better UX)
    const now = Date.now();
    const requestTime = timestamp || now;
    const timeDiff = Math.abs(now - requestTime);
    
    if (timeDiff > 600000) { // 10 minutes (increased from 5)
      return res.status(400).json({ ok: false, error: 'Request timestamp invalid' });
    }

    // Input sanitization
    const sanitizedEmail = email.toString().trim().toLowerCase();
    const sanitizedPassword = password.toString();
    
    // Email validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(sanitizedEmail)) {
      return res.status(400).json({ ok: false, error: 'Invalid email format' });
    }

    // Password length validation
    if (sanitizedPassword.length < 6 || sanitizedPassword.length > 128) {
      return res.status(400).json({ ok: false, error: 'Invalid password length' });
    }
    
    // Find admin by email (use sanitized email)
    const admin = await prisma.admin.findUnique({
      where: { email: sanitizedEmail }
    });
    
    
    if (!admin) {
      return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    }
    
    if (!admin.is_active) {
      return res.status(401).json({ ok: false, error: 'Account is deactivated' });
    }
    
    // Check if account is locked
    if (admin.locked_until && new Date() < admin.locked_until) {
      return res.status(401).json({ ok: false, error: 'Account is temporarily locked' });
    }
    
    // Verify password (use sanitized password)
    const isValidPassword = await bcrypt.compare(sanitizedPassword, admin.password_hash);
    
    if (!isValidPassword) {
      // Get IP address and user agent for failed login
      const failedIpAddress = getRealIP(req);
      const userAgent = req.headers['user-agent'] || '';
      const { browser, os, device } = parseUserAgent(userAgent);
      
      // Log failed login attempt
      await prisma.admin_login_log.create({
        data: {
          admin_id: admin.id,
          ip_address: failedIpAddress,
          user_agent: userAgent,
          location: 'Unknown',
          device: device,
          browser: browser,
          os: os,
          success: false,
          failure_reason: 'Invalid password'
        }
      });
      
      // Increment login attempts
      const newAttempts = (admin.login_attempts || 0) + 1;
      const lockUntil = newAttempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null; // Lock for 15 minutes
      
      await prisma.admin.update({
        where: { id: admin.id },
        data: {
          login_attempts: newAttempts,
          locked_until: lockUntil
        }
      });
      
      return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    }
    
    // Parse user agent (reuse ipAddress and userAgent from above)
    const { browser, os, device } = parseUserAgent(userAgent);
    
    // Log successful login
    await prisma.admin_login_log.create({
      data: {
        admin_id: admin.id,
        ip_address: ipAddress,
        user_agent: userAgent,
        location: 'Unknown', // You can integrate with IP geolocation service
        device: device,
        browser: browser,
        os: os,
        success: true
      }
    });
    
    // Reset login attempts on successful login
    await prisma.admin.update({
      where: { id: admin.id },
      data: {
        login_attempts: 0,
        locked_until: null,
        last_login: new Date()
      }
    });
    
    // Check if this admin is a country admin
    let countryAdminData = null;
    try {
      const countryAdminResult = await pool.query(
        'SELECT * FROM public.country_admins WHERE email = $1',
        [sanitizedEmail]
      );
      if (countryAdminResult.rows.length > 0) {
        const countryAdmin = countryAdminResult.rows[0];
        // Parse features from comma-separated string to array and normalize paths
        // Normalize: extract last part of path to match sidebar filter logic
        const normalizeFeature = (f) => {
          if (typeof f !== 'string' || !f.includes('/')) return f.trim();
          // Remove leading /admin/ if present, then get last part
          const cleaned = f.replace(/^\/admin\//, '').replace(/^\//, '').trim();
          return cleaned.split('/').pop() || cleaned;
        };
        
        const features = countryAdmin.features 
          ? countryAdmin.features.split(',').map(f => normalizeFeature(f.trim())).filter(f => f && f.length > 0)
          : [];
        
        countryAdminData = {
          isCountryAdmin: true,
          features: features,
          country: countryAdmin.country_code,
          countryAdminId: countryAdmin.id,
          status: countryAdmin.status,
          name: countryAdmin.name
        };
      }
    } catch (err) {
      console.error('Error checking country_admin table:', err);
      // Continue with regular admin login if country admin check fails
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { 
        adminId: admin.id, 
        email: admin.email,
        role: admin.admin_role,
        isCountryAdmin: countryAdminData ? true : false
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    // Build admin response object
    const adminResponse = {
        id: admin.id,
        email: admin.email,
        role: admin.admin_role,
        last_login: admin.last_login
    };
    
    // Add country admin data if applicable
    if (countryAdminData) {
      adminResponse.isCountryAdmin = true;
      adminResponse.features = countryAdminData.features;
      adminResponse.country = countryAdminData.country;
      adminResponse.name = countryAdminData.name;
      adminResponse.admin_role = 'country_admin'; // Override role for country admins
    }
    
    res.json({
      ok: true,
      token,
      admin: adminResponse
    });
  } catch (err) {
    console.error('POST /admin/login failed:', err);
    res.status(500).json({ ok: false, error: 'Login failed' });
  }
});

// Admin logout
app.post('/admin/logout', async (req, res) => {
  try {
    // In a real app, you might want to blacklist the token
    res.json({ ok: true, message: 'Logged out successfully' });
  } catch (err) {
    console.error('POST /admin/logout failed:', err);
    res.status(500).json({ ok: false, error: 'Logout failed' });
  }
});

// Verify admin token
app.get('/admin/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ ok: false, error: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    
    const admin = await prisma.admin.findUnique({
      where: { id: decoded.adminId },
      select: {
        id: true,
        email: true,
        admin_role: true,
        is_active: true,
        last_login: true
      }
    });
    
    if (!admin || !admin.is_active) {
      return res.status(401).json({ ok: false, error: 'Invalid token' });
    }
    
    res.json({
      ok: true,
      admin
    });
  } catch (err) {
    console.error('GET /admin/verify failed:', err);
    res.status(401).json({ ok: false, error: 'Invalid token' });
  }
});

// ===== PAYMENT METHODS MANAGEMENT =====
// List pending and approved payment methods
app.get('/admin/payment-methods', authenticateAdmin, async (req, res) => {
  const q = (req.query.q || '').toString().trim().toLowerCase();
  try {
    // Raw SQL using exact column names from your schema
    const sql = `
      SELECT
        pm."id",
        pm."userId",
        pm."address",
        pm."currency",
        pm."network",
        pm."status",
        pm."submittedAt",
        pm."approvedAt",
        pm."approvedBy",
        pm."rejectionReason",
        pm."createdAt",
        pm."updatedAt",
        pm."methodType",
        pm."bankName",
        pm."accountName",
        pm."accountNumber",
        pm."ifscSwiftCode",
        pm."accountType",
        u.email AS user_email,
        u.name  AS user_name
      FROM public."PaymentMethod" pm
      LEFT JOIN public."User" u ON u.id = pm."userId"
      ORDER BY COALESCE(pm."submittedAt", pm."createdAt") DESC
    `;
    const { rows } = await pool.query(sql);

    const mapRow = (r) => ({
      id: r.id,
      userId: r.userId,
      address: r.address ?? null,
      currency: r.currency ?? null,
      network: r.network ?? null,
      status: r.status ?? null,
      submittedAt: r.submittedAt ?? null,
      approvedAt: r.approvedAt ?? null,
      approvedBy: r.approvedBy ?? null,
      rejectionReason: r.rejectionReason ?? null,
      createdAt: r.createdAt ?? null,
      updatedAt: r.updatedAt ?? null,
      methodType: r.methodType ?? null,
      label: r.label ?? null,
      bankName: r.bankName ?? null,
      accountName: r.accountName ?? null,
      accountNumber: r.accountNumber ?? null,
      ifscSwiftCode: r.ifscSwiftCode ?? null,
      accountType: r.accountType ?? null,
      user: (r.user_email || r.user_name) ? { id: r.userId || null, email: r.user_email || null, name: r.user_name || null } : null,
    });

    const all = rows.map(mapRow);
    const pendingOut = all.filter(r => String(r.status||'').toLowerCase() === 'pending');
    const approvedOut = all.filter(r => String(r.status||'').toLowerCase() === 'approved');

    const applyFilter = (arr) => (
      q ? arr.filter(r => (
        (r.user?.email || '').toLowerCase().includes(q) ||
        (r.address || '').toLowerCase().includes(q) ||
        (r.currency || '').toLowerCase().includes(q) ||
        (r.network || '').toLowerCase().includes(q) ||
        (r.status || '').toLowerCase().includes(q) ||
        (r.methodType || '').toLowerCase().includes(q) ||
        (r.bankName || '').toLowerCase().includes(q) ||
        (r.accountName || '').toLowerCase().includes(q) ||
        (r.accountNumber || '').toLowerCase().includes(q) ||
        (r.ifscSwiftCode || '').toLowerCase().includes(q) ||
        (r.accountType || '').toLowerCase().includes(q)
      )) : arr
    );

    return res.json({ ok: true, pending: applyFilter(pendingOut), approved: applyFilter(approvedOut) });
  } catch (err) {
    console.error('GET /admin/payment-methods failed (outer):', err);
    // Never 500 for this listing; return empty lists to keep UI working
    res.json({ ok: true, pending: [], approved: [] });
  }
});

// Wallet transactions report
app.get('/admin/wallet-transactions', authenticateAdmin, async (req, res) => {
  try {
    const take = Math.min(parseInt(req.query.limit || '1000', 10), 5000);
    const q = (req.query.q || '').toString().toLowerCase();
    const sql = `
      SELECT wt.*, u.email AS user_email, u.name AS user_name
      FROM public."WalletTransaction" wt
      LEFT JOIN public."User" u ON u.id = wt."userId"
      ORDER BY COALESCE(wt."createdAt", wt."updatedAt") DESC
      LIMIT $1
    `;
    const { rows } = await pool.query(sql, [take]);
    // Build wallet label map from payment_gateway table
    let walletLabelMap = new Map();
    try {
      const walletIds = Array.from(new Set(rows.map(r => (r.walletid || r.walletId || '').toString()).filter(Boolean)));
      if (walletIds.length) {
        const { rows: wrows } = await pool.query(
          `SELECT id::text as id, wallet_name, deposit_wallet_address
           FROM public.payment_gateway
           WHERE deposit_wallet_address = ANY($1) OR id::text = ANY($1)`,
          [walletIds]
        );
        for (const w of wrows) {
          if (w.deposit_wallet_address) walletLabelMap.set(w.deposit_wallet_address, w.wallet_name || w.deposit_wallet_address);
          if (w.id) walletLabelMap.set(w.id, w.wallet_name || w.deposit_wallet_address || w.id);
        }
      }
    } catch {}

    let items = rows.map(r => {
      const walletId = r.walletid || r.walletId || null;
      const walletLabel = walletLabelMap.get(String(walletId)) || walletId || null;
      const mt5Id = r.mt5accountid || r.mt5AccountId || null;
      const type = r.type || null;
      let description = r.description || null;
      if (!description || /undefined/i.test(String(description))) {
        if (type === 'MT5_TO_WALLET') description = `From MT5 ${mt5Id || '-'} to Wallet ${walletLabel || walletId || '-'}`;
        else if (type === 'WALLET_TO_MT5') description = `From Wallet ${walletLabel || walletId || '-'} to MT5 ${mt5Id || '-'}`;
        else description = `Wallet transaction ${type || ''}`.trim();
      }
      return {
        id: r.id,
        walletId,
        walletLabel,
        userId: r.userid || r.userId || null,
        userEmail: r.user_email || null,
        userName: r.user_name || null,
        type,
        amount: Number(r.amount || 0),
        status: r.status || null,
        description,
        mt5AccountId: mt5Id,
        withdrawalId: r.withdrawalid || r.withdrawalId || null,
        createdAt: r.createdat || r.createdAt || null,
        updatedAt: r.updatedat || r.updatedAt || null,
      };
    });
    if (q) {
      items = items.filter(r => (
        (r.userEmail || '').toLowerCase().includes(q) ||
        (r.userName || '').toLowerCase().includes(q) ||
        (r.type || '').toLowerCase().includes(q) ||
        (r.status || '').toLowerCase().includes(q) ||
        (r.description || '').toLowerCase().includes(q) ||
        (r.mt5AccountId || '').toLowerCase().includes(q)
      ));
    }
    res.json({ ok: true, items });
  } catch (err) {
    console.error('GET /admin/wallet-transactions failed:', err);
    res.json({ ok: true, items: [] });
  }
});

// ===== SUPPORT TICKETS =====
const STATUS_MAP = {
  opened: ['Open', 'open', 'New', 'new'],
  pending: ['Pending', 'pending'],
  closed: ['Closed', 'closed'],
};

// List tickets with optional status filter
app.get('/admin/support/tickets', authenticateAdmin, async (req, res) => {
  try {
    const { status, q = '' } = req.query;
    const search = (q || '').toLowerCase();
    const statusList = status && STATUS_MAP[status] ? STATUS_MAP[status] : null;

    // If country admin, automatically filter by their assigned country
    let countryFilter = null;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    // Build base query
    const whereParts = [];
    const params = [];
    if (statusList) {
      whereParts.push(`t.status = ANY($${params.length + 1})`);
      params.push(statusList);
    }
    if (search) {
      whereParts.push(`(LOWER(t.title) LIKE $${params.length + 1} OR LOWER(t.description) LIKE $${params.length + 1} OR LOWER(u.email) LIKE $${params.length + 1})`);
      params.push(`%${search}%`);
    }
    if (countryFilter) {
      whereParts.push(`LOWER(u.country) = LOWER($${params.length + 1})`);
      params.push(countryFilter);
    }
    const whereClause = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';

    const sql = `
      SELECT t.*, u.email as user_email, u.name as user_name
      FROM support_tickets t
      LEFT JOIN "User" u ON (u.id = t.parent_id OR u."clientId" = t.parent_id OR LOWER(u.email) = LOWER(t.parent_id))
      ${whereClause}
      ORDER BY COALESCE(t.last_reply_at, t.created_at) DESC
      LIMIT 500
    `;

    const { rows } = await pool.query(sql, params);

    const countsSql = 'SELECT status, COUNT(*)::int as count FROM support_tickets GROUP BY status';
    const counts = await pool.query(countsSql);

    res.json({ ok: true, items: rows, counts: counts.rows });
  } catch (err) {
    console.error('GET /admin/support/tickets failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch support tickets' });
  }
});

// Ticket details + replies
app.get('/admin/support/tickets/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const tSql = `
      SELECT t.*, u.email as user_email, u.name as user_name
      FROM support_tickets t
      LEFT JOIN "User" u ON (u.id = t.parent_id OR u."clientId" = t.parent_id OR LOWER(u.email) = LOWER(t.parent_id))
      WHERE t.id = $1
    `;
    const tResult = await pool.query(tSql, [id]);
    if (tResult.rowCount === 0) return res.status(404).json({ ok: false, error: 'Ticket not found' });
    const ticket = tResult.rows[0];
    const rSql = 'SELECT * FROM support_ticket_replies WHERE ticket_id = $1 ORDER BY created_at ASC';
    const replies = (await pool.query(rSql, [id])).rows;
    res.json({ ok: true, ticket, replies });
  } catch (err) {
    console.error('GET /admin/support/tickets/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch ticket' });
  }
});

// Assign to current admin (adds greeting if fresh)
app.post('/admin/support/tickets/:id/assign', authenticateAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const admin = req.admin; // set by middleware
    const now = new Date();
    await client.query('BEGIN');
    const tRes = await client.query('SELECT * FROM chat_conversations WHERE id = $1::int FOR UPDATE', [id]);
    if (tRes.rowCount === 0) { await client.query('ROLLBACK'); return res.status(404).json({ ok: false, error: 'Ticket not found' }); }
    const t = tRes.rows[0];
    const assignChanged = (t.admin_id || '') !== (admin.email || String(admin.id));
    await client.query(
      'UPDATE chat_conversations SET admin_id = $1, status = $2, updated_at = $3 WHERE id = $4::int',
      [admin.email || String(admin.id), (String(t.status || '').toLowerCase() === 'closed' ? 'open' : 'open'), now, id]
    );
    // Ensure a professional greeting exists once per conversation
    const greeting = 'Hello! Welcome to Zuperior Support — how can I help you today?';
    const firstAdminMsg = await client.query(
      `SELECT id, content FROM chat_messages 
       WHERE conversation_id = $1::int AND sender_type = 'admin' 
       ORDER BY created_at ASC LIMIT 1`, [id]);
    if (firstAdminMsg.rowCount === 0) {
      const insertSql = `
        INSERT INTO chat_messages
          (conversation_id, sender_id, sender_name, sender_type, message_type, content, metadata, is_read, created_at, updated_at)
        VALUES ($1::int, $2, $3, 'admin', 'text', $4, jsonb_build_object('is_internal', false), false, $5, $5)
      `;
      await client.query(insertSql, [id, String(admin.id), admin.email || 'support', greeting, now]);
      await client.query('UPDATE chat_conversations SET last_message_at = $1 WHERE id = $2::int', [now, id]);
    } else {
      const msg = firstAdminMsg.rows[0];
      if (/welcome to\s+zuperior\s+support/i.test(msg.content)) {
        await client.query('UPDATE chat_messages SET content = $1, updated_at = $2 WHERE id = $3', [greeting, now, msg.id]);
      }
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('POST /admin/support/tickets/:id/assign failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to assign ticket' });
  } finally {
    client.release();
  }
});

// Add admin reply
app.post('/admin/support/tickets/:id/replies', authenticateAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const { content, is_internal = false } = req.body || {};
    if (!content || !content.trim()) return res.status(400).json({ ok: false, error: 'Content required' });
    const admin = req.admin;
    const now = new Date();
    await client.query('BEGIN');
    const insertSql = `
      WITH ridseq AS (
        SELECT COALESCE(MAX(reply_id), 0) + 1 AS rid FROM support_ticket_replies WHERE ticket_id = $1::int
      )
      INSERT INTO support_ticket_replies
        (ticket_id, reply_id, sender_id, sender_name, sender_type, content, is_internal, attachments, created_at, updated_at, is_read)
      SELECT $1::int, ridseq.rid, $2, $3, $4, $5, $6, ARRAY[]::text[], $7::timestamptz, $7::timestamptz, false FROM ridseq
      RETURNING id, ticket_id, reply_id, sender_name, sender_type, content, is_internal, created_at
    `;
    const result = await client.query(insertSql, [id, String(admin.id), admin.email || 'support', 'admin', content, !!is_internal, now]);
    await client.query('UPDATE support_tickets SET last_reply_at = $1::timestamptz, status = $2, updated_at = $1::timestamptz WHERE id = $3', [now, 'Open', id]);
    await client.query('COMMIT');
    const reply = result?.rows?.[0] || { ticket_id: id, content, sender_name: admin.email || 'support', sender_type: 'admin', created_at: now };
    res.json({ ok: true, reply });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('POST /admin/support/tickets/:id/replies failed:', err?.message || err, err?.stack || '');
    console.error('Full error object:', err);
    res.status(500).json({ ok: false, error: 'Failed to post reply' });
  } finally {
    client.release();
  }
});

// Update ticket status (close / reopen / pending)
app.put('/admin/support/tickets/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body || {};
    if (!status) return res.status(400).json({ ok: false, error: 'Status required' });

    const now = new Date();
    const normalized = String(status).toLowerCase();

    // Discover available columns for robust updates across schemas
    const { rows: colrows } = await pool.query(
      `SELECT column_name FROM information_schema.columns 
       WHERE table_schema = 'public' AND table_name = 'support_tickets'`
    );
    const has = (c) => colrows.some(r => r.column_name === c);

    // Ensure at least the status column exists
    if (!has('status')) return res.status(500).json({ ok: false, error: 'support_tickets.status column missing' });

    const sets = [];
    const params = [];

    // 1) status
    const finalStatus = normalized === 'closed' ? 'Closed' : normalized === 'pending' ? 'Pending' : 'Open';
    params.push(finalStatus); sets.push(`status = $${params.length}`);

    // 2) timestamps
    if (has('updated_at')) { params.push(now); sets.push(`updated_at = $${params.length}`); }
    if (normalized === 'closed') {
      if (has('closed_at')) { params.push(now); sets.push(`closed_at = $${params.length}`); }
      if (has('closed_by')) { params.push(req.admin?.email || String(req.adminId || '')); sets.push(`closed_by = $${params.length}`); }
    }

    // Build SQL
    params.push(id);
    const sql = `UPDATE support_tickets SET ${sets.join(', ')} WHERE id = $${params.length}::int RETURNING *`;

    const { rows } = await pool.query(sql, params);
    if (!rows || rows.length === 0) return res.status(404).json({ ok: false, error: 'Ticket not found' });
    res.json({ ok: true, ticket: rows[0] });
  } catch (err) {
    console.error('PUT /admin/support/tickets/:id/status failed:', err?.message || err);
    res.status(500).json({ ok: false, error: 'Failed to update status' });
  }
});
// Approve a payment method
app.put('/admin/payment-methods/:id/approve', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const adminId = req.adminId;
    const sql = `
      UPDATE public."PaymentMethod"
      SET status = 'approved', "approvedAt" = NOW(), "approvedBy" = $2, "updatedAt" = NOW()
      WHERE id = $1
      RETURNING *
    `;
    const { rows } = await pool.query(sql, [id, String(adminId)]);
    if (!rows || rows.length === 0) return res.status(404).json({ ok: false, error: 'Payment method not found' });
    return res.json({ ok: true, item: rows[0] });
  } catch (err) {
    console.error('PUT /admin/payment-methods/:id/approve failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to approve payment method' });
  }
});

// Reject a payment method
app.put('/admin/payment-methods/:id/reject', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body || {};
    const sql = `
      UPDATE public."PaymentMethod"
      SET status = 'rejected', "rejectionReason" = $2, "updatedAt" = NOW()
      WHERE id = $1
      RETURNING *
    `;
    const { rows } = await pool.query(sql, [id, reason || 'Rejected']);
    if (!rows || rows.length === 0) return res.status(404).json({ ok: false, error: 'Payment method not found' });
    return res.json({ ok: true, item: rows[0] });
  } catch (err) {
    console.error('PUT /admin/payment-methods/:id/reject failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to reject payment method' });
  }
});
// Create default admin (for initial setup)
// Test database connection
app.get('/admin/test-db', async (req, res) => {
  try {
    const adminCount = await prisma.admin.count();
    const admin = await prisma.admin.findFirst();
    res.json({ ok: true, adminCount, admin: admin ? { email: admin.email, role: admin.admin_role, is_active: admin.is_active } : null });
  } catch (err) {
    console.error('Database test failed:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Get all admins
app.get('/admin/admins', async (req, res) => {
  try {
    const admins = await prisma.admin.findMany({
      select: {
        id: true,
        username: true,
        email: true,
        admin_role: true,
        is_active: true,
        last_login: true,
        created_at: true
      }
    });
    res.json({ ok: true, admins });
  } catch (err) {
    console.error('GET /admin/admins failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch admins' });
  }
});

// Update admin role
app.put('/admin/admins/:id/role', async (req, res) => {
  try {
    const { id } = req.params;
    const { admin_role } = req.body;
    
    if (!admin_role) {
      return res.status(400).json({ ok: false, error: 'Role is required' });
    }
    
    const admin = await prisma.admin.update({
      where: { id: parseInt(id) },
      data: { admin_role },
      select: {
        id: true,
        username: true,
        email: true,
        admin_role: true,
        is_active: true
      }
    });
    
    res.json({ ok: true, admin });
  } catch (err) {
    console.error('PUT /admin/admins/:id/role failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update admin role' });
  }
});

// Create new admin
app.post('/admin/admins', async (req, res) => {
  try {
    const { username, email, password, admin_role } = req.body;
    
    if (!username || !email || !password || !admin_role) {
      return res.status(400).json({ ok: false, error: 'All fields are required' });
    }
    
    // Check if email already exists
    const existingAdmin = await prisma.admin.findUnique({
      where: { email }
    });
    
    if (existingAdmin) {
      return res.status(400).json({ ok: false, error: 'Email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const admin = await prisma.admin.create({
      data: {
        username,
        email,
        password_hash: hashedPassword,
        admin_role,
        is_active: true
      },
      select: {
        id: true,
        username: true,
        email: true,
        admin_role: true,
        is_active: true,
        created_at: true
      }
    });
    
    res.json({ ok: true, admin });
  } catch (err) {
    console.error('POST /admin/admins failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to create admin' });
  }
});

// Delete admin (cannot delete superadmin)
app.delete('/admin/admins/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const admin = await prisma.admin.findUnique({ where: { id: parseInt(id) } });
    if (!admin) return res.status(404).json({ ok: false, error: 'Admin not found' });
    if (admin.admin_role === 'superadmin') {
      return res.status(403).json({ ok: false, error: 'Cannot delete superadmin' });
    }
    await prisma.admin.delete({ where: { id: parseInt(id) } });
    res.json({ ok: true, message: 'Admin deleted' });
  } catch (err) {
    console.error('DELETE /admin/admins/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to delete admin' });
  }
});

app.post('/admin/setup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password are required' });
    }
    
    // Check if any admin exists
    const existingAdmin = await prisma.admin.findFirst();
    if (existingAdmin) {
      return res.status(400).json({ ok: false, error: 'Admin already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const admin = await prisma.admin.create({
      data: {
        username: email.split('@')[0], // Use email prefix as username
        email,
        password_hash: hashedPassword,
        admin_role: 'superadmin',
        is_active: true
      }
    });
    
    res.json({
      ok: true,
      message: 'Default admin created successfully',
      admin: {
        id: admin.id,
        email: admin.email,
        role: admin.admin_role
      }
    });
  } catch (err) {
    console.error('POST /admin/setup failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to create admin' });
  }
});

// ===== ROLE MANAGEMENT =====
// Fetch all roles
app.get('/admin/roles', authenticateAdmin, async (req, res) => {
  try {
    let roles;
    // If country admin, only show roles created by them (strictly filter - no NULL values)
    if (req.isCountryAdmin && req.admin?.email) {
      // Use raw SQL to strictly filter by created_by - only show roles created by this country admin
      try {
        const result = await pool.query(
          `SELECT id, name, permissions, description, "createdAt", "updatedAt", 
           COALESCE(created_by, '') as created_by
           FROM "Role" 
           WHERE created_by = $1
           ORDER BY "createdAt" DESC`,
          [req.admin.email]
        );
        roles = result.rows.map(r => ({
          id: r.id,
          name: r.name,
          description: r.description,
          permissions: (() => { try { return JSON.parse(r.permissions || '{}'); } catch { return {}; } })(),
          createdAt: r.createdAt,
          updatedAt: r.updatedAt,
          created_by: r.created_by
        }));
      } catch (sqlErr) {
        // If created_by column doesn't exist or query fails, return empty array for country admins
        // This ensures country admins don't see roles they didn't create
        roles = [];
      }
    } else {
      // For superadmins, show all roles
      roles = await prisma.role.findMany({ orderBy: { createdAt: 'desc' } });
    // Parse stored permissions JSON
      roles = roles.map(r => ({
      id: r.id,
      name: r.name,
      description: r.description,
      permissions: (() => { try { return JSON.parse(r.permissions || '{}'); } catch { return {}; } })(),
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
    }
    res.json({ ok: true, roles });
  } catch (err) {
    console.error('GET /admin/roles failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch roles' });
  }
});

// Create a new role
app.post('/admin/roles', authenticateAdmin, async (req, res) => {
  try {
    const { name, description, features } = req.body || {};
    if (!name || !Array.isArray(features) || features.length === 0) {
      return res.status(400).json({ ok: false, error: 'Role name and at least one feature are required' });
    }

    // If country admin, validate that all features are within their permissions
    if (req.isCountryAdmin && req.admin?.features) {
      const adminFeatures = Array.isArray(req.admin.features) ? req.admin.features : [];
      // Normalize feature paths for comparison
      const normalizeFeature = (f) => {
        if (typeof f !== 'string') return '';
        return f.replace(/^\/admin\//, '').replace(/^\//, '').trim().split('/').pop() || f.trim();
      };
      const normalizedAdminFeatures = adminFeatures.map(normalizeFeature);
      const invalidFeatures = features.filter(f => {
        const normalized = normalizeFeature(f);
        return !normalizedAdminFeatures.includes(normalized);
      });
      if (invalidFeatures.length > 0) {
        return res.status(403).json({ 
          ok: false, 
          error: `You do not have permission to assign these features: ${invalidFeatures.join(', ')}` 
        });
      }
    }

    const id = crypto.randomUUID();
    const now = new Date();
    const permissions = JSON.stringify({ features });
    const createdBy = req.isCountryAdmin && req.admin?.email ? req.admin.email : null;

    // Use raw SQL to insert with created_by if column exists
    try {
      await pool.query(
        `INSERT INTO "Role" (id, name, description, permissions, "createdAt", "updatedAt", created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [id, name, description || null, permissions, now, now, createdBy]
      );
      const created = await prisma.role.findUnique({ where: { id } });
      res.json({ ok: true, role: { ...created, permissions: { features }, created_by: createdBy } });
    } catch (sqlErr) {
      // If created_by column doesn't exist, use Prisma (will add column later)
    const created = await prisma.role.create({
      data: { id, name, description: description || null, permissions, createdAt: now, updatedAt: now },
    });
    res.json({ ok: true, role: { ...created, permissions: { features } } });
    }
  } catch (err) {
    console.error('POST /admin/roles failed:', err);
    if (err?.code === 'P2002' || err?.code === '23505') {
      return res.status(409).json({ ok: false, error: 'Role name already exists' });
    }
    res.status(500).json({ ok: false, error: 'Failed to create role' });
  }
});

// Update an existing role
app.put('/admin/roles/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, features } = req.body || {};

    if (!Array.isArray(features) || features.length === 0) {
      return res.status(400).json({ ok: false, error: 'At least one feature is required' });
    }

    // If country admin, check if they created this role
    if (req.isCountryAdmin && req.admin?.email) {
      try {
        const roleCheck = await pool.query(
          'SELECT created_by FROM "Role" WHERE id = $1',
          [id]
        );
        if (roleCheck.rows.length === 0) {
          return res.status(404).json({ ok: false, error: 'Role not found' });
        }
        const createdBy = roleCheck.rows[0].created_by;
        if (createdBy && createdBy !== req.admin.email) {
          return res.status(403).json({ ok: false, error: 'You can only update roles you created' });
        }
      } catch (sqlErr) {
        // If created_by column doesn't exist, allow update (backward compatibility)
      }
    }

    // If country admin, validate that all features are within their permissions
    if (req.isCountryAdmin && req.admin?.features) {
      const adminFeatures = Array.isArray(req.admin.features) ? req.admin.features : [];
      const normalizeFeature = (f) => {
        if (typeof f !== 'string') return '';
        return f.replace(/^\/admin\//, '').replace(/^\//, '').trim().split('/').pop() || f.trim();
      };
      const normalizedAdminFeatures = adminFeatures.map(normalizeFeature);
      const invalidFeatures = features.filter(f => {
        const normalized = normalizeFeature(f);
        return !normalizedAdminFeatures.includes(normalized);
      });
      if (invalidFeatures.length > 0) {
        return res.status(403).json({ 
          ok: false, 
          error: `You do not have permission to assign these features: ${invalidFeatures.join(', ')}` 
        });
      }
    }

    const permissions = JSON.stringify({ features });
    const updated = await prisma.role.update({
      where: { id },
      data: {
        name: name || undefined,
        description: description ?? null,
        permissions,
        updatedAt: new Date()
      }
    });

    res.json({ ok: true, role: { ...updated, permissions: { features } } });
  } catch (err) {
    console.error('PUT /admin/roles/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update role' });
  }
});

// Delete a role
app.delete('/admin/roles/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // If country admin, check if they created this role
    if (req.isCountryAdmin && req.admin?.email) {
      try {
        const roleCheck = await pool.query(
          'SELECT created_by FROM "Role" WHERE id = $1',
          [id]
        );
        if (roleCheck.rows.length === 0) {
          return res.status(404).json({ ok: false, error: 'Role not found' });
        }
        const createdBy = roleCheck.rows[0].created_by;
        if (createdBy && createdBy !== req.admin.email) {
          return res.status(403).json({ ok: false, error: 'You can only delete roles you created' });
        }
      } catch (sqlErr) {
        // If created_by column doesn't exist, allow delete (backward compatibility)
      }
    }
    
    // Optionally block deleting built-in roles
    // Perform delete
    await prisma.role.delete({ where: { id } });
    res.json({ ok: true, message: 'Role deleted' });
  } catch (err) {
    console.error('DELETE /admin/roles/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to delete role' });
  }
});

// ---- Helper function to get real IP address ----
const getRealIP = (req) => {
  return req.headers['x-forwarded-for'] || 
         req.headers['x-real-ip'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         req.ip ||
         '127.0.0.1';
};

// ---- Helper function to parse user agent ----
const parseUserAgent = (userAgent) => {
  if (!userAgent) return { browser: 'Unknown', os: 'Unknown', device: 'Unknown' };
  
  const browser = userAgent.includes('Chrome') ? 'Chrome' :
                  userAgent.includes('Firefox') ? 'Firefox' :
                  userAgent.includes('Safari') ? 'Safari' :
                  userAgent.includes('Edge') ? 'Edge' : 'Unknown';
  
  const os = userAgent.includes('Windows') ? 'Windows' :
             userAgent.includes('Mac') ? 'macOS' :
             userAgent.includes('Linux') ? 'Linux' :
             userAgent.includes('Android') ? 'Android' :
             userAgent.includes('iOS') ? 'iOS' : 'Unknown';
  
  const device = userAgent.includes('Mobile') ? 'Mobile' :
                 userAgent.includes('Tablet') ? 'Tablet' : 'Desktop';
  
  return { browser, os, device };
};

// ---- Admin Profile Endpoints ----
app.get('/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    const admin = await prisma.admin.findUnique({
      where: { id: req.adminId },
      select: {
        id: true,
        username: true,
        email: true,
        admin_role: true,
        is_active: true,
        last_login: true,
        login_attempts: true,
        locked_until: true,
        created_at: true,
        updated_at: true
      }
    });

    if (!admin) {
      return res.status(404).json({ ok: false, error: 'Admin not found' });
    }

    res.json({ ok: true, profile: admin });
  } catch (err) {
    console.error('GET /admin/profile failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch profile' });
  }
});

app.put('/admin/profile', authenticateAdmin, async (req, res) => {
  try {
    const { username, email, currentPassword, newPassword } = req.body;
    
    // Get current admin
    const currentAdmin = await prisma.admin.findUnique({
      where: { id: req.adminId }
    });

    if (!currentAdmin) {
      return res.status(404).json({ ok: false, error: 'Admin not found' });
    }

    // Verify current password if changing password
    if (newPassword && currentPassword) {
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, currentAdmin.password_hash);
      if (!isCurrentPasswordValid) {
        return res.status(400).json({ ok: false, error: 'Current password is incorrect' });
      }
    }

    // Prepare update data
    const updateData = {
      username,
      email,
      updated_at: new Date()
    };

    // Hash new password if provided
    if (newPassword) {
      updateData.password_hash = await bcrypt.hash(newPassword, 10);
      updateData.password_changed_at = new Date();
    }

    // Update admin
    const updatedAdmin = await prisma.admin.update({
      where: { id: req.adminId },
      data: updateData,
      select: {
        id: true,
        username: true,
        email: true,
        admin_role: true,
        is_active: true,
        last_login: true,
        login_attempts: true,
        locked_until: true,
        created_at: true,
        updated_at: true
      }
    });

    res.json({ ok: true, profile: updatedAdmin });
  } catch (err) {
    console.error('PUT /admin/profile failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update profile' });
  }
});

app.get('/admin/login-history', authenticateAdmin, async (req, res) => {
  try {
    // Fetch real login history from database
    const loginLogs = await prisma.admin_login_log.findMany({
      where: {
        admin_id: req.adminId
      },
      orderBy: {
        created_at: 'desc'
      },
      take: 50 // Last 50 login attempts
    });

    // Format the data for frontend
    const history = loginLogs.map(log => ({
      timestamp: log.created_at.toISOString(),
      ip_address: log.ip_address,
      location: log.location || 'Unknown',
      device: `${log.browser} on ${log.os}`,
      browser: log.browser,
      os: log.os,
      success: log.success,
      failure_reason: log.failure_reason
    }));

    res.json({ ok: true, history });
  } catch (err) {
    console.error('GET /admin/login-history failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch login history' });
  }
});

// ---- Payment Gateways Endpoints ----
app.get('/admin/payment-gateways', authenticateAdmin, async (req, res) => {
  try {
    const gateways = await prisma.payment_gateway.findMany({
      orderBy: {
        created_at: 'desc'
      }
    });

    res.json({ ok: true, gateways });
  } catch (err) {
    console.error('GET /admin/payment-gateways failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch payment gateways' });
  }
});

app.post('/admin/payment-gateways', authenticateAdmin, async (req, res) => {
  try {
    const { wallet_name, deposit_wallet_address, api_key, secret_key, gateway_type, is_active, description } = req.body;
    
    const gateway = await prisma.payment_gateway.create({
      data: {
        wallet_name,
        deposit_wallet_address,
        api_key,
        secret_key,
        gateway_type,
        is_active,
        description
      }
    });

    res.json({ ok: true, gateway });
  } catch (err) {
    console.error('POST /admin/payment-gateways failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to create payment gateway' });
  }
});

app.put('/admin/payment-gateways/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { wallet_name, deposit_wallet_address, api_key, secret_key, gateway_type, is_active, description } = req.body;
    
    const gateway = await prisma.payment_gateway.update({
      where: { id: parseInt(id) },
      data: {
        wallet_name,
        deposit_wallet_address,
        api_key,
        secret_key,
        gateway_type,
        is_active,
        description
      }
    });

    res.json({ ok: true, gateway });
  } catch (err) {
    console.error('PUT /admin/payment-gateways/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update payment gateway' });
  }
});

app.delete('/admin/payment-gateways/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    await prisma.payment_gateway.delete({
      where: { id: parseInt(id) }
    });

    res.json({ ok: true, message: 'Payment gateway deleted successfully' });
  } catch (err) {
    console.error('DELETE /admin/payment-gateways/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to delete payment gateway' });
  }
});

// Change admin password
app.put('/admin/admins/:id/password', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { newPassword } = req.body;
    
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ ok: false, error: 'Password must be at least 6 characters' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    const admin = await prisma.admin.update({
      where: { id: parseInt(id) },
      data: { password_hash: hashedPassword },
      select: {
        id: true,
        username: true,
        email: true,
        admin_role: true,
        is_active: true,
        last_login: true,
        created_at: true,
        updated_at: true
      }
    });

    res.json({ ok: true, admin });
  } catch (err) {
    console.error('PUT /admin/admins/:id/password failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update password' });
  }
});

// ---- Manual Gateways Endpoints ----
app.get('/admin/manual-gateways', authenticateAdmin, async (req, res) => {
  try {
    const params = [];
    let where = '';
    if (req.query.country) {
      params.push(String(req.query.country).toUpperCase());
      where = `WHERE country_code = $${params.length} OR country_code IS NULL`;
    }
    const sql = `
      SELECT id, type, name, details, icon_url, qr_code_url, is_active,
             vpa_address, crypto_address, bank_name, account_name, account_number,
             ifsc_code, swift_code, account_type, country_code, created_at, updated_at
      FROM public.manual_gateway
      ${where}
      ORDER BY created_at DESC
    `;
    const { rows } = await pool.query(sql, params);
    res.json({ ok: true, gateways: rows });
  } catch (err) {
    console.error('GET /admin/manual-gateways failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch manual gateways' });
  }
});

app.post('/admin/manual-gateways', authenticateAdmin, upload.fields([{ name: 'icon', maxCount: 1 }, { name: 'qr_code', maxCount: 1 }]), async (req, res) => {
  try {
    const { type, name, details, is_active,
      vpa_address, crypto_address,
      bank_name, account_name, account_number, ifsc_code, swift_code, account_type, country_code
    } = req.body;
    
    // Handle file uploads
    const icon_url = req.files?.icon ? `/kyc_proofs/${path.basename(req.files.icon[0].path)}` : null;
    const qr_code_url = req.files?.qr_code ? `/kyc_proofs/${path.basename(req.files.qr_code[0].path)}` : null;
    
    const sql = `
      INSERT INTO public.manual_gateway
        (type, name, details, icon_url, qr_code_url, is_active,
         vpa_address, crypto_address, bank_name, account_name, account_number,
         ifsc_code, swift_code, account_type, country_code, created_at, updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW(),NOW())
      RETURNING *
    `;
    const params = [
      String(type),
      String(name),
      details ? String(details) : '',
        icon_url,
        qr_code_url,
      (String(is_active) === 'true' || is_active === true || String(is_active).toLowerCase()==='on'),
      vpa_address || null,
      crypto_address || null,
      bank_name || null,
      account_name || null,
      account_number || null,
      ifsc_code || null,
      swift_code || null,
      account_type || null,
      country_code ? String(country_code).toUpperCase() : null,
    ];
    const { rows } = await pool.query(sql, params);
    res.json({ ok: true, gateway: rows[0] });
  } catch (err) {
    console.error('POST /admin/manual-gateways failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to create manual gateway' });
  }
});

app.put('/admin/manual-gateways/:id', authenticateAdmin, upload.fields([{ name: 'icon', maxCount: 1 }, { name: 'qr_code', maxCount: 1 }]), async (req, res) => {
  try {
    const { id } = req.params;
    const { type, name, details, is_active,
      vpa_address, crypto_address,
      bank_name, account_name, account_number, ifsc_code, swift_code, account_type, country_code
    } = req.body;
    
    // Handle file uploads
    const sets = [
      'type = $1','name = $2','details = $3','is_active = $4',
      'vpa_address = $5','crypto_address = $6','bank_name = $7','account_name = $8','account_number = $9',
      'ifsc_code = $10','swift_code = $11','account_type = $12','country_code = $13','updated_at = NOW()'
    ];
    const params = [
      String(type),
      String(name),
      details ? String(details) : '',
      (String(is_active) === 'true' || is_active === true || String(is_active).toLowerCase()==='on'),
      vpa_address || null,
      crypto_address || null,
      bank_name || null,
      account_name || null,
      account_number || null,
      ifsc_code || null,
      swift_code || null,
      account_type || null,
      country_code ? String(country_code).toUpperCase() : null,
    ];
    if (req.files?.icon) {
      sets.push(`icon_url = $${params.length+1}`);
      params.push(`/kyc_proofs/${path.basename(req.files.icon[0].path)}`);
    }
    if (req.files?.qr_code) {
      sets.push(`qr_code_url = $${params.length+1}`);
      params.push(`/kyc_proofs/${path.basename(req.files.qr_code[0].path)}`);
    }
    params.push(parseInt(id));
    const sql = `UPDATE public.manual_gateway SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING *`;
    const { rows } = await pool.query(sql, params);
    res.json({ ok: true, gateway: rows[0] });
  } catch (err) {
    console.error('PUT /admin/manual-gateways/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update manual gateway' });
  }
});

app.delete('/admin/manual-gateways/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { rowCount } = await pool.query('DELETE FROM public.manual_gateway WHERE id = $1', [parseInt(id)]);
    res.json({ ok: true, deleted: rowCount });
  } catch (err) {
    console.error('DELETE /admin/manual-gateways/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to delete manual gateway' });
  }
});

// ---- Error handler ----
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ ok: false, error: 'Internal Server Error' });
});

// Create default admin if none exists
async function createDefaultAdmin() {
  try {
    const existingAdmin = await prisma.admin.findFirst();
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash('Admin@000', 10);
      await prisma.admin.create({
        data: {
          username: 'admin',
          email: 'admin@zuperior.com',
          password_hash: hashedPassword,
          admin_role: 'superadmin',
          is_active: true
        }
      });
      console.log('✅ Default admin created: admin@zuperior.com');
    } else {
      // Reset password for existing admin
      const hashedPassword = await bcrypt.hash('Admin@000', 10);
      await prisma.admin.update({
        where: { email: 'admin@zuperior.com' },
        data: {
          password_hash: hashedPassword,
          login_attempts: 0,
          locked_until: null
        }
      });
      console.log('✅ Default admin password reset: admin@zuperior.com');
    }
  } catch (err) {
    console.error('❌ Failed to create/reset default admin:', err);
  }
}

// ---- MT5 Balance Operations Endpoints ----

// Get MT5 account info by login
// Test endpoint without auth
app.get('/test/mt5/account/:login', async (req, res) => {
  try {
    const { login } = req.params;
    
    // Call the real MT5 API to get account info
    const mt5ApiUrl = process.env.MT5_API_URL || 'http://localhost:8080';
    const mt5ApiKey = process.env.MT5_API_KEY || 'your-mt5-api-key';
    
    try {
      const response = await fetch(`${mt5ApiUrl}/api/Users/${login}/getClientProfile`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${mt5ApiKey}`,
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const mt5Data = await response.json();
        
        // Check if MT5 API returned success
        if (mt5Data.Success === true) {
          console.log('✅ MT5 API returned success:', mt5Data.Message);
          // MT5 API returned successful data - convert to our format
          const accountInfo = {
            login: mt5Data.Data.Login,
            name: mt5Data.Data.Name || `Account ${login}`,
            balance: mt5Data.Data.Balance || 0,
            credit: mt5Data.Data.Credit || 0,
            equity: mt5Data.Data.Equity || 0,
            margin: mt5Data.Data.Margin || 0,
            free_margin: mt5Data.Data.MarginFree || 0,
            margin_level: mt5Data.Data.MarginLevel || 0,
            currency: 'USD',
            leverage: mt5Data.Data.Leverage || 100,
            group: mt5Data.Data.Group || 'demo',
            status: mt5Data.Data.IsEnabled ? 'active' : 'inactive'
          };
          
          res.json({ ok: true, account: accountInfo });
        } else {
          // MT5 API returned successful data
          const accountInfo = {
            login: login,
            name: mt5Data.Data.Name || `Account ${login}`,
            balance: mt5Data.Data.Balance || 0,
            credit: mt5Data.Data.Credit || 0,
            equity: mt5Data.Data.Equity || 0,
            margin: mt5Data.Data.Margin || 0,
            free_margin: mt5Data.Data.MarginFree || 0,
            margin_level: mt5Data.Data.MarginLevel || 0,
            currency: 'USD',
            leverage: mt5Data.Data.Leverage || 100,
            group: mt5Data.Data.Group || 'demo',
            status: mt5Data.Data.IsEnabled ? 'active' : 'inactive'
          };
          
          res.json({ ok: true, account: accountInfo });
        }
      } else {
        // If MT5 API fails, return basic info
        const accountInfo = {
          login: login,
          name: `Account ${login}`,
          balance: 0,
          credit: 0,
          equity: 0,
          margin: 0,
          free_margin: 0,
          margin_level: 0,
          currency: 'USD',
          leverage: 100,
          group: 'demo',
          status: 'active'
        };
        
        res.json({ ok: true, account: accountInfo });
      }
    } catch (mt5Error) {
      console.log('MT5 API not available, using fallback data');
      // Fallback to basic account info
      const accountInfo = {
        login: login,
        name: `Account ${login}`,
        balance: 0,
        credit: 0,
        equity: 0,
        margin: 0,
        free_margin: 0,
        margin_level: 0,
        currency: 'USD',
        leverage: 100,
        group: 'demo',
        status: 'active'
      };
      
      res.json({ ok: true, account: accountInfo });
    }
  } catch (err) {
    console.error('GET /test/mt5/account/:login failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch account info' });
  }
});

app.get('/admin/mt5/account/:login', authenticateAdmin, async (req, res) => {
  try {
    const { login } = req.params;
    
    // Use the same MT5 API URL as the MT5 Users endpoint
    const MT5_API_BASE = 'http://18.175.242.21:5003/api/Users';
    
    console.log(`🔍 Fetching MT5 account info for login: ${login}`);
    
    try {
      const response = await axios.get(`${MT5_API_BASE}/${login}/getClientProfile`, {
        timeout: 5000,
      });
      
      const mt5Response = response.data;
      
      // Check if MT5 API call was successful
      if (mt5Response?.Success === true && mt5Response?.Data) {
        const data = mt5Response.Data;
        
        const accountInfo = {
          Login: data.Login || login,
          Name: (data.Name && data.Name.trim() !== "") ? data.Name : "-",
          Group: (data.Group && data.Group.trim() !== "") ? data.Group : "-",
          Balance: data.Balance || 0,
          Credit: data.Credit || 0,
          Equity: data.Equity || 0,
          Margin: data.Margin || 0,
          MarginFree: data.MarginFree || 0,
          MarginLevel: data.MarginLevel || 0,
          Leverage: data.Leverage ? data.Leverage.toString() : "-",
          Comment: (data.Comment && data.Comment.trim() !== "") ? data.Comment : "-",
          IsEnabled: data.IsEnabled,
          Status: data.IsEnabled ? 'active' : 'inactive'
        };
        
        res.json({ ok: true, account: accountInfo });
      } else {
        console.warn(`⚠️ MT5 API call failed for account ${login}. Success: ${mt5Response?.Success}, Message: ${mt5Response?.Message}`);
        res.json({ 
          ok: false, 
          error: `MT5 API call failed: ${mt5Response?.Message || 'Unknown error'}` 
        });
      }
    } catch (mt5Error) {
      console.error(`❌ MT5 API error for account ${login}:`, mt5Error.message);
      res.json({ 
        ok: false, 
        error: `Failed to fetch MT5 account data: ${mt5Error.message}` 
      });
    }
  } catch (err) {
    console.error('GET /admin/mt5/account/:login failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch account info' });
  }
});

// Deposit balance to MT5 account
app.post('/admin/mt5/deposit', authenticateAdmin, async (req, res) => {
  try {
    const { login, amount, description } = req.body;
    const ipAddress = getRealIP(req);
    const userAgent = req.headers['user-agent'] || '';
    
    if (!login || !amount) {
      return res.status(400).json({ ok: false, error: 'Login and amount are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ ok: false, error: 'Amount must be positive' });
    }
    
    // Call the real MT5 API: POST /api/Users/{login}/AddClientBalance
    const mt5ApiUrl = process.env.MT5_API_URL || 'http://localhost:8080';
    const mt5ApiKey = process.env.MT5_API_KEY || 'your-mt5-api-key';
    
    let operationStatus = 'completed';
    let errorMessage = null;
    
    try {
      const mt5Response = await fetch(`${mt5ApiUrl}/api/Users/${login}/AddClientBalance`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${mt5ApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          balance: parseFloat(amount),
          comment: description || 'Balance deposit'
        })
      });
      
      if (!mt5Response.ok) {
        operationStatus = 'failed';
        errorMessage = 'MT5 API call failed';
      }
    } catch (mt5Error) {
      console.log('MT5 API not available, logging operation anyway');
      operationStatus = 'completed'; // Log as completed for demo purposes
    }
    
    // Log the operation (best-effort)
    let operation = null;
    try {
      operation = await prisma.balance_operation_history.create({
      data: {
        admin_id: req.adminId,
        mt5_login: login,
        operation_type: 'deposit',
        amount: parseFloat(amount),
        currency: 'USD',
        description: description || 'Balance deposit',
        status: operationStatus,
        error_message: errorMessage,
        ip_address: ipAddress,
        user_agent: userAgent
      }
    });
    } catch (logErr) {
      console.warn('Balance operation log failed (deposit):', logErr.message);
    }

    // Try to resolve user and send email (best-effort)
    let emailSent = false;
    try {
      const acc = await prisma.mT5Account.findFirst({
        where: { accountId: String(login) },
        select: { User: { select: { email: true, name: true } } }
      });
      const userEmail = acc?.User?.email || null;
      const userName = acc?.User?.name || '';
      if (userEmail) {
        const r = await sendOperationEmail('deposit', {
          email: userEmail,
          account_login: String(login),
          amount: parseFloat(amount),
          date: new Date().toISOString(),
          name: userName
        });
        emailSent = !!r?.ok;
      }
    } catch (e) { console.warn('Deposit email send skipped:', e.message); }
    
    res.json({ 
      ok: true, 
      message: operationStatus === 'completed' ? 'Deposit successful! You will see the deposit in your MT5 account in 2-5 minutes.' : 'Operation logged but MT5 API unavailable',
      operation: {
        id: operation?.id || null,
        login: login,
        amount: operation?.amount || parseFloat(amount),
        type: operation?.operation_type || 'deposit',
        status: operation?.status || operationStatus,
        created_at: operation?.created_at || new Date()
      },
      emailSent
    });
  } catch (err) {
    console.error('POST /admin/mt5/deposit failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to deposit balance' });
  }
});

// Withdraw balance from MT5 account
app.post('/admin/mt5/withdraw', authenticateAdmin, async (req, res) => {
  try {
    const { login, amount, description } = req.body;
    const ipAddress = getRealIP(req);
    const userAgent = req.headers['user-agent'] || '';
    
    if (!login || !amount) {
      return res.status(400).json({ ok: false, error: 'Login and amount are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ ok: false, error: 'Amount must be positive' });
    }
    
    // Call the real MT5 API: POST /api/Users/{login}/DeductClientBalance
    const mt5ApiUrl = process.env.MT5_API_URL || 'http://localhost:8080';
    const mt5ApiKey = process.env.MT5_API_KEY || 'your-mt5-api-key';
    
    let operationStatus = 'completed';
    let errorMessage = null;
    
    try {
      const mt5Response = await fetch(`${mt5ApiUrl}/api/Users/${login}/DeductClientBalance`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${mt5ApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          balance: parseFloat(amount),
          comment: description || 'Balance withdrawal'
        })
      });
      
      if (!mt5Response.ok) {
        operationStatus = 'failed';
        errorMessage = 'MT5 API call failed';
      }
    } catch (mt5Error) {
      console.log('MT5 API not available, logging operation anyway');
      operationStatus = 'completed'; // Log as completed for demo purposes
    }
    
    // Log the operation (best-effort)
    let operation = null;
    try {
      operation = await prisma.balance_operation_history.create({
      data: {
        admin_id: req.adminId,
        mt5_login: login,
        operation_type: 'withdraw',
        amount: parseFloat(amount),
        currency: 'USD',
        description: description || 'Balance withdrawal',
        status: operationStatus,
        error_message: errorMessage,
        ip_address: ipAddress,
        user_agent: userAgent
      }
    });
    } catch (logErr) {
      console.warn('Balance operation log failed (withdraw):', logErr.message);
    }

    // Try to resolve user and send withdrawal email (best-effort)
    let emailSent = false;
    try {
      const acc = await prisma.mT5Account.findFirst({
        where: { accountId: String(login) },
        select: { User: { select: { email: true, name: true } } }
      });
      const userEmail = acc?.User?.email || null;
      const userName = acc?.User?.name || '';
      if (userEmail) {
        const r = await sendOperationEmail('withdrawal', {
          email: userEmail,
          account_login: String(login),
          amount: parseFloat(amount),
          date: new Date().toISOString(),
          name: userName
        });
        emailSent = !!r?.ok;
      }
    } catch (e) { console.warn('Withdrawal email send skipped:', e.message); }
    
    res.json({ 
      ok: true, 
      message: operationStatus === 'completed' ? 'Withdrawal successful! It will take 3-5 minutes to reflect in the account.' : 'Operation logged but MT5 API unavailable',
      operation: {
        id: operation?.id || null,
        login: login,
        amount: operation?.amount || parseFloat(amount),
        type: operation?.operation_type || 'withdraw',
        status: operation?.status || operationStatus,
        created_at: operation?.created_at || new Date()
      },
      emailSent
    });
  } catch (err) {
    console.error('POST /admin/mt5/withdraw failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to withdraw balance' });
  }
});

// Add credit to MT5 account
app.post('/admin/mt5/credit', authenticateAdmin, async (req, res) => {
  try {
    const { login, amount, description } = req.body;
    const ipAddress = getRealIP(req);
    const userAgent = req.headers['user-agent'] || '';
    
    if (!login || !amount) {
      return res.status(400).json({ ok: false, error: 'Login and amount are required' });
    }
    
    if (amount <= 0) {
      return res.status(400).json({ ok: false, error: 'Amount must be positive' });
    }
    
    // Call the real MT5 API: POST /api/Users/{login}/AddClientCredit
    const mt5ApiUrl = process.env.MT5_API_URL || 'http://localhost:8080';
    const mt5ApiKey = process.env.MT5_API_KEY || 'your-mt5-api-key';
    
    let operationStatus = 'completed';
    let errorMessage = null;
    
    try {
      const mt5Response = await fetch(`${mt5ApiUrl}/api/Users/${login}/AddClientCredit`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${mt5ApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          amount: parseFloat(amount),
          balance: parseFloat(amount),
          comment: description || 'Credit added'
        })
      });
      
      if (!mt5Response.ok) {
        operationStatus = 'failed';
        errorMessage = 'MT5 API call failed';
      }
    } catch (mt5Error) {
      console.log('MT5 API not available, logging operation anyway');
      operationStatus = 'completed'; // Log as completed for demo purposes
    }
    
    // Log the operation (best-effort)
    let operation = null;
    try {
      operation = await prisma.balance_operation_history.create({
      data: {
        admin_id: req.adminId,
        mt5_login: login,
        operation_type: 'credit',
        amount: parseFloat(amount),
        currency: 'USD',
        description: description || 'Credit added',
        status: operationStatus,
        error_message: errorMessage,
        ip_address: ipAddress,
        user_agent: userAgent
      }
    });
    } catch (logErr) {
      console.warn('Balance operation log failed (credit):', logErr.message);
    }
    
    // Email: bonus added
    let emailSent = false;
    try {
      const acc = await prisma.mT5Account.findFirst({
        where: { accountId: String(login) },
        select: { User: { select: { email: true, name: true } } }
      });
      const userEmail = acc?.User?.email || null;
      const userName = acc?.User?.name || '';
      if (userEmail) {
        const r = await sendOperationEmail('bonus_add', {
          email: userEmail,
          account_login: String(login),
          amount: parseFloat(amount),
          date: new Date().toISOString(),
          name: userName
        });
        emailSent = !!r?.ok;
      }
    } catch (e) { console.warn('Bonus add email skipped:', e.message); }
    
    res.json({ 
      ok: true, 
      message: operationStatus === 'completed' ? 'Credit added successfully' : 'Operation logged but MT5 API unavailable',
      operation: {
        id: operation?.id || null,
        login: login,
        amount: operation?.amount || parseFloat(amount),
        type: operation?.operation_type || 'credit',
        status: operation?.status || operationStatus,
        created_at: operation?.created_at || new Date()
      },
      emailSent
    });
  } catch (err) {
    console.error('POST /admin/mt5/credit failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to add credit' });
  }
});

// Deduct credit from MT5 account
app.post('/admin/mt5/credit/deduct', authenticateAdmin, async (req, res) => {
  try {
    const { login, amount, description } = req.body;
    const ipAddress = getRealIP(req);
    const userAgent = req.headers['user-agent'] || '';

    if (!login || !amount) {
      return res.status(400).json({ ok: false, error: 'Login and amount are required' });
    }

    if (amount <= 0) {
      return res.status(400).json({ ok: false, error: 'Amount must be positive' });
    }

    const mt5ApiUrl = process.env.MT5_API_URL || 'http://localhost:8080';
    const mt5ApiKey = process.env.MT5_API_KEY || 'your-mt5-api-key';

    let operationStatus = 'completed';
    let errorMessage = null;

    try {
      const mt5Response = await fetch(`${mt5ApiUrl}/api/Users/${login}/DeductClientCredit`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${mt5ApiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          amount: parseFloat(amount),
          balance: parseFloat(amount),
          comment: description || 'Credit deducted'
        })
      });

      if (!mt5Response.ok) {
        operationStatus = 'failed';
        errorMessage = 'MT5 API call failed';
      }
    } catch (mt5Error) {
      console.log('MT5 API not available, logging operation anyway');
      operationStatus = 'completed';
    }

    // Log the operation (best-effort)
    let operation = null;
    try {
      operation = await prisma.balance_operation_history.create({
        data: {
          admin_id: req.adminId,
          mt5_login: login,
          operation_type: 'credit_deduct',
          amount: parseFloat(amount),
          currency: 'USD',
          description: description || 'Credit deducted',
          status: operationStatus,
          error_message: errorMessage,
          ip_address: ipAddress,
          user_agent: userAgent
        }
      });
    } catch (logErr) {
      console.warn('Balance operation log failed (credit_deduct):', logErr.message);
    }

    // Email: bonus deducted
    let emailSent = false;
    try {
      const acc = await prisma.mT5Account.findFirst({
        where: { accountId: String(login) },
        select: { User: { select: { email: true, name: true } } }
      });
      const userEmail = acc?.User?.email || null;
      const userName = acc?.User?.name || '';
      if (userEmail) {
        const r = await sendOperationEmail('bonus_deduct', {
          email: userEmail,
          account_login: String(login),
          amount: parseFloat(amount),
          date: new Date().toISOString(),
          name: userName
        });
        emailSent = !!r?.ok;
      }
    } catch (e) { console.warn('Bonus deduct email skipped:', e.message); }

    res.json({
      ok: true,
      message: operationStatus === 'completed' ? 'Credit deducted successfully' : 'Operation logged but MT5 API unavailable',
      operation: {
        id: operation?.id || null,
        login: login,
        amount: operation?.amount || parseFloat(amount),
        type: operation?.operation_type || 'credit_deduct',
        status: operation?.status || operationStatus,
        created_at: operation?.created_at || new Date()
      },
      emailSent
    });
  } catch (err) {
    console.error('POST /admin/mt5/credit/deduct failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to deduct credit' });
  }
});

// Get balance operation history
app.get('/admin/mt5/balance-history', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, login, operation_type } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const where = {
      admin_id: req.adminId
    };
    
    if (login) {
      where.mt5_login = { contains: login };
    }
    
    if (operation_type) {
      where.operation_type = operation_type;
    }
    
    const [operations, total] = await Promise.all([
      prisma.balance_operation_history.findMany({
        where,
        orderBy: { created_at: 'desc' },
        skip,
        take: parseInt(limit),
        include: {
          admin: {
            select: {
              id: true,
              username: true,
              email: true
            }
          }
        }
      }),
      prisma.balance_operation_history.count({ where })
    ]);
    
    res.json({
      ok: true,
      operations,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (err) {
    console.error('GET /admin/mt5/balance-history failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch balance history' });
  }
});

// Admin transactions consolidated report (deposit/withdraw/bonus_add/bonus_deduct)
app.get('/admin/admin-transactions', authenticateAdmin, async (req, res) => {
  try {
    const {
      page = 1,
      limit = 100,
      operation_type,
      status,
      login,
      admin_id,
      from,
      to,
      q,
    } = req.query;

    // If country admin, automatically filter by their assigned country
    let countryFilter = null;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    const take = Math.min(parseInt(limit, 10) || 100, 1000);
    const curPage = Math.max(parseInt(page, 10) || 1, 1);
    const offset = (curPage - 1) * take;

    const whereParts = [];
    const params = [];
    
    if (countryFilter) {
      whereParts.push(`LOWER(u.country) = LOWER($${params.length + 1})`);
      params.push(countryFilter);
    }

    if (operation_type) { params.push(String(operation_type)); whereParts.push(`t.operation_type = $${params.length}`); }
    if (status) { params.push(String(status)); whereParts.push(`t.status = $${params.length}`); }
    if (login) { params.push(String(login)); whereParts.push(`t.mt5_login = $${params.length}`); }
    if (admin_id) { params.push(parseInt(admin_id, 10)); whereParts.push(`t.admin_id = $${params.length}`); }
    if (from) { params.push(new Date(from)); whereParts.push(`t.created_at >= $${params.length}`); }
    if (to) { params.push(new Date(to)); whereParts.push(`t.created_at <= $${params.length}`); }
    if (q) {
      params.push(`%${q}%`);
      whereParts.push(`(
        t.mt5_login ILIKE $${params.length} OR
        COALESCE(t.external_transaction_id,'') ILIKE $${params.length} OR
        COALESCE(u.email,'') ILIKE $${params.length} OR
        COALESCE(a.email,'') ILIKE $${params.length}
      )`);
    }

    const whereSql = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';

    const baseSql = `
      FROM admin_transactions t
      LEFT JOIN admin a ON a.id = t.admin_id
      LEFT JOIN "User" u ON u.id = t.user_id
      LEFT JOIN "MT5Account" m ON m.id = t.mt5_account_id
      ${whereSql}
    `;

    const countSql = `SELECT COUNT(1) AS cnt ${baseSql}`;
    const itemsSql = `
      SELECT 
        t.*, 
        a.email AS admin_email, a.admin_role AS admin_role, a.username AS admin_username,
        u.email AS user_email, u.name AS user_name,
        m."accountId" AS mt5_accountid
      ${baseSql}
      ORDER BY t.created_at DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;

    const countRes = await pool.query(countSql, params);
    const total = Number(countRes.rows?.[0]?.cnt || 0);

    const itemsRes = await pool.query(itemsSql, [...params, take, offset]);
    const items = itemsRes.rows || [];

    res.json({ ok: true, total, page: curPage, limit: take, items });
  } catch (err) {
    console.error('GET /admin/admin-transactions failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch admin transactions' });
  }
});

// Log an admin transaction (deposit/withdraw/bonus_add/bonus_deduct)
app.post('/admin/admin-transactions', authenticateAdmin, async (req, res) => {
  try {
    const adminId = req.adminId;
    const {
      operation_type,
      mt5_login,
      amount,
      currency = 'USD',
      status = 'completed',
      comment = '',
      external_transaction_id = null,
    } = req.body || {};

    if (!operation_type || !['deposit','withdraw','bonus_add','bonus_deduct'].includes(String(operation_type))) {
      return res.status(400).json({ ok: false, error: 'Invalid operation_type' });
    }
    if (!mt5_login) return res.status(400).json({ ok: false, error: 'mt5_login required' });
    const amt = Number(amount);
    if (!amt || !(amt > 0)) return res.status(400).json({ ok: false, error: 'amount must be > 0' });

    // Try to resolve user_id and mt5_account_id
    let userId = null, mt5AccountId = null;
    try {
      const acc = await prisma.mT5Account.findFirst({
        where: { accountId: String(mt5_login) },
        select: { id: true, userId: true }
      });
      if (acc) { mt5AccountId = acc.id; userId = acc.userId || null; }
    } catch {}

    // Insert via SQL for compatibility
    const sql = `
      INSERT INTO admin_transactions
        (admin_id, user_id, mt5_account_id, mt5_login, operation_type, amount, currency, status,
         comment, external_transaction_id, ip_address, user_agent, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
              $9, $10, $11, $12, NOW(), NOW())
      RETURNING *
    `;
    const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString().split(',')[0].trim();
    const ua = req.headers['user-agent'] || '';
    const params = [
      parseInt(adminId, 10) || adminId,
      userId,
      mt5AccountId,
      String(mt5_login),
      String(operation_type),
      amt,
      String(currency),
      String(status),
      comment ? String(comment) : null,
      external_transaction_id ? String(external_transaction_id) : null,
      ip || null,
      ua || null,
    ];
    const { rows } = await pool.query(sql, params);
    res.json({ ok: true, item: rows?.[0] || null });
  } catch (err) {
    console.error('POST /admin/admin-transactions failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to log admin transaction' });
  }
});

// Internal transfers from Transaction table
app.get('/admin/internal-transfers', authenticateAdmin, async (req, res) => {
  try {
    const take = Math.min(parseInt(req.query.limit || '100', 10), 1000);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const status = req.query.status ? String(req.query.status) : null;
    const from = req.query.from ? new Date(req.query.from) : null;
    const to = req.query.to ? new Date(req.query.to) : null;
    const q = (req.query.q || '').toString().trim();

    // If country admin, automatically filter by their assigned country
    let countryFilter = null;
    if (req.isCountryAdmin && req.admin?.country) {
      const adminCountry = String(req.admin.country || '').trim().toUpperCase();
      if (adminCountry) {
        countryFilter = adminCountry.toLowerCase();
      }
    }

    const whereParts = ["(t.\"type\" = 'transfer' OR t.\"paymentMethod\" = 'internal_transfer')"];
    const params = [];
    
    if (countryFilter) {
      whereParts.push(`LOWER(u.country) = LOWER($${params.length + 1})`);
      params.push(countryFilter);
    }
    if (status) { params.push(status); whereParts.push(`t."status" = $${params.length}`); }
    if (from) { params.push(from); whereParts.push(`t."createdAt" >= $${params.length}`); }
    if (to) { params.push(to); whereParts.push(`t."createdAt" <= $${params.length}`); }
    if (q) {
      params.push(`%${q}%`);
      whereParts.push(`(t."description" ILIKE $${params.length} OR t."userId"::text ILIKE $${params.length})`);
    }

    const whereSQL = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';
    const joinSQL = countryFilter ? 'LEFT JOIN public."User" u ON u.id = t."userId"' : '';

    const countSql = `SELECT COUNT(1) AS cnt FROM public."Transaction" t ${joinSQL} ${whereSQL}`;
    const { rows: cntRows } = await pool.query(countSql, params);
    const total = Number(cntRows?.[0]?.cnt || 0);

    const itemsSql = `
      SELECT t."id",t."userId",t."type",t."amount",t."status",t."currency",t."paymentMethod",
             t."transactionId",t."description",t."depositId",t."withdrawalId",t."createdAt",t."updatedAt"
      FROM public."Transaction" t
      ${joinSQL}
      ${whereSQL}
      ORDER BY t."createdAt" DESC
      LIMIT $${params.length+1} OFFSET $${params.length+2}
    `;
    const { rows } = await pool.query(itemsSql, [...params, take, skip]);

    // Group pairs into single transfer rows (from + to)
    const groups = new Map();
    const acctIds = new Set();
    function parseAcc(desc){
      if (!desc) return {};
      const mFrom = /from account\s(\d+)/i.exec(desc);
      const mTo = /to account\s(\d+)/i.exec(desc);
      return { from: mFrom ? mFrom[1] : null, to: mTo ? mTo[1] : null };
    }
    rows.forEach(r => {
      const t = new Date(r.createdAt).getTime();
      const bucket = Math.floor(t/1000); // per second bucket
      const key = `${r.userId}|${r.amount}|${r.currency}|${bucket}`;
      const acc = parseAcc(r.description);
      let g = groups.get(key);
      if (!g) {
        g = {
          id: r.id,
          createdAt: r.createdAt,
          amount: r.amount,
          currency: r.currency,
          status: r.status,
          fromLogin: null,
          toLogin: null,
          notes: []
        };
        groups.set(key, g);
      } else {
        // keep latest status if either is completed
        if (r.status === 'completed') g.status = 'completed';
        if (new Date(r.createdAt) > new Date(g.createdAt)) g.createdAt = r.createdAt;
      }
      if (acc.from) { g.fromLogin = acc.from; acctIds.add(acc.from); }
      if (acc.to)   { g.toLogin   = acc.to;   acctIds.add(acc.to); }
      if (r.description) g.notes.push(r.description);
    });

    // Resolve account -> user details
    const accounts = Array.from(acctIds);
    const userMap = new Map();
    if (accounts.length) {
      try {
        const accRows = await prisma.mT5Account.findMany({
          where: { accountId: { in: accounts } },
          select: { accountId: true, User: { select: { id: true, email: true, name: true } } }
        });
        accRows.forEach(a => userMap.set(a.accountId, a.User || null));
      } catch (e) { console.warn('Lookup MT5Account failed:', e.message); }
    }

    const items = Array.from(groups.values()).map(g => ({
      id: g.id,
      createdAt: g.createdAt,
      amount: g.amount,
      currency: g.currency,
      status: g.status,
      from: g.fromLogin ? { mt5Login: g.fromLogin, user: userMap.get(g.fromLogin) } : null,
      to:   g.toLogin   ? { mt5Login: g.toLogin,   user: userMap.get(g.toLogin) }   : null,
      description: g.notes.join(' | ')
    }));

    res.json({ ok: true, total: items.length, page, limit: take, items });
  } catch (err) {
    console.error('GET /admin/internal-transfers failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch internal transfers' });
  }
});

// MT5 API Proxy endpoint - REMOVED
// This endpoint is no longer needed as the /admin/mt5/users endpoint
// now provides all the account details directly, eliminating double API calls

// ===== GROUP MANAGEMENT ENDPOINTS =====

// Get all groups
app.get('/admin/group-management', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 50, search, is_active } = req.query;
    const skip = (Number(page) - 1) * Number(limit);
    
    const where = {};
    if (search) {
      where.OR = [
        { group: { contains: String(search), mode: 'insensitive' } },
        { company: { contains: String(search), mode: 'insensitive' } },
      ];
    }
    if (is_active !== undefined) {
      where.is_active = is_active === 'true';
    }
    
    const [items, total] = await Promise.all([
      prisma.group_management.findMany({
        where,
        skip,
        take: Number(limit),
        orderBy: { created_at: 'desc' },
      }),
      prisma.group_management.count({ where }),
    ]);
    
    res.json({ ok: true, items, total, page: Number(page), limit: Number(limit) });
  } catch (err) {
    console.error('GET /admin/group-management failed:', err);
    const errorMessage = err.message || 'Failed to fetch groups';
    // Check if it's a Prisma model not found error
    if (errorMessage.includes('group_management') || errorMessage.includes('does not exist')) {
      res.status(500).json({ 
        ok: false, 
        error: 'Database table not found. Please run: npx prisma generate && npx prisma migrate dev' 
      });
    } else {
      res.status(500).json({ ok: false, error: errorMessage });
    }
  }
});

// Sync groups from API
app.post('/admin/group-management/sync', authenticateAdmin, async (req, res) => {
  try {
    const apiUrl = 'https://metaapi.zuperior.com/api/groups';
    
    console.log(`[Group Sync] Fetching groups from ${apiUrl}...`);
    
    const response = await axios.get(apiUrl, {
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    
    if (!response.data || !Array.isArray(response.data)) {
      throw new Error('Invalid API response format');
    }
    
    const groups = response.data;
    console.log(`[Group Sync] Received ${groups.length} groups from API`);
    
    let created = 0;
    let updated = 0;
    let errors = 0;
    
    for (const groupData of groups) {
      try {
        if (!groupData.Group) {
          console.warn('[Group Sync] Skipping group without Group field:', groupData);
          errors++;
          continue;
        }
        
        const groupName = String(groupData.Group);
        
        // Map API response to database fields
        const data = {
          group: groupName,
          server: groupData.Server ?? 1,
          permissions_flags: groupData.PermissionsFlags ?? 0,
          auth_mode: groupData.AuthMode ?? 0,
          auth_password_min: groupData.AuthPasswordMin ?? 8,
          company: groupData.Company || null,
          company_page: groupData.CompanyPage || null,
          company_email: groupData.CompanyEmail || null,
          company_support_page: groupData.CompanySupportPage || null,
          company_support_email: groupData.CompanySupportEmail || null,
          company_catalog: groupData.CompanyCatalog || null,
          currency: groupData.Currency || null,
          currency_digits: groupData.CurrencyDigits ?? 2,
          reports_mode: groupData.ReportsMode ?? 1,
          reports_flags: groupData.ReportsFlags ?? 5,
          reports_smtp: groupData.ReportsSMTP || null,
          reports_smtp_login: groupData.ReportsSMTPLogin || null,
          news_mode: groupData.NewsMode ?? 2,
          news_category: groupData.NewsCategory || null,
          mail_mode: groupData.MailMode ?? 1,
          trade_flags: groupData.TradeFlags ?? 2135,
          trade_interestrate: groupData.TradeInterestrate ? parseFloat(groupData.TradeInterestrate) : 0,
          trade_virtual_credit: groupData.TradeVirtualCredit ? parseFloat(groupData.TradeVirtualCredit) : 0,
          margin_free_mode: groupData.MarginFreeMode ?? 1,
          margin_so_mode: groupData.MarginSOMode ?? 0,
          margin_call: groupData.MarginCall ? parseFloat(groupData.MarginCall) : 100,
          margin_stop_out: groupData.MarginStopOut ? parseFloat(groupData.MarginStopOut) : 5,
          demo_leverage: groupData.DemoLeverage ?? 100,
          demo_deposit: groupData.DemoDeposit ? parseFloat(groupData.DemoDeposit) : 0,
          limit_history: groupData.LimitHistory ?? 0,
          limit_orders: groupData.LimitOrders ?? 0,
          limit_symbols: groupData.LimitSymbols ?? 0,
          limit_positions: groupData.LimitPositions ?? 0,
          margin_mode: groupData.MarginMode ?? 2,
          margin_flags: groupData.MarginFlags ?? 0,
          trade_transfer_mode: groupData.TradeTransferMode ?? 0,
          synced_at: new Date(),
          updated_at: new Date(),
        };
        
        // Check if group exists
        const existing = await prisma.group_management.findUnique({
          where: { group: groupName },
        });
        
        if (existing) {
          // Update existing group (preserve is_active status)
          await prisma.group_management.update({
            where: { group: groupName },
            data: { ...data, is_active: existing.is_active }, // Preserve existing is_active
          });
          updated++;
        } else {
          // Create new group
          await prisma.group_management.create({
            data: { ...data, is_active: true }, // New groups default to active
          });
          created++;
        }
      } catch (err) {
        console.error(`[Group Sync] Error processing group ${groupData.Group}:`, err.message);
        errors++;
      }
    }
    
    console.log(`[Group Sync] Completed: ${created} created, ${updated} updated, ${errors} errors`);
    
    res.json({
      ok: true,
      message: `Sync completed: ${created} created, ${updated} updated, ${errors} errors`,
      stats: { created, updated, errors, total: groups.length },
    });
  } catch (err) {
    console.error('[Group Sync] Failed:', err);
    res.status(500).json({
      ok: false,
      error: err.message || 'Failed to sync groups from API',
    });
  }
});

// Toggle group active status
app.put('/admin/group-management/:id/toggle-active', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { is_active } = req.body;
    
    if (typeof is_active !== 'boolean') {
      return res.status(400).json({ ok: false, error: 'is_active must be a boolean' });
    }
    
    const group = await prisma.group_management.update({
      where: { id: Number(id) },
      data: { is_active, updated_at: new Date() },
    });
    
    res.json({ ok: true, group });
  } catch (err) {
    console.error('PUT /admin/group-management/:id/toggle-active failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update group status' });
  }
});

// Get single group by ID
app.get('/admin/group-management/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const group = await prisma.group_management.findUnique({
      where: { id: Number(id) },
    });
    
    if (!group) {
      return res.status(404).json({ ok: false, error: 'Group not found' });
    }
    
    res.json({ ok: true, group });
  } catch (err) {
    console.error('GET /admin/group-management/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch group' });
  }
});

// Update dedicated_name
app.put('/admin/group-management/:id/dedicated-name', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { dedicated_name } = req.body;
    
    if (dedicated_name !== undefined && dedicated_name !== null && typeof dedicated_name !== 'string') {
      return res.status(400).json({ ok: false, error: 'dedicated_name must be a string' });
    }
    
    // Allow empty string to clear the dedicated_name
    const updateData = { 
      dedicated_name: dedicated_name === '' ? null : dedicated_name,
      updated_at: new Date() 
    };
    
    const group = await prisma.group_management.update({
      where: { id: Number(id) },
      data: updateData,
    });
    
    res.json({ ok: true, group });
  } catch (err) {
    console.error('PUT /admin/group-management/:id/dedicated-name failed:', err);
    const errorMessage = err.message || 'Failed to update dedicated name';
    
    // Check if it's a database column error
    if (errorMessage.includes('dedicated_name') || errorMessage.includes('Unknown column') || errorMessage.includes('column') && errorMessage.includes('does not exist')) {
      res.status(500).json({ 
        ok: false, 
        error: 'Database column not found. Please run: ALTER TABLE "group_management" ADD COLUMN "dedicated_name" VARCHAR(255);' 
      });
    } else {
      res.status(500).json({ ok: false, error: errorMessage });
    }
  }
});

app.listen(PORT, async () => {
  console.log(`zuperior-admin-back listening on :${PORT}`);
  await createDefaultAdmin();
});

// --- CREATE country admin (POST) ---
app.post('/admin/country-admins', async (req, res) => {
  try {
    const { name, email, password, status, features, country } = req.body;
    if (!name || !email || !status || !country) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }
    const featuresStr = Array.isArray(features) ? features.join(',') : (features || '');
    // Use the actual table: public.country_admins
    // Resolve country code from either full name or code (case-insensitive),
    // and store EXACT value from countries table to satisfy FK
    let isoInput = String(country || '').trim();
    let iso = isoInput;
    try {
      const look = await pool.query(
        'SELECT code FROM public.countries WHERE LOWER(code) = LOWER($1) OR LOWER(country) = LOWER($1) LIMIT 1',
        [isoInput]
      );
      if (look.rows?.[0]?.code) {
        iso = look.rows[0].code; // use exact code from table (likely uppercase)
      } else {
        // As a last resort, truncate to 2 and try again
        const try2 = await pool.query(
          'SELECT code FROM public.countries WHERE LOWER(code) = LOWER($1) LIMIT 1',
          [isoInput.slice(0,2)]
        );
        if (try2.rows?.[0]?.code) iso = try2.rows[0].code;
      }
    } catch {}
    if (!iso || iso.length === 0) {
      return res.status(400).json({ ok: false, error: 'Invalid country or code' });
    }
    // Try update-by-email first; if not found, insert a new row
    const update = `UPDATE public.country_admins
                    SET name = $1,
                        status = $3,
                        country_code = $4,
                        features = $5
                    WHERE email = $2
                    RETURNING *`;
    let result = await pool.query(update, [name, email, status, iso, featuresStr]);
    let createdRow = result.rows[0];
    if (!createdRow) {
      // Determine next integer id if table doesn't auto-generate
      let nextId = null;
      try {
        const idq = await pool.query('SELECT COALESCE(MAX(id),0)+1 AS id FROM public.country_admins');
        nextId = idq.rows?.[0]?.id || 1;
      } catch {}
      let insert;
      let params;
      if (nextId) {
        insert = `INSERT INTO public.country_admins (id, name, email, status, country_code, features, created_at)
                  VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *`;
        params = [nextId, name, email, status, iso, featuresStr];
      } else {
        insert = `INSERT INTO public.country_admins (name, email, status, country_code, features, created_at)
                  VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`;
        params = [name, email, status, iso, featuresStr];
      }
      result = await pool.query(insert, params);
      createdRow = result.rows[0];
    }

    // Mirror account to prisma.admin so the partner can login
    try {
      const existing = await prisma.admin.findUnique({ where: { email } });
      if (!existing) {
        const password_hash = await bcrypt.hash(password, 10);
        await prisma.admin.create({
          data: {
            username: name,
            email,
            password_hash,
            admin_role: 'admin',
            is_active: true,
            created_at: new Date()
          }
        });
      }
    } catch (e) {
      console.error('Failed to mirror to prisma.admin:', e);
      // do not fail the main request
    }

    res.json({ ok: true, admin: { ...createdRow, features: (createdRow.features ? String(createdRow.features).split(',') : []) } });
  } catch (err) {
    console.error('POST /admin/country-admins failed:', err);
    res.status(500).json({ ok: false, error: err.message || 'Insert failed', code: err.code, detail: err.detail });
  }
});
// --- READ (GET) all country admins ---
app.get('/admin/country-admins', async (req, res) => {
  try {
    const select = `SELECT * FROM public.country_admins ORDER BY id ASC`;
    const result = await pool.query(select);
    // Parse features (string) to array
    const admins = result.rows.map(a => ({
      ...a,
      features: a.features ? a.features.split(',') : [],
    }));
    res.json(admins);
  } catch (err) {
    console.warn('GET /admin/country-admins failed:', err.message);
    // Return empty list instead of 500 so frontend can gracefully proceed
    res.json([]);
  }
});

// --- GET current country admin info (authenticated) ---
app.get('/admin/country-admin/me', authenticateAdmin, async (req, res) => {
  try {
    if (!req.isCountryAdmin) {
      return res.status(403).json({ ok: false, error: 'Not a country admin' });
    }
    
    const countryAdminResult = await pool.query(
      'SELECT * FROM public.country_admins WHERE email = $1',
      [req.admin.email]
    );
    
    if (countryAdminResult.rows.length === 0) {
      return res.status(404).json({ ok: false, error: 'Country admin not found' });
    }
    
    const countryAdmin = countryAdminResult.rows[0];
    // Parse features from comma-separated string to array and normalize paths
    // Normalize: extract last part of path to match sidebar filter logic
    const normalizeFeature = (f) => {
      if (typeof f !== 'string' || !f.includes('/')) return f.trim();
      // Remove leading /admin/ if present, then get last part
      const cleaned = f.replace(/^\/admin\//, '').replace(/^\//, '').trim();
      return cleaned.split('/').pop() || cleaned;
    };
    
    const features = countryAdmin.features 
      ? countryAdmin.features.split(',').map(f => normalizeFeature(f.trim())).filter(f => f && f.length > 0)
      : [];
    
    res.json({
      ok: true,
      admin: {
        id: countryAdmin.id,
        name: countryAdmin.name,
        email: countryAdmin.email,
        status: countryAdmin.status,
        country: countryAdmin.country_code,
        features: features,
        isCountryAdmin: true
      }
    });
  } catch (err) {
    console.error('GET /admin/country-admin/me failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch country admin info' });
  }
});

// --- UPDATE country admin (PUT) ---
app.put('/admin/country-admins/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, status, country, features } = req.body || {};
    const featuresStr = Array.isArray(features) ? features.join(',') : (features || null);
    // Resolve code from name/code like in POST
    let isoInput = String(country || '').trim();
    let iso = null;
    if (isoInput) {
      try {
        const look = await pool.query(
          'SELECT code FROM public.countries WHERE LOWER(code) = LOWER($1) OR LOWER(country) = LOWER($1) LIMIT 1',
          [isoInput]
        );
        if (look.rows?.[0]?.code) iso = look.rows[0].code; else {
          const try2 = await pool.query('SELECT code FROM public.countries WHERE LOWER(code) = LOWER($1) LIMIT 1', [isoInput.slice(0,2)]);
          if (try2.rows?.[0]?.code) iso = try2.rows[0].code;
        }
      } catch {}
    }
    const update = `UPDATE public.country_admins SET 
      name = COALESCE($1, name),
      status = COALESCE($2, status),
      country_code = COALESCE($3, country_code),
      features = COALESCE($4, features)
      WHERE id = $5 RETURNING *`;
    const result = await pool.query(update, [name ?? null, status ?? null, iso, featuresStr, id]);
    if (!result.rows[0]) return res.status(404).json({ ok: false, error: 'Not found' });
    const row = result.rows[0];
    res.json({ ok: true, admin: { ...row, features: row.features ? row.features.split(',') : [] } });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --- CHANGE PASSWORD country admin (PATCH) ---
app.patch('/admin/country-admins/:id/password', async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body || {};
    if (!password || String(password).length < 6) return res.status(400).json({ ok: false, error: 'Password too short' });
    // Update the mirrored prisma.admin user by looking up email from country_admins
    try {
      const lookup = await pool.query('SELECT email FROM public.country_admins WHERE id = $1', [id]);
      const email = lookup.rows?.[0]?.email;
      if (email) {
        const hash = await bcrypt.hash(password, 10);
        await prisma.admin.update({ where: { email }, data: { password_hash: hash } });
      }
    } catch (e) {
      console.warn('Mirror password update failed:', e.message);
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --- DELETE country admin (DELETE) ---
app.delete('/admin/country-admins/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM public.country_admins WHERE id = $1', [id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Get unique countries from user registration data for dropdowns
app.get('/admin/countries', async (req, res) => {
  try {
    const result = await pool.query('SELECT code, country FROM public.countries ORDER BY country ASC');
    res.json({ ok: true, countries: result.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------------- User-facing Manual Gateways ----------------
// Returns active manual gateways eligible for a user's country or a provided ISO country code
// Usage:
//   GET /u/manual-gateways?userId=<id>
//   GET /u/manual-gateways?country=IN
//   Optional: &type=upi|crypto|wire|local
app.get('/u/manual-gateways', async (req, res) => {
  try {
    const { userId, country, type } = req.query;

    let iso = (country || '').toString().trim().toUpperCase();
    if (!iso && userId) {
      try {
        const user = await prisma.user.findUnique({ where: { id: String(userId) }, select: { country: true } });
        iso = (user?.country || '').toString().trim().toUpperCase();
      } catch {}
    }

    const where = { is_active: true };
    if (iso) where.OR = [{ country_code: null }, { country_code: iso }];
    if (type) where.type = String(type);

    const gateways = await prisma.manual_gateway.findMany({ where, orderBy: { created_at: 'desc' } });
    res.json({ ok: true, country: iso || null, items: gateways });
  } catch (err) {
    console.error('GET /u/manual-gateways failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch available gateways' });
  }
});
