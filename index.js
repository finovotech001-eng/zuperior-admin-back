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
      if (!origin || allowed.includes(origin)) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  };
}

app.use(cors(corsOptions));
app.use(express.json({ limit: '1mb' }));
// Static serving for stored KYC proofs
app.use('/kyc_proofs', express.static(path.join(process.cwd(), 'zuperior-admin-back', 'src', 'kyc_proofs')));

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

    req.adminId = admin.id;
    req.admin = admin;
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
    await prisma.user.delete({ where: { id } });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /admin/users/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Delete failed' });
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
    const rec = await prisma.kYC.update({ where: { id }, data, select: { id: true } });
    res.json({ ok: true, id: rec.id });
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
    const emailVerifiedParam = (req.query.emailVerified || '').trim();

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
app.post('/admin/users', async (req, res) => {
  try {
    const { email, password, name, phone, country, role = 'user', status = 'active', emailVerified = false } = req.body || {};
    if (!email || !password) return res.status(400).json({ ok: false, error: 'email and password required' });
    const id = crypto.randomUUID();
    const clientId = `cm${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`.slice(0, 26);
    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { id, clientId, email, password: hashed, name, phone, country, role, status, emailVerified: !!emailVerified },
      select: { id: true, clientId: true, email: true }
    });
    res.json({ ok: true, user });
  } catch (err) {
    console.error('POST /admin/users failed:', err);
    if (err?.code === 'P2002') return res.status(409).json({ ok: false, error: 'Email or clientId already exists' });
    res.status(500).json({ ok: false, error: 'Failed to create user' });
  }
});

// Fetch users with MT5 accounts and balances
app.get('/admin/users/with-balance', async (req, res) => {
  try {
    const take = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const q = (req.query.q || '').trim();

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
    const MT5_API_BASE = 'http://18.130.5.209:5003/api/Users';
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
app.get('/admin/mt5/account/:accountId', async (req, res) => {
  try {
    const { accountId } = req.params;
    const MT5_API_BASE = 'http://18.130.5.209:5003/api/Users';
    const response = await axios.get(`${MT5_API_BASE}/${accountId}/getClientProfile`, {
      timeout: 5000,
    });
    if (response.data?.Success) {
      res.json({ ok: true, data: response.data.Data });
    } else {
      res.status(404).json({ ok: false, error: 'Account not found' });
    }
  } catch (error) {
    console.error(`Failed to fetch MT5 account ${req.params.accountId}:`, error.message);
    res.status(500).json({ ok: false, error: 'Failed to fetch account details' });
  }
});

// Fetch all MT5 users with balances
app.get('/admin/mt5/users', authenticateAdmin, async (req, res) => {
  try {
    const take = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;
    const q = (req.query.q || '').trim();

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

    // Fetch balances for each user's MT5 accounts
    const MT5_API_BASE = 'http://18.130.5.209:5003/api/Users';
    const items = await Promise.all(
      users.map(async (user) => {
        const totalBalance = await Promise.all(
          user.MT5Account.map(async (account) => {
            try {
              const response = await axios.get(`${MT5_API_BASE}/${account.accountId}/getClientProfile`, {
                timeout: 5000,
              });
              return response.data?.Data?.Balance || 0;
            } catch (error) {
              console.warn(`Failed to fetch balance for account ${account.accountId}:`, error.message);
              return 0;
            }
          })
        ).then(balances => balances.reduce((sum, balance) => sum + balance, 0));

        return {
          ...user,
          totalBalance,
          MT5Account: user.MT5Account,
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
    const { userId, accountId, password } = req.body || {};
    if (!userId || !accountId) {
      return res.status(400).json({ ok: false, error: 'User ID and Account ID are required' });
    }

    // Check if user exists
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      return res.status(404).json({ ok: false, error: 'User not found' });
    }

    // Check if account already assigned (userId not null)
    const existing = await prisma.mT5Account.findUnique({ where: { accountId } });
    if (existing && existing.userId) {
      return res.status(409).json({ ok: false, error: 'Account ID already assigned' });
    }

    // If exists but unassigned, update it; else create
    let mt5Account;
    if (existing) {
      mt5Account = await prisma.mT5Account.update({
        where: { accountId },
        data: { userId, updatedAt: new Date() },
        select: { id: true, accountId: true },
      });
    } else {
      mt5Account = await prisma.mT5Account.create({
        data: {
          id: crypto.randomUUID(),
          userId,
          accountId,
          updatedAt: new Date(),
        },
        select: { id: true, accountId: true },
      });
    }

    res.json({ ok: true, mt5Account });
  } catch (err) {
    console.error('POST /admin/mt5/assign failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to assign MT5 account' });
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

    const where = {
      ...(status ? { status } : {}),
      ...(q ? { User: { email: { contains: q, mode: 'insensitive' } } } : {}),
    };

    const [total, totalSum, items] = await Promise.all([
      prisma.deposit.count({ where }),
      prisma.deposit.aggregate({ where, _sum: { amount: true } }),
      prisma.deposit.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take,
        include: {
          User: { select: { id: true, email: true, name: true } },
          MT5Account: { select: { id: true, accountId: true } },
        },
      }),
    ]);

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

    const where = {
      ...(status ? { status } : {}),
      ...(q ? { User: { email: { contains: q, mode: 'insensitive' } } } : {}),
    };

    const [total, items] = await Promise.all([
      prisma.withdrawal.count({ where }),
      prisma.withdrawal.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take,
        include: {
          User: { select: { id: true, email: true, name: true } },
          MT5Account: { select: { id: true, accountId: true } },
        },
      }),
    ]);

    res.json({ ok: true, total, page, limit: take, items });
  } catch (err) {
    console.error('GET /admin/withdrawals failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch withdrawals' });
  }
});

// Approve withdrawal
app.post('/admin/withdrawals/:id/approve', async (req, res) => {
  try {
    const { id } = req.params;

    const withdrawal = await prisma.withdrawal.findUnique({
      where: { id },
      include: { MT5Account: true },
    });

    if (!withdrawal) return res.status(404).json({ ok: false, error: 'Withdrawal not found' });

    if (withdrawal.status !== 'pending') return res.status(400).json({ ok: false, error: 'Withdrawal not pending' });

    // Hit MT5 API to deduct balance
    const MT5_API_BASE = 'http://18.130.5.209:5003/api/Users';
    const response = await axios.post(`${MT5_API_BASE}/${withdrawal.MT5Account.accountId}/DeductClientBalance`, {
      balance: withdrawal.amount,
      comment: 'WITHDRAWAL',
    }, { timeout: 10000 });

    if (response.data?.Success) {
      // Update withdrawal status to approved
      await prisma.withdrawal.update({
        where: { id },
        data: { status: 'approved', approvedAt: new Date() },
      });

      res.json({
        ok: true,
        message: 'Withdrawal approved successfully. It will take 3-5 minutes to reflect in the account.'
      });
    } else {
      res.status(400).json({ ok: false, error: 'Failed to deduct balance from MT5 account' });
    }
  } catch (err) {
    console.error('POST /admin/withdrawals/:id/approve failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to approve withdrawal' });
  }
});

// Approve deposit
app.post('/admin/deposits/:id/approve', async (req, res) => {
  try {
    const { id } = req.params;

    const deposit = await prisma.deposit.findUnique({
      where: { id },
      include: { MT5Account: true },
    });

    if (!deposit) return res.status(404).json({ ok: false, error: 'Deposit not found' });

    if (deposit.status !== 'pending') return res.status(400).json({ ok: false, error: 'Deposit not pending' });

    // Hit MT5 API to add balance
    const MT5_API_BASE = 'http://18.130.5.209:5003/api/Users';
    const response = await axios.post(`${MT5_API_BASE}/${deposit.MT5Account.accountId}/AddClientBalance`, {
      balance: deposit.amount,
      comment: 'DEPOSIT',
    }, { timeout: 10000 });

    if (response.data?.Success) {
      // Update deposit status to approved
      await prisma.deposit.update({
        where: { id },
        data: { status: 'approved', approvedAt: new Date() },
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

// Aggregated activity logs endpoint
app.get('/admin/activity-logs', async (req, res) => {
  try {
    const type = req.query.type; // 'deposit', 'withdrawal', 'account'
    const status = req.query.status; // 'pending', 'approved', 'rejected', 'opened'
    const from = req.query.from ? new Date(req.query.from) : null;
    const to = req.query.to ? new Date(req.query.to) : null;
    const search = (req.query.search || '').trim();
    const take = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const skip = (page - 1) * take;

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
    };

    // Fetch data from each entity
    const [depositTotal, deposits] = await Promise.all([
      prisma.deposit.count({ where: depositWhere }),
      prisma.deposit.findMany({
        where: depositWhere,
        orderBy: { createdAt: 'desc' },
        skip,
        take: type === 'deposit' ? take : Math.floor(take / 3),
        include: {
          User: { select: { id: true, email: true, name: true } },
          MT5Account: { select: { id: true, accountId: true } },
        },
      }),
    ]);

    const [withdrawalTotal, withdrawals] = await Promise.all([
      prisma.withdrawal.count({ where: withdrawalWhere }),
      prisma.withdrawal.findMany({
        where: withdrawalWhere,
        orderBy: { createdAt: 'desc' },
        skip,
        take: type === 'withdrawal' ? take : Math.floor(take / 3),
        include: {
          User: { select: { id: true, email: true, name: true } },
          MT5Account: { select: { id: true, accountId: true } },
        },
      }),
    ]);

    const [userTotal, users] = await Promise.all([
      prisma.user.count({ where: userWhere }),
      prisma.user.findMany({
        where: userWhere,
        orderBy: { createdAt: 'desc' },
        skip,
        take: type === 'account' ? take : Math.floor(take / 3),
        select: {
          id: true,
          clientId: true,
          email: true,
          name: true,
          createdAt: true,
        },
      }),
    ]);

    // Combine and sort all activities
    const activities = [
      ...deposits.map(d => ({
        id: d.id,
        time: d.createdAt,
        type: 'Deposit',
        user: d.User?.email || '-',
        userName: d.User?.name || '-',
        mts: d.MT5Account?.accountId || '-',
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
        mts: w.MT5Account?.accountId || '-',
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
    res.status(500).json({ ok: false, error: 'Failed to fetch activity logs' });
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

// ===== ADMIN AUTHENTICATION ENDPOINTS =====

// Admin login
app.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password are required' });
    }
    
    // Find admin by email
    const admin = await prisma.admin.findUnique({
      where: { email }
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
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, admin.password_hash);
    
    if (!isValidPassword) {
      // Get IP address and user agent for failed login
      const ipAddress = getRealIP(req);
      const userAgent = req.headers['user-agent'] || '';
      const { browser, os, device } = parseUserAgent(userAgent);
      
      // Log failed login attempt
      await prisma.admin_login_log.create({
        data: {
          admin_id: admin.id,
          ip_address: ipAddress,
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
    
    // Get IP address and user agent
    const ipAddress = getRealIP(req);
    const userAgent = req.headers['user-agent'] || '';
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
    
    // Generate JWT token
    const token = jwt.sign(
      { 
        adminId: admin.id, 
        email: admin.email,
        role: admin.admin_role 
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.json({
      ok: true,
      token,
      admin: {
        id: admin.id,
        email: admin.email,
        role: admin.admin_role,
        last_login: admin.last_login
      }
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
    const gateways = await prisma.manual_gateway.findMany({
      orderBy: {
        created_at: 'desc'
      }
    });

    res.json({ ok: true, gateways });
  } catch (err) {
    console.error('GET /admin/manual-gateways failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to fetch manual gateways' });
  }
});

app.post('/admin/manual-gateways', authenticateAdmin, async (req, res) => {
  try {
    const { type, name, details, is_active } = req.body;
    
    // Handle file uploads
    const icon_url = req.files?.icon ? `/uploads/${req.files.icon[0].filename}` : null;
    const qr_code_url = req.files?.qr_code ? `/uploads/${req.files.qr_code[0].filename}` : null;
    
    const gateway = await prisma.manual_gateway.create({
      data: {
        type,
        name,
        details,
        icon_url,
        qr_code_url,
        is_active
      }
    });

    res.json({ ok: true, gateway });
  } catch (err) {
    console.error('POST /admin/manual-gateways failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to create manual gateway' });
  }
});

app.put('/admin/manual-gateways/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { type, name, details, is_active } = req.body;
    
    // Handle file uploads
    const updateData = { type, name, details, is_active };
    
    if (req.files?.icon) {
      updateData.icon_url = `/uploads/${req.files.icon[0].filename}`;
    }
    if (req.files?.qr_code) {
      updateData.qr_code_url = `/uploads/${req.files.qr_code[0].filename}`;
    }
    
    const gateway = await prisma.manual_gateway.update({
      where: { id: parseInt(id) },
      data: updateData
    });

    res.json({ ok: true, gateway });
  } catch (err) {
    console.error('PUT /admin/manual-gateways/:id failed:', err);
    res.status(500).json({ ok: false, error: 'Failed to update manual gateway' });
  }
});

app.delete('/admin/manual-gateways/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    await prisma.manual_gateway.delete({
      where: { id: parseInt(id) }
    });

    res.json({ ok: true, message: 'Manual gateway deleted successfully' });
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

app.listen(PORT, async () => {
  console.log(`zuperior-admin-back listening on :${PORT}`);
  await createDefaultAdmin();
});
