// Basic Express server bootstrap for Zuperior Admin backend
// Loads env, configures CORS/JSON, and prepares a Postgres connection.

const express = require('express');
const cors = require('cors');
const axios = require('axios'); // eslint-disable-line no-unused-vars
const jwt = require('jsonwebtoken'); // eslint-disable-line no-unused-vars
const { Pool } = require('pg');
const { PrismaClient } = require('@prisma/client');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
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
app.get('/admin/kyc', async (req, res) => {
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
app.get('/admin/users/all', async (req, res) => {
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
app.get('/admin/mt5/users', async (req, res) => {
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
app.get('/admin/deposits', async (req, res) => {
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
app.get('/admin/withdrawals', async (req, res) => {
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

// ---- Error handler ----
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ ok: false, error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`zuperior-admin-back listening on :${PORT}`);
});
