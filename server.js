require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

app.use(express.json());
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use('/api/', limiter);

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Database connected at:', res.rows[0].now);
    }
});

async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                balance DECIMAL(18,8) DEFAULT 0,
                total_earned DECIMAL(18,8) DEFAULT 0,
                referral_earnings DECIMAL(18,8) DEFAULT 0,
                total_clicks INT DEFAULT 0,
                ads_today INT DEFAULT 0,
                referral_code VARCHAR(20) UNIQUE,
                referred_by VARCHAR(20),
                fraud_score INT DEFAULT 0,
                is_banned BOOLEAN DEFAULT FALSE,
                ip_address VARCHAR(45),
                last_click_time BIGINT DEFAULT 0,
                join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_reset_date DATE
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS withdrawals (
                id VARCHAR(30) PRIMARY KEY,
                user_id INT REFERENCES users(id) ON DELETE CASCADE,
                email VARCHAR(255),
                amount DECIMAL(18,8),
                status VARCHAR(20) DEFAULT 'pending',
                payout_id VARCHAR(100),
                request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_date TIMESTAMP,
                processed_by VARCHAR(255)
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS ad_views (
                id SERIAL PRIMARY KEY,
                user_id INT REFERENCES users(id) ON DELETE CASCADE,
                ad_id INT,
                reward DECIMAL(18,8),
                referral_commission DECIMAL(18,8) DEFAULT 0,
                view_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                role VARCHAR(20) DEFAULT 'admin',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        console.log('Database tables initialized');
    } catch (error) {
        console.error('Database initialization error:', error);
    }
}

initDatabase();

async function faucetPaySend(email, amount) {
    try {
        const response = await axios.post('https://faucetpay.io/api/v1/send', {
            api_key: process.env.FAUCETPAY_API_KEY,
            amount: amount,
            to: email,
            currency: 'USDT',
            referral: 'ptc-system'
        });
        
        if (response.data.status === 200) {
            return { success: true, payout_id: response.data.payout_id };
        }
        
        return { success: false, message: response.data.message };
    } catch (error) {
        console.error('FaucetPay error:', error.response?.data || error.message);
        return { success: false, message: 'Payment API error' };
    }
}

async function checkFraud(userId) {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = result.rows[0];
    
    let score = 0;
    const reasons = [];
    
    const timeSince = Date.now() - user.last_click_time;
    if (timeSince < 5000 && user.last_click_time > 0) {
        score += 30;
        reasons.push('Clicks too fast');
    }
    
    if (user.ads_today > (parseInt(process.env.DAILY_AD_LIMIT) || 20)) {
        score += 50;
        reasons.push('Exceeded daily limit');
    }
    
    const ipCheck = await pool.query(
        'SELECT COUNT(*) as count FROM users WHERE ip_address = $1 AND id != $2',
        [user.ip_address, userId]
    );
    
    if (ipCheck.rows[0].count > 3) {
        score += 40;
        reasons.push('Multiple accounts detected');
    }
    
    return { fraudScore: score, reasons };
}

function authenticateAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'No token' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default-secret');
        req.adminId = decoded.adminId;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/config', (req, res) => {
    res.json({
        success: true,
        config: {
            minWithdrawal: parseFloat(process.env.MIN_WITHDRAWAL || 0.00001),
            dailyAdLimit: parseInt(process.env.DAILY_AD_LIMIT || 20),
            referralCommission: parseFloat(process.env.REFERRAL_COMMISSION || 0.4)
        }
    });
});

app.post('/api/user/connect', async (req, res) => {
    try {
        const { email, referralCode } = req.body;
        const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        
        if (!email || !email.includes('@')) {
            return res.status(400).json({ success: false, message: 'Invalid email' });
        }
        
        const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        
        if (existing.rows.length > 0) {
            const user = existing.rows[0];
            
            if (user.is_banned) {
                return res.status(403).json({ success: false, message: 'Account banned' });
            }
            
            return res.json({
                success: true,
                user: {
                    id: user.id,
                    email: user.email,
                    balance: parseFloat(user.balance),
                    totalEarned: parseFloat(user.total_earned),
                    referralEarnings: parseFloat(user.referral_earnings),
                    totalClicks: user.total_clicks,
                    adsToday: user.ads_today,
                    referralCode: user.referral_code,
                    referredBy: user.referred_by,
                    fraudScore: user.fraud_score
                }
            });
        }
        
        const newRefCode = 'REF' + Math.random().toString(36).substring(2, 9).toUpperCase();
        
        const result = await pool.query(
            `INSERT INTO users (email, referral_code, referred_by, ip_address, last_reset_date)
             VALUES ($1, $2, $3, $4, CURRENT_DATE) RETURNING id`,
            [email, newRefCode, referralCode || null, ipAddress]
        );
        
        res.json({
            success: true,
            user: {
                id: result.rows[0].id,
                email,
                balance: 0,
                totalEarned: 0,
                referralEarnings: 0,
                totalClicks: 0,
                adsToday: 0,
                referralCode: newRefCode,
                referredBy: referralCode || null,
                fraudScore: 0
            }
        });
        
    } catch (error) {
        console.error('Connect error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/user/claim-ad', async (req, res) => {
    try {
        const { userId, adId, reward } = req.body;
        
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        const user = result.rows[0];
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        if (user.is_banned) {
            return res.status(403).json({ success: false, message: 'Account banned' });
        }
        
        const dailyLimit = parseInt(process.env.DAILY_AD_LIMIT || 20);
        if (user.ads_today >= dailyLimit) {
            return res.status(429).json({ success: false, message: 'Daily limit reached' });
        }
        
        const fraudCheck = await checkFraud(userId);
        
        if (fraudCheck.fraudScore > 70) {
            return res.status(403).json({
                success: false,
                message: 'Suspicious activity detected',
                fraudScore: fraudCheck.fraudScore
            });
        }
        
        const rewardAmount = parseFloat(reward);
        
        await pool.query(
            `UPDATE users SET
             balance = balance + $1,
             total_earned = total_earned + $1,
             total_clicks = total_clicks + 1,
             ads_today = ads_today + 1,
             last_click_time = $2,
             fraud_score = $3
             WHERE id = $4`,
            [rewardAmount, Date.now(), fraudCheck.fraudScore, userId]
        );
        
        await pool.query(
            'INSERT INTO ad_views (user_id, ad_id, reward) VALUES ($1, $2, $3)',
            [userId, adId, rewardAmount]
        );
        
        let referralCommission = 0;
        if (user.referred_by) {
            const commission = rewardAmount * parseFloat(process.env.REFERRAL_COMMISSION || 0.4);
            
            await pool.query(
                `UPDATE users SET
                 balance = balance + $1,
                 referral_earnings = referral_earnings + $1
                 WHERE referral_code = $2`,
                [commission, user.referred_by]
            );
            
            referralCommission = commission;
        }
        
        const updated = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        const updatedUser = updated.rows[0];
        
        res.json({
            success: true,
            user: {
                balance: parseFloat(updatedUser.balance),
                totalEarned: parseFloat(updatedUser.total_earned),
                totalClicks: updatedUser.total_clicks,
                adsToday: updatedUser.ads_today,
                fraudScore: updatedUser.fraud_score
            },
            referralCommission
        });
        
    } catch (error) {
        console.error('Claim error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/user/withdraw', async (req, res) => {
    try {
        const { userId, amount } = req.body;
        
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        const user = result.rows[0];
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        if (user.is_banned) {
            return res.status(403).json({ success: false, message: 'Account banned' });
        }
        
        const withdrawAmount = parseFloat(amount);
        const minWithdraw = parseFloat(process.env.MIN_WITHDRAWAL || 0.00001);
        
        if (withdrawAmount < minWithdraw) {
            return res.status(400).json({ success: false, message: 'Amount too low' });
        }
        
        if (withdrawAmount > parseFloat(user.balance)) {
            return res.status(400).json({ success: false, message: 'Insufficient balance' });
        }
        
        const withdrawalId = 'WD' + Date.now();
        
        await pool.query(
            'INSERT INTO withdrawals (id, user_id, email, amount) VALUES ($1, $2, $3, $4)',
            [withdrawalId, userId, user.email, withdrawAmount]
        );
        
        await pool.query(
            'UPDATE users SET balance = balance - $1 WHERE id = $2',
            [withdrawAmount, userId]
        );
        
        res.json({
            success: true,
            withdrawalId,
            message: 'Withdrawal request submitted'
        });
        
    } catch (error) {
        console.error('Withdrawal error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/user/:userId/stats', async (req, res) => {
    try {
        const userId = req.params.userId;
        
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        const user = result.rows[0];
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const refCount = await pool.query(
            'SELECT COUNT(*) as count FROM users WHERE referred_by = $1',
            [user.referral_code]
        );
        
        const withdrawals = await pool.query(
            'SELECT * FROM withdrawals WHERE user_id = $1 ORDER BY request_date DESC',
            [userId]
        );
        
        res.json({
            success: true,
            user: {
                email: user.email,
                balance: parseFloat(user.balance),
                totalEarned: parseFloat(user.total_earned),
                referralEarnings: parseFloat(user.referral_earnings),
                totalClicks: user.total_clicks,
                adsToday: user.ads_today,
                referralCode: user.referral_code,
                referralCount: parseInt(refCount.rows[0].count),
                fraudScore: user.fraud_score,
                isBanned: user.is_banned
            },
            withdrawals: withdrawals.rows.map(w => ({
                id: w.id,
                amount: parseFloat(w.amount),
                status: w.status,
                requestDate: w.request_date,
                processedDate: w.processed_date,
                payoutId: w.payout_id
            }))
        });
        
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        const admin = result.rows[0];
        const validPassword = await bcrypt.compare(password, admin.password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { adminId: admin.id, role: admin.role },
            process.env.JWT_SECRET || 'default-secret',
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            admin: {
                username: admin.username,
                role: admin.role
            }
        });
        
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/admin/withdrawals', authenticateAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        
        let query = 'SELECT w.*, u.fraud_score FROM withdrawals w JOIN users u ON w.user_id = u.id';
        const params = [];
        
        if (status) {
            query += ' WHERE w.status = $1';
            params.push(status);
        }
        
        query += ' ORDER BY w.request_date DESC';
        
        const result = await pool.query(query, params);
        
        res.json({
            success: true,
            withdrawals: result.rows.map(w => ({
                id: w.id,
                userId: w.user_id,
                email: w.email,
                amount: parseFloat(w.amount),
                status: w.status,
                requestDate: w.request_date,
                processedDate: w.processed_date,
                payoutId: w.payout_id,
                fraudScore: w.fraud_score
            }))
        });
        
    } catch (error) {
        console.error('Get withdrawals error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/admin/withdrawal/approve', authenticateAdmin, async (req, res) => {
    try {
        const { withdrawalId } = req.body;
        
        const result = await pool.query('SELECT * FROM withdrawals WHERE id = $1', [withdrawalId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Withdrawal not found' });
        }
        
        const withdrawal = result.rows[0];
        
        if (withdrawal.status !== 'pending') {
            return res.status(400).json({ success: false, message: 'Already processed' });
        }
        
        const paymentResult = await faucetPaySend(withdrawal.email, parseFloat(withdrawal.amount));
        
        if (paymentResult.success) {
            await pool.query(
                `UPDATE withdrawals SET
                 status = 'completed',
                 payout_id = $1,
                 processed_date = CURRENT_TIMESTAMP,
                 processed_by = $2
                 WHERE id = $3`,
                [paymentResult.payout_id, req.adminId, withdrawalId]
            );
            
            res.json({
                success: true,
                payoutId: paymentResult.payout_id
            });
        } else {
            res.status(400).json({
                success: false,
                message: paymentResult.message
            });
        }
        
    } catch (error) {
        console.error('Approve error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/admin/withdrawal/reject', authenticateAdmin, async (req, res) => {
    try {
        const { withdrawalId } = req.body;
        
        const result = await pool.query('SELECT * FROM withdrawals WHERE id = $1', [withdrawalId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Withdrawal not found' });
        }
        
        const withdrawal = result.rows[0];
        
        await pool.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2',
            [withdrawal.amount, withdrawal.user_id]
        );
        
        await pool.query(
            `UPDATE withdrawals SET
             status = 'rejected',
             processed_date = CURRENT_TIMESTAMP,
             processed_by = $1
             WHERE id = $2`,
            [req.adminId, withdrawalId]
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Reject error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

async function resetDailyAds() {
    try {
        await pool.query('UPDATE users SET ads_today = 0 WHERE last_reset_date < CURRENT_DATE');
        await pool.query('UPDATE users SET last_reset_date = CURRENT_DATE WHERE last_reset_date < CURRENT_DATE');
        console.log('Daily ads reset');
    } catch (error) {
        console.error('Reset error:', error);
    }
}

setInterval(resetDailyAds, 60 * 60 * 1000);
app.post('/api/setup/create-admin', async (req, res) => {
    try {
        const { username, password, secretKey } = req.body;
        
        if (secretKey !== 'guadoo2025setup') {
            return res.status(403).json({ success: false, message: 'Invalid secret key' });
        }
        
        const existing = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        
        if (existing.rows.length > 0) {
            return res.json({ success: false, message: 'Admin already exists' });
        }
        
        const passwordHash = await bcrypt.hash(password, 10);
        
        await pool.query(
            'INSERT INTO admins (username, password_hash, email, role) VALUES ($1, $2, $3, $4)',
            [username, passwordHash, 'admin@guadoo.net', 'superadmin']
        );
        
        res.json({
            success: true,
            message: 'Admin created successfully',
            username: username
        });
        
    } catch (error) {
        console.error('Create admin error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log('Server running on port', PORT);
    console.log('Environment:', process.env.NODE_ENV || 'development');
    console.log('Frontend URL:', process.env.FRONTEND_URL || 'Not set');
    resetDailyAds();
});

process.on('SIGTERM', async () => {
    console.log('SIGTERM received, closing...');
    await pool.end();
    process.exit(0);
});
