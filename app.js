require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const { pool } = require('./conexion_bd.js');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
const PUERTO = process.env.PORT || 3000;
const MAX_PPM = 300;

if (!process.env.SESSION_SECRET) {
    console.error('Falta SESSION_SECRET en el .env');
    process.exit(1);
}

if (isProd) app.set('trust proxy', 1);
const origenesPermitidos = (process.env.FRONTEND_URL || 'http://localhost:5500')
    .split(',')
    .map((o) => o.trim());
app.use(cors({ origin: origenesPermitidos, credentials: true }));

app.use(express.json());

const NOMBRE_COOKIE = 'typer.sid';
const opcionesCookie = {
    httpOnly: true,
    secure: isProd,                    
    sameSite: isProd ? 'none' : 'lax' 
};

app.use(session({
    name: NOMBRE_COOKIE,
    secret: process.env.SESSION_SECRET,
    store: new MySQLStore({}, pool),  
    resave: false,
    saveUninitialized: false,
    cookie: { ...opcionesCookie, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const regenerarSesion = (req) =>
    new Promise((resolve, reject) => req.session.regenerate((err) => (err ? reject(err) : resolve())));

const requireAuth = (req, res, next) => {
    if (!req.session.user_id) return res.status(401).json({ msg: 'No autenticado' });
    next();
};

const validar = (req, res, next) => {
    const errores = validationResult(req);
    if (!errores.isEmpty()) return res.status(400).json({ msg: errores.array()[0].msg });
    next();
};

app.post('/api/registro', [
    body('username').trim()
        .matches(/^[a-zA-Z0-9_-]{8,20}$/)
        .withMessage('El username debe tener entre 8 y 20 caracteres (letras, números, _ o -)'),
    body('email').trim()
        .isEmail().withMessage('Ingresa un email válido'),
    body('password')
        .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+])[0-9a-zA-Z!@#$%^&*()_+]{8,50}$/)
        .withMessage('La contraseña debe tener mínimo 8 caracteres, una minúscula, una mayúscula, un número y un símbolo'),
    body('passwordConfirm')
        .custom((valor, { req }) => valor === req.body.password)
        .withMessage('Las contraseñas deben coincidir'),
    validar
], asyncH(async (req, res) => {
    const { username, email, password } = req.body;
    const hash = await bcrypt.hash(password, 10);

    let resultado;
    try {
        [resultado] = await pool.query(
            'INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)',
            [username, email, hash]
        );
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ msg: 'Ya hay un usuario registrado con ese nombre y/o email' });
        }
        throw err;
    }

    await regenerarSesion(req);
    req.session.user_id = resultado.insertId;
    res.status(201).json({ ok: true });
}));

app.post('/api/login', asyncH(async (req, res) => {
    const { username, password } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
        return res.status(400).json({ msg: 'Ingresa tu username y tu contraseña' });
    }

    const [filas] = await pool.query('SELECT id, password FROM usuarios WHERE username = ?', [username]);
    const usuario = filas[0];

    if (!usuario || !(await bcrypt.compare(password, usuario.password))) {
        return res.status(401).json({ msg: 'Usuario y/o contraseña incorrectos' });
    }

    await regenerarSesion(req);
    req.session.user_id = usuario.id;
    res.json({ ok: true });
}));

app.get('/api/me', requireAuth, asyncH(async (req, res) => {
    const [filas] = await pool.query(
        'SELECT username, ppm_record FROM usuarios WHERE id = ?',
        [req.session.user_id]
    );
    if (filas.length === 0) {
        return req.session.destroy(() => res.status(401).json({ msg: 'No autenticado' }));
    }
    res.json({ username: filas[0].username, ppm_record: filas[0].ppm_record ?? 0 });
}));

app.post('/api/record', requireAuth, asyncH(async (req, res) => {
    const ppm = req.body.ppm_record;
    if (!Number.isInteger(ppm) || ppm < 0 || ppm > MAX_PPM) {
        return res.status(400).json({ msg: 'Puntaje inválido' });
    }

    const [resultado] = await pool.query(
        'UPDATE usuarios SET ppm_record = ? WHERE id = ? AND (ppm_record IS NULL OR ppm_record < ?)',
        [ppm, req.session.user_id, ppm]
    );
    res.json({ ok: true, actualizado: resultado.affectedRows > 0 });
}));

app.post('/api/logout', (req, res, next) => {
    req.session.destroy((err) => {
        if (err) return next(err);
        res.clearCookie(NOMBRE_COOKIE, opcionesCookie);
        res.json({ ok: true });
    });
});

app.use((req, res) => res.status(404).json({ msg: 'Ruta no encontrada' }));

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ msg: 'Error del servidor' });
});

pool.query('SELECT 1')
    .then(() => {
        console.log('Conexión con la BD exitosa');
        app.listen(PUERTO, () => console.log(`API escuchando en el puerto ${PUERTO}...`));
    })
    .catch((err) => {
        console.error('No se pudo conectar a la BD:', err.message);
        process.exit(1);
});
