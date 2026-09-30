const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

function configurarSSL() {
    if (process.env.DB_SSL !== 'true') return undefined;

    if (process.env.DB_SSL_CA) {
        return { ca: process.env.DB_SSL_CA.replace(/\\n/g, '\n'), rejectUnauthorized: true };
    }

    if (process.env.DB_SSL_CA_PATH) {
        const ruta = path.resolve(__dirname, process.env.DB_SSL_CA_PATH);
        return { ca: fs.readFileSync(ruta), rejectUnauthorized: true };
    }
    return { rejectUnauthorized: true };
}

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    database: process.env.DB_DATABASE || 'TyperTraining',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    ssl: configurarSSL(),
    waitForConnections: true,
    connectionLimit: 10
});

module.exports = { pool };