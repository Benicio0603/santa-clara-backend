
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// Conexão com Supabase Session Pooler (IPv4 grátis para Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'santa-clara-secreto-2024';

// Teste de conexão
pool.on('error', (err) => console.error('Pool error', err));

// Cria tabelas se não existirem (resolve 500)
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nome VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        senha VARCHAR(200) NOT NULL,
        perfil VARCHAR(20) NOT NULL,
        telefone VARCHAR(20),
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS aluno_responsavel (
        aluno_id INT NOT NULL,
        responsavel_id INT NOT NULL,
        PRIMARY KEY (aluno_id, responsavel_id)
      );
      CREATE TABLE IF NOT EXISTS disciplinas (
        id SERIAL PRIMARY KEY,
        nome VARCHAR(100) NOT NULL
      );
      CREATE TABLE IF NOT EXISTS turmas (
        id SERIAL PRIMARY KEY,
        nome VARCHAR(100) NOT NULL
      );
    `);
    // Admin padrão se não existir
    const { rows } = await pool.query("SELECT id FROM usuarios WHERE email='admin@escola.com'");
    if (rows.length === 0) {
      await pool.query("INSERT INTO usuarios (nome,email,senha,perfil) VALUES ('Admin Santa Clara','admin@escola.com','admin123','admin')");
      console.log('Admin criado');
    }
    console.log('DB init OK');
  } catch (e) {
    console.error('Erro initDB', e);
  }
}
initDB();

// --- SAUDE (isso estava dando 404) ---
app.get('/', (req, res) => res.json({ message: 'API Santa Clara online!' }));
app.get('/api/saude', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'conectado', db: 'ok', timestamp: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ status: 'erro', error: e.message });
  }
});

// --- LOGIN (corrigido para retornar 400 e não 500 quando falta campo) ---
app.post('/api/login', async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) {
    return res.status(400).json({ error: 'Email e senha são obrigatórios' });
  }
  try {
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Usuário não encontrado' });
    const user = rows[0];
    let ok = false;
    if (user.senha.startsWith('$2a$') || user.senha.startsWith('$2b$')) {
      ok = await bcrypt.compare(senha, user.senha);
    } else {
      ok = user.senha === senha;
    }
    if (!ok) return res.status(401).json({ error: 'Senha inválida' });
    const token = jwt.sign({ id: user.id, perfil: user.perfil }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, perfil: user.perfil, usuario: user });
  } catch (e) {
    console.error('Login error', e);
    res.status(500).json({ error: 'Erro interno no login', details: e.message });
  }
});

// --- RESPONSAVEIS ---
app.get('/api/responsaveis', async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM usuarios WHERE perfil='responsavel' ORDER BY nome");
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/responsaveis', async (req, res) => {
  const { nome, email, telefone, aluno_id } = req.body;
  if (!nome || !email) return res.status(400).json({ error: 'Nome e email obrigatórios' });
  const telSomenteNumeros = (telefone || '').replace(/\D/g, '');
  try {
    const { rows } = await pool.query(
      "INSERT INTO usuarios (nome,email,telefone,perfil,senha) VALUES ($1,$2,$3,'responsavel','123456') RETURNING *",
      [nome, email, telSomenteNumeros]
    );
    const resp = rows[0];
    if (aluno_id) {
      await pool.query('INSERT INTO aluno_responsavel (aluno_id,responsavel_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [aluno_id, resp.id]);
    }
    res.json(resp);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/responsaveis/:id', async (req, res) => {
  const { id } = req.params;
  const { nome, email, telefone } = req.body;
  const telSomenteNumeros = (telefone || '').replace(/\D/g, '');
  try {
    const { rows } = await pool.query(
      'UPDATE usuarios SET nome=$1, email=$2, telefone=$3 WHERE id=$4 RETURNING *',
      [nome, email, telSomenteNumeros, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Responsável não encontrado' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log('Server on '+PORT));
