
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'santa-clara-secret';

// --- AUTH ---
app.post('/api/login', async (req, res) => {
  const { email, senha } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Usuário não encontrado' });
    const user = rows[0];
    // aceita senha plain ou bcrypt (para facilitar teste admin123)
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
    console.error(e);
    res.status(500).json({ error: 'Erro no login' });
  }
});

// --- RESPONSAVEIS ---
app.get('/api/responsaveis', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE perfil=\'responsavel\' ORDER BY nome');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/responsaveis', async (req, res) => {
  const { nome, email, telefone, aluno_id } = req.body;
  const telSomenteNumeros = (telefone || '').replace(/\D/g, '');
  try {
    const { rows } = await pool.query(
      'INSERT INTO usuarios (nome, email, telefone, perfil, senha) VALUES ($1,$2,$3,\'responsavel\',\'123456\') RETURNING *',
      [nome, email, telSomenteNumeros]
    );
    const resp = rows[0];
    if (aluno_id) {
      await pool.query('INSERT INTO aluno_responsavel (aluno_id, responsavel_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [aluno_id, resp.id]);
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
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- HEALTH ---
app.get('/', (req, res) => res.send('API Santa Clara online!'));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log('Server on '+PORT));
