
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization','X-File-Name'] }));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('supabase') ? { rejectUnauthorized: false } : false
});

if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET precisa estar configurado em produção.');
}
const JWT_SECRET = process.env.JWT_SECRET || 'santa-clara-secret-2024';

// Helper universal de exclusão
async function excluirComOpcaoHistorico({ tabela, id, preservarHistorico, tabelasDependentes = [] }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (preservarHistorico) {
      // Verifica se tem coluna ativo
      const colInfo = await client.query(`SELECT column_name FROM information_schema.columns WHERE table_name=$1 AND column_name='ativo'`, [tabela]);
      if (colInfo.rows.length > 0) {
        await client.query(`UPDATE ${tabela} SET ativo=false WHERE id=$1`, [id]);
      } else {
        // Se não tem ativo, apenas retorna erro amigável
        throw new Error(`Tabela ${tabela} não possui controle de inativação. Use exclusão permanente.`);
      }
      await client.query('COMMIT');
      return { mensagem: `${tabela} inativado. Histórico preservado.`, preservado: true };
    } else {
      // Exclusão permanente - apaga dependentes primeiro
      for (const dep of tabelasDependentes) {
        await client.query(`DELETE FROM ${dep.tabela} WHERE ${dep.coluna}=$1`, [id]);
      }
      await client.query(`DELETE FROM ${tabela} WHERE id=$1`, [id]);
      await client.query('COMMIT');
      return { mensagem: `${tabela} e todo histórico excluídos permanentemente.`, preservado: false };
    }
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

async function excluirFrequenciasDosVinculos(client, vinculoIds) {
  const ids = [...new Set(vinculoIds.map(Number).filter(Number.isInteger))];
  if (!ids.length) return;
  await client.query('DELETE FROM justificativas WHERE falta_id IN (SELECT id FROM frequencias WHERE turma_disciplina_id=ANY($1::int[]))', [ids]);
  await client.query('DELETE FROM frequencias WHERE turma_disciplina_id=ANY($1::int[])', [ids]);
}

async function garantirTabelasFrequencias() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS alunos (
        id SERIAL PRIMARY KEY, nome VARCHAR(150) NOT NULL, matricula VARCHAR(30) UNIQUE,
        data_nascimento DATE, foto_url TEXT, ativo BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS turmas (
        id SERIAL PRIMARY KEY, nome VARCHAR(100) NOT NULL, ano_letivo INT DEFAULT 2027, ativo BOOLEAN DEFAULT true
      );
      CREATE TABLE IF NOT EXISTS disciplinas (
        id SERIAL PRIMARY KEY, nome VARCHAR(100) NOT NULL, ativo BOOLEAN DEFAULT true
      );
      CREATE TABLE IF NOT EXISTS professores (
        id SERIAL PRIMARY KEY, nome VARCHAR(150), email VARCHAR(150) UNIQUE, usuario_id INT, ativo BOOLEAN DEFAULT true
      );
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY, nome VARCHAR(150), email VARCHAR(150) UNIQUE,
        senha TEXT, senha_hash TEXT, perfil VARCHAR(30), telefone VARCHAR(30),
        foto_url TEXT, ativo BOOLEAN DEFAULT true, professor_id INT, responsavel_id INT, created_at TIMESTAMPTZ DEFAULT NOW()
      );
      ALTER TABLE alunos ADD COLUMN IF NOT EXISTS matricula VARCHAR(30);
      ALTER TABLE alunos ADD COLUMN IF NOT EXISTS data_nascimento DATE;
      ALTER TABLE alunos ADD COLUMN IF NOT EXISTS foto_url TEXT;
      ALTER TABLE alunos ADD COLUMN IF NOT EXISTS ativo BOOLEAN DEFAULT true;
      ALTER TABLE alunos ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
      ALTER TABLE turmas ADD COLUMN IF NOT EXISTS ano_letivo INT DEFAULT 2027;
      ALTER TABLE turmas ADD COLUMN IF NOT EXISTS ativo BOOLEAN DEFAULT true;
      ALTER TABLE matriculas ADD COLUMN IF NOT EXISTS ativo BOOLEAN DEFAULT true;
      ALTER TABLE responsaveis ADD COLUMN IF NOT EXISTS telefone VARCHAR(30);
      ALTER TABLE responsaveis ADD COLUMN IF NOT EXISTS usuario_id INT;
      ALTER TABLE responsaveis ADD COLUMN IF NOT EXISTS parentesco VARCHAR(50) DEFAULT 'Responsável';
      ALTER TABLE responsaveis ADD COLUMN IF NOT EXISTS ativo BOOLEAN DEFAULT true;
      ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS professor_id INT;
      ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS responsavel_id INT;
      CREATE TABLE IF NOT EXISTS responsaveis (
        id SERIAL PRIMARY KEY, nome VARCHAR(150) NOT NULL, email VARCHAR(150) UNIQUE,
        telefone VARCHAR(30), usuario_id INT, parentesco VARCHAR(50) DEFAULT 'Responsável', ativo BOOLEAN DEFAULT true
      );
      CREATE TABLE IF NOT EXISTS aluno_responsavel (
        id SERIAL PRIMARY KEY, aluno_id INT REFERENCES alunos(id), responsavel_id INT REFERENCES responsaveis(id), parentesco VARCHAR(50) DEFAULT 'Responsável', UNIQUE(aluno_id, responsavel_id)
      );
      CREATE TABLE IF NOT EXISTS turmas_disciplinas (
        id SERIAL PRIMARY KEY, turma_id INT REFERENCES turmas(id), disciplina_id INT REFERENCES disciplinas(id), professor_id INT REFERENCES professores(id), UNIQUE(turma_id, disciplina_id, professor_id)
      );
      CREATE TABLE IF NOT EXISTS turma_disciplina (
        id SERIAL PRIMARY KEY, turma_id INT REFERENCES turmas(id), disciplina_id INT REFERENCES disciplinas(id), professor_id INT REFERENCES professores(id), UNIQUE(turma_id, disciplina_id, professor_id)
      );
      CREATE TABLE IF NOT EXISTS matriculas (
        id SERIAL PRIMARY KEY, aluno_id INT REFERENCES alunos(id), turma_id INT REFERENCES turmas(id), ativo BOOLEAN DEFAULT true, UNIQUE(aluno_id, turma_id)
      );
      CREATE TABLE IF NOT EXISTS frequencias (
        id SERIAL PRIMARY KEY, turma_disciplina_id INT, aluno_id INT, data DATE, presente BOOLEAN DEFAULT true, detalhes TEXT, created_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(turma_disciplina_id, aluno_id, data)
      );
      CREATE TABLE IF NOT EXISTS avisos (
        id SERIAL PRIMARY KEY, titulo VARCHAR(200), mensagem TEXT, turma_id INT, aluno_id INT,
        created_at TIMESTAMPTZ DEFAULT NOW(), ativo BOOLEAN DEFAULT true
      );
      ALTER TABLE avisos ADD COLUMN IF NOT EXISTS titulo VARCHAR(200);
      ALTER TABLE avisos ADD COLUMN IF NOT EXISTS mensagem TEXT;
      ALTER TABLE avisos ADD COLUMN IF NOT EXISTS turma_id INT;
      ALTER TABLE avisos ADD COLUMN IF NOT EXISTS aluno_id INT;
      ALTER TABLE avisos ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
      ALTER TABLE avisos ADD COLUMN IF NOT EXISTS ativo BOOLEAN DEFAULT true;
      CREATE TABLE IF NOT EXISTS notas (
        id SERIAL PRIMARY KEY,
        aluno_id INT REFERENCES alunos(id) ON DELETE CASCADE,
        disciplina_id INT REFERENCES disciplinas(id),
        turma_id INT REFERENCES turmas(id),
        professor_id INT REFERENCES professores(id),
        bimestre INT,
        nota NUMERIC(4,2),
        observacao TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(aluno_id, disciplina_id, turma_id, bimestre)
      );
      CREATE TABLE IF NOT EXISTS justificativas (
        id SERIAL PRIMARY KEY, falta_id INT REFERENCES frequencias(id) ON DELETE CASCADE, nome_original VARCHAR(255), mime_type VARCHAR(100), dados BYTEA, created_at TIMESTAMPTZ DEFAULT NOW()
      );
      ALTER TABLE frequencias ADD COLUMN IF NOT EXISTS justificativa TEXT;
      ALTER TABLE frequencias ADD COLUMN IF NOT EXISTS anexo_url TEXT;
      ALTER TABLE alunos ALTER COLUMN foto_url TYPE TEXT;
      ALTER TABLE professores ADD COLUMN IF NOT EXISTS usuario_id INT;
      ALTER TABLE professores ADD COLUMN IF NOT EXISTS telefone VARCHAR(30);
      ALTER TABLE turmas_disciplinas ADD COLUMN IF NOT EXISTS disciplina_id INT REFERENCES disciplinas(id);
      ALTER TABLE turma_disciplina ADD COLUMN IF NOT EXISTS disciplina_id INT REFERENCES disciplinas(id);
      ALTER TABLE notas ADD COLUMN IF NOT EXISTS aluno_id INT REFERENCES alunos(id) ON DELETE CASCADE;
      ALTER TABLE notas ADD COLUMN IF NOT EXISTS disciplina_id INT REFERENCES disciplinas(id);
      ALTER TABLE notas ADD COLUMN IF NOT EXISTS turma_id INT REFERENCES turmas(id);
      ALTER TABLE notas ADD COLUMN IF NOT EXISTS professor_id INT REFERENCES professores(id);
      ALTER TABLE notas ADD COLUMN IF NOT EXISTS bimestre INT;
      ALTER TABLE notas ADD COLUMN IF NOT EXISTS nota NUMERIC(4,2);
      ALTER TABLE notas ADD COLUMN IF NOT EXISTS observacao TEXT;
      ALTER TABLE justificativas ADD COLUMN IF NOT EXISTS dados BYTEA;
      ALTER TABLE turmas ALTER COLUMN ano_letivo SET DEFAULT 2027;
    `);
  } catch (e) {
    console.error('Falha ao preparar o banco de dados:', e);
    throw e;
  }
}

function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ erro: 'Token não informado' });
  const token = auth.split(' ')[1];
  try { req.usuario = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ erro: 'Token inválido' }); }
}
function exigirPerfil(...perfis) {
  return (req, res, next) => {
    if (!perfis.includes(req.usuario?.perfil)) {
      return res.status(403).json({ erro: 'Seu perfil não tem permissão para esta operação.' });
    }
    next();
  };
}
function formatarTelefone(value) {
  const telefone = String(value || '').replace(/\D/g, '');
  const numero = telefone.length === 10 || telefone.length === 11 ? `55${telefone}` : telefone;
  return /^55\d{10,11}$/.test(numero);
}

// SAUDE
app.get('/api/versao', (req,res)=> res.json({ versao:'PRODUCAO-V3-2026-11-09', notas: true, avisos_responsavel: true, matricula_responsavel: true, professores_whatsapp: true, login_filho: true }));
app.get('/api/saude', async (req,res)=>{
  try { await pool.query('SELECT 1'); res.json({status:'conectado', banco:'postgres'}); }
  catch(e){ res.json({status:'erro', erro:e.message}); }
});

// LOGIN - aceita hash e plain
app.post('/api/login', async (req,res)=>{
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: 'Informe e-mail e senha' });
  try {
    let r = await pool.query('SELECT * FROM usuarios WHERE LOWER(email)=LOWER($1) LIMIT 1', [email.trim()]);
    let usuario = r.rows[0];
    if (!usuario) {
      // Um aluno pode ter mais de um responsável; compare a senha em cada conta vinculada.
      r = await pool.query(`SELECT DISTINCT u.* FROM usuarios u
        JOIN responsaveis resp ON resp.usuario_id=u.id
        JOIN aluno_responsavel ar ON ar.responsavel_id=resp.id
        JOIN alunos a ON a.id=ar.aluno_id
        WHERE LOWER(TRIM(a.nome))=LOWER(TRIM($1)) AND u.perfil='responsavel' AND u.ativo IS DISTINCT FROM false`, [email.trim()]);
      for (const candidato of r.rows) {
        const senhaArmazenada = candidato.senha_hash || candidato.senha || '';
        const valida = senhaArmazenada.startsWith('$2')
          ? await bcrypt.compare(senha, senhaArmazenada)
          : senha === senhaArmazenada;
        if (valida) {
          usuario = candidato;
          break;
        }
      }
      if (!usuario) return res.status(401).json({ erro: 'Usuário ou senha incorretos' });
    }
    if (!usuario || usuario.ativo === false) return res.status(401).json({ erro: 'Usuário não encontrado ou inativo' });
    let ok = false;
    if (usuario.senha_hash && usuario.senha_hash.startsWith('$2')) {
      ok = await bcrypt.compare(senha, usuario.senha_hash);
    } else if (usuario.senha && usuario.senha.startsWith('$2')) {
      ok = await bcrypt.compare(senha, usuario.senha);
    } else {
      ok = senha === usuario.senha || senha === usuario.senha_hash;
    }
    if (!ok) return res.status(401).json({ erro: 'Senha incorreta' });
    const token = jwt.sign({ id: usuario.id, perfil: usuario.perfil, email: usuario.email, professor_id: usuario.professor_id }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email, perfil: usuario.perfil } });
  } catch(e){ console.error(e); res.status(500).json({ erro: 'Erro interno no login' }); }
});

// --- TURMAS ---
app.get('/api/turmas', autenticar, async (req,res)=>{
  try {
    if (req.query.incluirInativas === 'true') { const r = await pool.query('SELECT * FROM turmas ORDER BY nome'); return res.json(r.rows); }
    const r = await pool.query('SELECT * FROM turmas WHERE ativo IS NULL OR ativo=true ORDER BY nome');
    res.json(r.rows);
  } catch(e){ console.error('GET turmas', e); res.status(500).json({ erro:'Não foi possível carregar as turmas.' }); }
});
app.post('/api/turmas/:id/reativar', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try { await pool.query('UPDATE turmas SET ativo=true WHERE id=$1', [req.params.id]); res.json({ mensagem: 'Turma reativada com sucesso!' }); }
  catch(e){ res.status(400).json({ erro: e.message }); }
});
app.post('/api/turmas', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const { nome, ano_letivo } = req.body;
  if (!nome?.trim()) return res.status(400).json({ erro: 'Informe o nome da turma.' });
  const r = await pool.query('INSERT INTO turmas (nome, ano_letivo) VALUES ($1,$2) RETURNING *', [nome.trim(), ano_letivo || 2027]);
  res.json({ mensagem: 'Turma criada', turma: r.rows[0] });
});
app.put('/api/turmas/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const { nome, ano_letivo } = req.body;
  await pool.query('UPDATE turmas SET nome=$1, ano_letivo=$2 WHERE id=$3', [nome, ano_letivo, req.params.id]);
  res.json({ mensagem: 'Turma atualizada' });
});
app.delete('/api/turmas/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ erro:'ID de turma inválido.' });
  if (preservar) {
    try {
      await pool.query('UPDATE turmas SET ativo=false WHERE id=$1', [id]);
      return res.json({ mensagem:'Turma inativada. Histórico preservado.', preservado:true });
    } catch(e) { return res.status(400).json({ erro:e.message }); }
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const links = await client.query('SELECT id FROM turmas_disciplinas WHERE turma_id=$1 UNION SELECT id FROM turma_disciplina WHERE turma_id=$1', [id]);
    await excluirFrequenciasDosVinculos(client, links.rows.map((row) => row.id));
    await client.query('DELETE FROM notas WHERE turma_id=$1', [id]);
    await client.query('DELETE FROM matriculas WHERE turma_id=$1', [id]);
    await client.query('DELETE FROM avisos WHERE turma_id=$1', [id]);
    await client.query('DELETE FROM turmas_disciplinas WHERE turma_id=$1', [id]);
    await client.query('DELETE FROM turma_disciplina WHERE turma_id=$1', [id]);
    const hasLegacyClassColumn = await client.query(`SELECT 1 FROM information_schema.columns WHERE table_name='alunos' AND column_name='turma_id'`);
    if (hasLegacyClassColumn.rowCount) await client.query('UPDATE alunos SET turma_id=NULL WHERE turma_id=$1', [id]);
    await client.query('DELETE FROM turmas WHERE id=$1', [id]);
    await client.query('COMMIT');
    res.json({ mensagem:'Turma e seus vínculos, notas e frequências excluídos permanentemente. Os alunos foram mantidos.', preservado:false });
  } catch(e){
    await client.query('ROLLBACK');
    console.error('Delete turma', e);
    res.status(400).json({ erro: e.message });
  } finally {
    client.release();
  }
});

// --- DISCIPLINAS ---
app.get('/api/disciplinas', autenticar, async (req,res)=>{
  try {
    if (req.query.incluirInativas === 'true') { const r = await pool.query('SELECT * FROM disciplinas ORDER BY nome'); return res.json(r.rows); }
    const r = await pool.query('SELECT * FROM disciplinas WHERE ativo IS NULL OR ativo=true ORDER BY nome');
    res.json(r.rows);
  } catch(e){ console.error('GET disciplinas', e); res.status(500).json({ erro:'Não foi possível carregar as disciplinas.' }); }
});
app.post('/api/disciplinas/:id/reativar', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try { await pool.query('UPDATE disciplinas SET ativo=true WHERE id=$1', [req.params.id]); res.json({ mensagem: 'Disciplina reativada!' }); }
  catch(e){ res.status(400).json({ erro: e.message }); }
});
app.post('/api/disciplinas', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const nome = req.body.nome?.trim();
  if (!nome) return res.status(400).json({ erro: 'Informe o nome da disciplina.' });
  const r = await pool.query('INSERT INTO disciplinas (nome) VALUES ($1) RETURNING *', [nome]);
  res.json({ mensagem:'Disciplina criada', disciplina:r.rows[0] });
});
app.put('/api/disciplinas/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const nome = req.body.nome?.trim();
  if (!nome) return res.status(400).json({ erro: 'Informe o nome da disciplina.' });
  await pool.query('UPDATE disciplinas SET nome=$1 WHERE id=$2', [nome, req.params.id]);
  res.json({ mensagem:'Disciplina atualizada' });
});
app.delete('/api/disciplinas/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ erro:'ID de disciplina inválido.' });
  const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
  if (preservar) {
    try {
      await pool.query('UPDATE disciplinas SET ativo=false WHERE id=$1', [id]);
      return res.json({ mensagem:'Disciplina inativada. Histórico preservado.', preservado:true });
    } catch(e) { return res.status(400).json({ erro:e.message }); }
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const links = await client.query('SELECT id FROM turmas_disciplinas WHERE disciplina_id=$1 UNION SELECT id FROM turma_disciplina WHERE disciplina_id=$1', [id]);
    await excluirFrequenciasDosVinculos(client, links.rows.map((row) => row.id));
    await client.query('DELETE FROM notas WHERE disciplina_id=$1', [id]);
    await client.query('DELETE FROM turmas_disciplinas WHERE disciplina_id=$1', [id]);
    await client.query('DELETE FROM turma_disciplina WHERE disciplina_id=$1', [id]);
    await client.query('DELETE FROM disciplinas WHERE id=$1', [id]);
    await client.query('COMMIT');
    res.json({ mensagem:'Disciplina e seu histórico excluídos permanentemente.', preservado:false });
  } catch(e){ await client.query('ROLLBACK'); res.status(400).json({ erro:e.message }); }
  finally { client.release(); }
});

// --- PROFESSORES ---
app.get('/api/professores', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try {
    if (req.query.incluirInativas === 'true') { const r = await pool.query('SELECT * FROM professores ORDER BY nome'); return res.json(r.rows); }
    const r = await pool.query('SELECT * FROM professores WHERE ativo IS NULL OR ativo=true ORDER BY nome');
    res.json(r.rows);
  } catch(e){ console.error('GET professores', e); res.status(500).json({ erro:'Não foi possível carregar os professores.' }); }
});
app.post('/api/professores/:id/reativar', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try {
    const updated = await pool.query('UPDATE professores SET ativo=true WHERE id=$1 RETURNING usuario_id', [req.params.id]);
    if (!updated.rowCount) return res.status(404).json({ erro:'Professor não encontrado.' });
    if (updated.rows[0].usuario_id) await pool.query('UPDATE usuarios SET ativo=true WHERE id=$1', [updated.rows[0].usuario_id]);
    res.json({ mensagem: 'Professor reativado!' });
  }
  catch(e){ res.status(400).json({ erro: e.message }); }
});
app.post('/api/professores', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const { nome, email, senha, telefone, whatsapp } = req.body;
  const nomeLimpo = nome?.trim();
  const emailLimpo = email?.trim().toLowerCase();
  const telefoneLimpo = String(whatsapp || telefone || '').trim();
  if (!nomeLimpo || !emailLimpo || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLimpo) || !senha) {
    return res.status(400).json({ erro: 'Informe nome, e-mail válido e senha inicial.' });
  }
  if (senha.length < 8) return res.status(400).json({ erro:'A senha inicial precisa ter pelo menos 8 caracteres.' });
  if (telefoneLimpo && !formatarTelefone(telefoneLimpo)) return res.status(400).json({ erro:'Informe um WhatsApp válido com DDD.' });
  const client = await pool.connect();
  try {
  await client.query('BEGIN');
  const hash = senha ? await bcrypt.hash(senha,10) : null;
  const u = await client.query('INSERT INTO usuarios (nome,email,senha,senha_hash,perfil,telefone,ativo) VALUES ($1,$2,$3,$4,$5,$6,true) RETURNING id', [nomeLimpo,emailLimpo,hash,hash,'professor',telefoneLimpo]);
  const p = await client.query('INSERT INTO professores (nome,email,usuario_id,telefone) VALUES ($1,$2,$3,$4) RETURNING *', [nomeLimpo,emailLimpo,u.rows[0].id,telefoneLimpo]);
  await client.query('UPDATE usuarios SET professor_id=$1 WHERE id=$2', [p.rows[0].id, u.rows[0].id]);
  await client.query('COMMIT');
  res.json({ mensagem:'Professor criado', professor:p.rows[0] });
  } catch(e) {
    await client.query('ROLLBACK');
    res.status(400).json({ erro:e.message });
  } finally {
    client.release();
  }
});
app.put('/api/professores/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const { nome, email, senha, telefone, whatsapp } = req.body;
  const nomeLimpo = nome?.trim();
  const emailLimpo = email?.trim().toLowerCase();
  const telefoneLimpo = String(whatsapp || telefone || '').trim();
  if (!nomeLimpo || !emailLimpo || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLimpo)) {
    return res.status(400).json({ erro: 'Informe nome e e-mail válido.' });
  }
  if (senha && senha.length < 8) return res.status(400).json({ erro:'A nova senha precisa ter pelo menos 8 caracteres.' });
  if (telefoneLimpo && !formatarTelefone(telefoneLimpo)) return res.status(400).json({ erro:'Informe um WhatsApp válido com DDD.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const updated = await client.query('UPDATE professores SET nome=$1, email=$2, telefone=$3 WHERE id=$4 RETURNING usuario_id', [nomeLimpo,emailLimpo,telefoneLimpo,req.params.id]);
    if (!updated.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ erro:'Professor não encontrado.' });
    }
    const userId = updated.rows[0].usuario_id;
    if (userId) {
      if (senha) {
        const hash = await bcrypt.hash(senha,10);
        await client.query('UPDATE usuarios SET nome=$1,email=$2,telefone=$3,senha=$4,senha_hash=$4 WHERE id=$5', [nomeLimpo,emailLimpo,telefoneLimpo,hash,userId]);
      } else {
        await client.query('UPDATE usuarios SET nome=$1,email=$2,telefone=$3 WHERE id=$4', [nomeLimpo,emailLimpo,telefoneLimpo,userId]);
      }
    }
    await client.query('COMMIT');
    res.json({ mensagem:'Professor atualizado' });
  } catch(e) {
    await client.query('ROLLBACK');
    res.status(400).json({ erro:e.message });
  } finally { client.release(); }
});
app.delete('/api/professores/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ erro:'ID de professor inválido.' });
  const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
  const professor = await pool.query('SELECT usuario_id FROM professores WHERE id=$1', [id]);
  if (!professor.rowCount) return res.status(404).json({ erro:'Professor não encontrado.' });
  if (preservar) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE professores SET ativo=false WHERE id=$1', [id]);
      if (professor.rows[0].usuario_id) await client.query('UPDATE usuarios SET ativo=false WHERE id=$1', [professor.rows[0].usuario_id]);
      await client.query('COMMIT');
      return res.json({ mensagem:'Professor e acesso inativados. Histórico preservado.', preservado:true });
    } catch(e) {
      await client.query('ROLLBACK');
      return res.status(400).json({ erro:e.message });
    } finally { client.release(); }
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const links = await client.query('SELECT id FROM turmas_disciplinas WHERE professor_id=$1 UNION SELECT id FROM turma_disciplina WHERE professor_id=$1', [id]);
    await excluirFrequenciasDosVinculos(client, links.rows.map((row) => row.id));
    await client.query('DELETE FROM notas WHERE professor_id=$1', [id]);
    await client.query('DELETE FROM turmas_disciplinas WHERE professor_id=$1', [id]);
    await client.query('DELETE FROM turma_disciplina WHERE professor_id=$1', [id]);
    await client.query('DELETE FROM professores WHERE id=$1', [id]);
    if (professor.rows[0].usuario_id) await client.query('DELETE FROM usuarios WHERE id=$1', [professor.rows[0].usuario_id]);
    await client.query('COMMIT');
    res.json({ mensagem:'Professor, acesso e histórico excluídos permanentemente.', preservado:false });
  } catch(e){ await client.query('ROLLBACK'); res.status(400).json({ erro:e.message }); }
  finally { client.release(); }
});

// --- ALUNOS ---
app.get('/api/alunos', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try {
    const activeFilter = req.query.incluirInativas === 'true' ? '' : 'WHERE a.ativo IS NULL OR a.ativo=true';
    const r = await pool.query(`
      SELECT a.*,
        ARRAY(
          SELECT DISTINCT m.turma_id FROM matriculas m
          WHERE m.aluno_id=a.id AND (m.ativo IS NULL OR m.ativo=true)
          ORDER BY m.turma_id
        ) AS turmas_ids
      FROM alunos a
      ${activeFilter}
      ORDER BY a.nome
    `);
    res.json(r.rows);
  } catch(e){ console.error('GET alunos', e); res.status(500).json({ erro:'Não foi possível carregar os alunos.' }); }
});
app.post('/api/alunos/:id/reativar', autenticar, exigirPerfil('admin'), async (req,res)=>{ try { await pool.query('UPDATE alunos SET ativo=true WHERE id=$1', [req.params.id]); res.json({ mensagem: 'Aluno reativado!' }); } catch(e){ res.status(400).json({ erro: e.message }); } });
app.post('/api/alunos', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const { nome, matricula, data_nascimento } = req.body;
  const r = await pool.query('INSERT INTO alunos (nome,matricula,data_nascimento) VALUES ($1,$2,$3) RETURNING *', [nome,matricula, data_nascimento||null]);
  res.json({ mensagem:'Aluno cadastrado e salvo no servidor', aluno:r.rows[0] });
});
app.put('/api/alunos/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const { nome, matricula, data_nascimento } = req.body;
  await pool.query('UPDATE alunos SET nome=$1,matricula=$2,data_nascimento=$3 WHERE id=$4', [nome,matricula,data_nascimento||null,req.params.id]);
  res.json({ mensagem:'Aluno atualizado' });
});
app.put('/api/alunos/:id/foto', autenticar, async (req,res)=>{
  try {
    if (!['admin', 'responsavel'].includes(req.usuario.perfil)) {
      return res.status(403).json({ erro:'Seu perfil não pode alterar a foto do aluno.' });
    }
    const { imagem } = req.body;
    const match = typeof imagem === 'string'
      ? imagem.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+={0,2})$/)
      : null;
    if (!match) return res.status(400).json({ erro:'Envie uma imagem JPEG, PNG ou WEBP válida.' });
    const bytes = Buffer.from(match[2], 'base64');
    if (!bytes.length || bytes.length > 10 * 1024 * 1024) {
      return res.status(400).json({ erro:'A imagem deve ter no máximo 10 MB.' });
    }
    if (req.usuario.perfil === 'responsavel') {
      const linked = await pool.query(`
        SELECT 1 FROM aluno_responsavel ar
        JOIN responsaveis r ON r.id=ar.responsavel_id
        WHERE ar.aluno_id=$1 AND r.usuario_id=$2
      `, [req.params.id, req.usuario.id]);
      if (!linked.rowCount) return res.status(403).json({ erro:'Este aluno não está vinculado ao seu acesso.' });
    }
    const updated = await pool.query('UPDATE alunos SET foto_url=$1 WHERE id=$2 RETURNING id', [imagem, req.params.id]);
    if (!updated.rowCount) return res.status(404).json({ erro:'Aluno não encontrado.' });
    res.json({ mensagem:'Foto salva.', foto_url:`/api/alunos/${req.params.id}/foto-arquivo` });
  } catch(e) {
    console.error('[PUT /api/alunos/:id/foto]', e);
    res.status(500).json({ erro:'Não foi possível salvar a foto do aluno.' });
  }
});
app.get('/api/alunos/:id/foto-arquivo', autenticar, async (req,res)=>{
  try {
    if (!['admin', 'responsavel'].includes(req.usuario.perfil)) {
      return res.status(403).json({ erro:'Seu perfil não pode consultar a foto do aluno.' });
    }
    if (req.usuario.perfil === 'responsavel') {
      const linked = await pool.query(`
        SELECT 1 FROM aluno_responsavel ar
        JOIN responsaveis r ON r.id=ar.responsavel_id
        WHERE ar.aluno_id=$1 AND r.usuario_id=$2
      `, [req.params.id, req.usuario.id]);
      if (!linked.rowCount) return res.status(403).json({ erro:'Este aluno não está vinculado ao seu acesso.' });
    }
    const result = await pool.query('SELECT foto_url FROM alunos WHERE id=$1', [req.params.id]);
    const match = result.rows[0]?.foto_url?.match(/^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/]+={0,2})$/);
    if (!match) return res.status(404).json({ erro:'Foto do aluno não encontrada.' });
    res.setHeader('Content-Type', match[1]);
    res.setHeader('Cache-Control', 'private, max-age=300');
    res.send(Buffer.from(match[2], 'base64'));
  } catch(e) {
    console.error('[GET /api/alunos/:id/foto-arquivo]', e);
    res.status(500).json({ erro:'Não foi possível carregar a foto do aluno.' });
  }
});
app.delete('/api/alunos/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try {
    const { confirmar_exclusao_com_historico } = req.body || {};
    const r = await pool.query('SELECT COUNT(*) FROM frequencias WHERE aluno_id=$1', [req.params.id]);
    const temHist = parseInt(r.rows[0].count) > 0;
    if (temHist && !confirmar_exclusao_com_historico) {
      return res.status(400).json({ erro:'Aluno possui histórico. Confirme exclusão permanente.', temHistorico:true });
    }
    await pool.query('DELETE FROM frequencias WHERE aluno_id=$1', [req.params.id]);
    await pool.query('DELETE FROM matriculas WHERE aluno_id=$1', [req.params.id]);
    await pool.query('DELETE FROM aluno_responsavel WHERE aluno_id=$1', [req.params.id]);
    await pool.query('DELETE FROM avisos WHERE aluno_id=$1', [req.params.id]);
    await pool.query('DELETE FROM alunos WHERE id=$1', [req.params.id]);
    res.json({ mensagem:'Aluno excluído permanentemente com histórico' });
  } catch(e){ res.status(400).json({ erro:e.message }); }
});

// --- RESPONSAVEIS ---
app.get('/api/responsaveis', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try{
    const incluir = req.query.incluirInativas === 'true';
    // ATENÇÃO: responsaveis NÃO tem coluna email. E-mail fica só em usuarios.
    // Por isso selecionamos colunas explícitas, nunca r.* + r.email.
    const r = await pool.query(`
      SELECT * FROM (
        SELECT r.id, r.nome, r.telefone, r.usuario_id, r.parentesco, r.ativo,
               u.email as usuario_email,
               COALESCE((SELECT string_agg(a.nome, ', ' ORDER BY a.nome) FROM alunos a JOIN aluno_responsavel ar ON ar.aluno_id=a.id WHERE ar.responsavel_id=r.id), '') as alunos_vinculados
        FROM responsaveis r LEFT JOIN usuarios u ON u.id=r.usuario_id
        UNION ALL
        SELECT NULL as id, u.nome, u.telefone, u.id as usuario_id, 'Responsável' as parentesco, u.ativo as ativo,
               u.email as usuario_email, '' as alunos_vinculados
        FROM usuarios u WHERE u.perfil='responsavel' AND NOT EXISTS (SELECT 1 FROM responsaveis r2 WHERE r2.usuario_id=u.id)
      ) t
      ${incluir ? '' : 'WHERE (t.ativo IS NULL OR t.ativo=true)'}
      ORDER BY t.nome`);
    res.json(r.rows);
  }catch(e){ console.error('[GET /responsaveis]', e); res.status(400).json({ erro:e.message }); }
});
app.get('/api/alunos/:id/responsaveis', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const r = await pool.query(`SELECT r.*, r.parentesco, u.email as usuario_email, r.telefone FROM responsaveis r JOIN aluno_responsavel ar ON ar.responsavel_id=r.id LEFT JOIN usuarios u ON u.id=r.usuario_id WHERE ar.aluno_id=$1 AND (r.ativo IS NULL OR r.ativo=true)`, [req.params.id]);
  res.json(r.rows);
});
app.post('/api/responsaveis', autenticar, exigirPerfil('admin'), async (req,res)=>{
  let client;
  try{
    const { nome, email, telefone, parentesco, alunos_ids } = req.body;
    if(!nome?.trim()) return res.status(400).json({ erro:'Informe o nome do responsável.' });
    if(!email?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return res.status(400).json({ erro:'Informe um e-mail válido.' });
    if(!formatarTelefone(telefone)) return res.status(400).json({ erro:'Informe um WhatsApp válido com DDD.' });
    if(!Array.isArray(alunos_ids) || !alunos_ids.length) return res.status(400).json({ erro:'Vincule pelo menos um aluno ao responsável.' });
    const studentIds = [...new Set(alunos_ids.map(Number))];
    if(studentIds.some((id) => !Number.isInteger(id) || id < 1)) return res.status(400).json({ erro:'A lista de alunos contém um ID inválido.' });

    const senhaTemporaria = crypto.randomBytes(9).toString('hex');
    const hash = await bcrypt.hash(senhaTemporaria,10);
    const nomeLimpo = nome.trim();
    const emailLimpo = email.trim();
    const telefoneLimpo = String(telefone).trim();
    client = await pool.connect();
    await client.query('BEGIN');

    const students = await client.query(
      'SELECT id FROM alunos WHERE id=ANY($1::int[]) AND (ativo IS NULL OR ativo=true)',
      [studentIds]
    );
    if (students.rowCount !== studentIds.length) throw new Error('Um ou mais alunos não existem ou estão inativos. Atualize a lista e tente novamente.');

    const duplicate = await client.query(
      'SELECT id, ativo, perfil, responsavel_id FROM usuarios WHERE LOWER(email)=LOWER($1) LIMIT 1 FOR UPDATE',
      [emailLimpo]
    );
    if (duplicate.rowCount && duplicate.rows[0].perfil !== 'responsavel') {
      await client.query('ROLLBACK');
      return res.status(400).json({ erro:'Este e-mail já pertence a outro perfil. Informe um e-mail exclusivo para o responsável.' });
    }
    let userId;
    let responsibleId;
    let message;

    if (duplicate.rowCount && duplicate.rows[0].ativo !== false) {
      userId = duplicate.rows[0].id;
      const existing = await client.query('SELECT id FROM responsaveis WHERE usuario_id=$1 LIMIT 1', [userId]);
      if (existing.rowCount) {
        await client.query('ROLLBACK');
        return res.status(400).json({ erro:'Este e-mail já está cadastrado e ativo. Use outro e-mail ou edite o responsável existente em Vínculos.' });
      }
      const responsible = await client.query(
        'INSERT INTO responsaveis (nome,telefone,usuario_id,parentesco,ativo) VALUES ($1,$2,$3,$4,true) RETURNING id',
        [nomeLimpo, telefoneLimpo, userId, parentesco || 'Responsável']
      );
      responsibleId = responsible.rows[0].id;
      await client.query(
        'UPDATE usuarios SET nome=$1, senha=$2, senha_hash=$2, telefone=$3, responsavel_id=$4 WHERE id=$5',
        [nomeLimpo, hash, telefoneLimpo, responsibleId, userId]
      );
      message = 'Cadastro de responsável recuperado e vinculado.';
    } else if (duplicate.rowCount) {
      userId = duplicate.rows[0].id;
      responsibleId = duplicate.rows[0].responsavel_id;
      await client.query(
        'UPDATE usuarios SET nome=$1, senha=$2, senha_hash=$2, telefone=$3, ativo=true WHERE id=$4',
        [nomeLimpo, hash, telefoneLimpo, userId]
      );
      const existingResponsible = responsibleId
        ? await client.query('SELECT id FROM responsaveis WHERE id=$1 AND usuario_id=$2 FOR UPDATE', [responsibleId, userId])
        : { rowCount: 0, rows: [] };
      if (existingResponsible.rowCount) {
        await client.query(
          'UPDATE responsaveis SET nome=$1, telefone=$2, ativo=true WHERE id=$3',
          [nomeLimpo, telefoneLimpo, responsibleId]
        );
      } else {
        const responsible = await client.query(
          'INSERT INTO responsaveis (nome,telefone,usuario_id,parentesco,ativo) VALUES ($1,$2,$3,$4,true) RETURNING id',
          [nomeLimpo, telefoneLimpo, userId, parentesco || 'Responsável']
        );
        responsibleId = responsible.rows[0].id;
        await client.query('UPDATE usuarios SET responsavel_id=$1 WHERE id=$2', [responsibleId, userId]);
      }
      message = 'Responsável reativado e vinculado.';
    } else {
      const user = await client.query(
        'INSERT INTO usuarios (nome,email,senha,senha_hash,perfil,telefone,ativo) VALUES ($1,$2,$3,$4,$5,$6,true) RETURNING id',
        [nomeLimpo, emailLimpo, hash, hash, 'responsavel', telefoneLimpo]
      );
      userId = user.rows[0].id;
      const responsible = await client.query(
        'INSERT INTO responsaveis (nome,telefone,usuario_id,parentesco) VALUES ($1,$2,$3,$4) RETURNING id',
        [nomeLimpo, telefoneLimpo, userId, parentesco || 'Responsável']
      );
      responsibleId = responsible.rows[0].id;
      await client.query('UPDATE usuarios SET responsavel_id=$1 WHERE id=$2', [responsibleId, userId]);
      message = 'Responsável criado e vinculado.';
    }

    for (const studentId of studentIds) {
      await client.query(
        'INSERT INTO aluno_responsavel (aluno_id,responsavel_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [studentId, responsibleId]
      );
    }
    await client.query('COMMIT');
    res.json({ mensagem:message, senha_temporaria:senhaTemporaria });
  }catch(e){
    if (client) await client.query('ROLLBACK');
    console.error('[POST /responsaveis]', e);
    res.status(400).json({ erro:e.message });
  } finally {
    client?.release();
  }
});
app.put('/api/responsaveis/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try{
    const { nome, email, telefone, alunos_ids, senha_nova } = req.body;
    if (!nome?.trim() || !email?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return res.status(400).json({ erro:'Informe nome e e-mail válido.' });
    if (senha_nova && senha_nova.length < 8) return res.status(400).json({ erro:'A senha precisa ter pelo menos 8 caracteres.' });
    // responsaveis NÃO tem email - email fica só em usuarios
    await pool.query('UPDATE responsaveis SET nome=$1,telefone=$2 WHERE id=$3', [nome,telefone,req.params.id]);
    const r = await pool.query('SELECT usuario_id FROM responsaveis WHERE id=$1', [req.params.id]);
    if (r.rows[0]?.usuario_id) { await pool.query('UPDATE usuarios SET nome=$1,email=$2,telefone=$3 WHERE id=$4', [nome.trim(),email.trim(),telefone,r.rows[0].usuario_id]); if(senha_nova){ const hh = await bcrypt.hash(senha_nova,10); await pool.query('UPDATE usuarios SET senha=$1, senha_hash=$1 WHERE id=$2', [hh, r.rows[0].usuario_id]); } }
    // Troca de aluno: se veio alunos_ids, apaga vínculos antigos e cria os novos
    if (Array.isArray(alunos_ids)) {
      await pool.query('DELETE FROM aluno_responsavel WHERE responsavel_id=$1', [req.params.id]);
      for (const aluno_id of alunos_ids) {
        if (!aluno_id || isNaN(Number(aluno_id))) continue;
        await pool.query('INSERT INTO aluno_responsavel (aluno_id,responsavel_id) VALUES ($1,$2)', [Number(aluno_id), req.params.id]);
      }
    }
    res.json({ mensagem:'Responsável atualizado' });
  }catch(e){ console.error('[PUT /responsaveis]', e); res.status(400).json({ erro:e.message }); }
});
app.put('/api/alunos/:alunoId/responsaveis/:respId', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try{
    // parentesco NÃO existe em aluno_responsavel, só em responsaveis
    await pool.query('UPDATE responsaveis SET parentesco=$1 WHERE id=$2', [req.body.parentesco||'Responsável', req.params.respId]);
    res.json({ mensagem:'Vínculo atualizado' });
  }catch(e){ console.error('[PUT aluno-responsavel]', e); res.status(400).json({ erro:e.message }); }
});
app.delete('/api/responsaveis/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try {
    const idNum = Number(req.params.id);
    if (!idNum || isNaN(idNum)) return res.status(400).json({ erro:'ID do responsável inválido. Este registro é órfão (usuário sem responsável) - use o botão Recuperar ou cadastre de novo com o mesmo e-mail.' });
    const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
    const ruAntes = await pool.query('SELECT usuario_id FROM responsaveis WHERE id=$1', [idNum]);
    const usuarioId = ruAntes.rows[0]?.usuario_id;
    const ret = await excluirComOpcaoHistorico({ tabela:'responsaveis', id:idNum, preservarHistorico:preservar, tabelasDependentes:[{tabela:'aluno_responsavel',coluna:'responsavel_id'}] });
    if (usuarioId && !preservar) await pool.query('DELETE FROM usuarios WHERE id=$1', [usuarioId]);
    if (usuarioId && preservar) await pool.query('UPDATE usuarios SET ativo=false WHERE id=$1', [usuarioId]);
    res.json(ret);
  } catch(e){ console.error('[DELETE /responsaveis]', e); res.status(400).json({ erro:e.message }); }
});
app.delete('/api/alunos/:alunoId/responsaveis/:respId', autenticar, exigirPerfil('admin'), async (req,res)=>{
  await pool.query('DELETE FROM aluno_responsavel WHERE aluno_id=$1 AND responsavel_id=$2', [req.params.alunoId, req.params.respId]);
  res.json({ mensagem:'Vínculo removido' });
});

// --- TURMAS-DISCIPLINAS ---
app.get('/api/turmas-disciplinas/todos', autenticar, async (req,res)=>{
  if (req.usuario.perfil !== 'admin') return res.status(403).json({ erro:'Seu perfil não pode consultar todos os vínculos.' });
  const r = await pool.query(`
    SELECT td.id, td.turma_id, td.disciplina_id, td.professor_id,
           t.nome as turma, d.nome as disciplina, p.nome as professor
    FROM turmas_disciplinas td
    LEFT JOIN turmas t ON t.id=td.turma_id
    LEFT JOIN disciplinas d ON d.id=td.disciplina_id
    LEFT JOIN professores p ON p.id=td.professor_id
    UNION
    SELECT td.id, td.turma_id, td.disciplina_id, td.professor_id,
           t.nome as turma, d.nome as disciplina, p.nome as professor
    FROM turma_disciplina td
    LEFT JOIN turmas t ON t.id=td.turma_id
    LEFT JOIN disciplinas d ON d.id=td.disciplina_id
    LEFT JOIN professores p ON p.id=td.professor_id
    ORDER BY turma
  `);
  // Remove duplicatas por id+turma+disciplina+prof
  const map = new Map();
  for (const row of r.rows) { const k=`${row.turma_id}-${row.disciplina_id}-${row.professor_id}`; if(!map.has(k)) map.set(k,row); }
  res.json(Array.from(map.values()));
});
app.get('/api/turmas-disciplinas/minhas', autenticar, async (req,res)=>{
  // professor logado
  let profId = null;
  if (req.usuario.perfil === 'professor') {
    const pr = await pool.query('SELECT id FROM professores WHERE usuario_id=$1 OR id=$2', [req.usuario.id, req.usuario.professor_id||0]);
    profId = pr.rows[0]?.id;
  }
  if (!profId && req.usuario.perfil==='admin') {
    return res.json((await pool.query('SELECT td.id, td.turma_id, td.disciplina_id, td.professor_id, t.nome as turma, d.nome as disciplina FROM turmas_disciplinas td JOIN turmas t ON t.id=td.turma_id JOIN disciplinas d ON d.id=td.disciplina_id LIMIT 50')).rows);
  }
  if (!profId) return res.json([]);
  const r = await pool.query(`
    SELECT td.id, td.turma_id, td.disciplina_id, td.professor_id, t.nome as turma, d.nome as disciplina
    FROM turmas_disciplinas td
    JOIN turmas t ON t.id=td.turma_id AND (t.ativo IS NULL OR t.ativo=true)
    JOIN disciplinas d ON d.id=td.disciplina_id AND (d.ativo IS NULL OR d.ativo=true)
    WHERE td.professor_id=$1
    UNION
    SELECT td.id, td.turma_id, td.disciplina_id, td.professor_id, t.nome as turma, d.nome as disciplina
    FROM turma_disciplina td
    JOIN turmas t ON t.id=td.turma_id AND (t.ativo IS NULL OR t.ativo=true)
    JOIN disciplinas d ON d.id=td.disciplina_id AND (d.ativo IS NULL OR d.ativo=true)
    WHERE td.professor_id=$1
    ORDER BY turma, disciplina
  `, [profId]);
  const unique = new Map();
  for (const row of r.rows) {
    const key = `${row.turma_id}-${row.disciplina_id}-${row.professor_id}`;
    if (!unique.has(key)) unique.set(key, row);
  }
  res.json(Array.from(unique.values()));
});
app.post('/api/turmas-disciplinas', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const { turma_id, disciplina_id, professor_id } = req.body;
  try {
    await pool.query('INSERT INTO turmas_disciplinas (turma_id,disciplina_id,professor_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [turma_id,disciplina_id,professor_id]);
    await pool.query('INSERT INTO turma_disciplina (turma_id,disciplina_id,professor_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [turma_id,disciplina_id,professor_id]);
    res.json({ mensagem:'Vínculo salvo' });
  } catch(e){ res.status(400).json({ erro:e.message }); }
});
app.put('/api/turmas-disciplinas/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const { turma_id, disciplina_id, professor_id } = req.body;
  await pool.query('UPDATE turmas_disciplinas SET turma_id=$1,disciplina_id=$2,professor_id=$3 WHERE id=$4', [turma_id,disciplina_id,professor_id,req.params.id]);
  await pool.query('UPDATE turma_disciplina SET turma_id=$1,disciplina_id=$2,professor_id=$3 WHERE id=$4', [turma_id,disciplina_id,professor_id,req.params.id]);
  res.json({ mensagem:'Vínculo atualizado' });
});
app.delete('/api/turmas-disciplinas/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try {
    const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
    if (preservar) return res.status(400).json({ erro:'Vínculo não tem histórico próprio, use exclusão permanente' });
    await pool.query('DELETE FROM turmas_disciplinas WHERE id=$1', [req.params.id]);
    await pool.query('DELETE FROM turma_disciplina WHERE id=$1', [req.params.id]);
    res.json({ mensagem:'Vínculo excluído' });
  } catch(e){ res.status(400).json({ erro:e.message }); }
});

// --- MATRICULAS ---
app.get('/api/matriculas', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const r = await pool.query('SELECT m.id, m.aluno_id, m.turma_id, a.nome as aluno, t.nome as turma FROM matriculas m JOIN alunos a ON a.id=m.aluno_id JOIN turmas t ON t.id=m.turma_id WHERE m.ativo IS NULL OR m.ativo=true ORDER BY t.nome, a.nome');
  res.json(r.rows);
});
app.post('/api/matriculas', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const client = await pool.connect();
  try{
    const { aluno_id, turma_id } = req.body;
    if(!aluno_id || !turma_id) return res.status(400).json({ erro:'Selecione o aluno e a turma.' });
    await client.query('BEGIN');
    const ex = await client.query('SELECT id FROM matriculas WHERE aluno_id=$1 AND turma_id=$2 LIMIT 1', [aluno_id, turma_id]);
    if(ex.rows.length){
      await client.query('UPDATE matriculas SET ativo=false WHERE aluno_id=$1 AND id<>$2', [aluno_id, ex.rows[0].id]);
      await client.query('UPDATE matriculas SET ativo=true WHERE id=$1', [ex.rows[0].id]);
      await client.query('COMMIT');
      return res.json({ mensagem:'Matrícula reativada; as demais matrículas do aluno foram inativadas.' });
    }
    await client.query('UPDATE matriculas SET ativo=false WHERE aluno_id=$1 AND (ativo IS NULL OR ativo=true)', [aluno_id]);
    await client.query('INSERT INTO matriculas (aluno_id,turma_id,ativo) VALUES ($1,$2,true)', [aluno_id, turma_id]);
    await client.query('COMMIT');
    res.json({ mensagem:'Matrícula salva' });
  }catch(e){ await client.query('ROLLBACK'); console.error('[POST /matriculas]', e); res.status(400).json({ erro:e.message }); }
  finally { client.release(); }
});
app.put('/api/matriculas/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const client = await pool.connect();
  try {
    const { aluno_id, turma_id } = req.body;
    if(!aluno_id || !turma_id) return res.status(400).json({ erro:'Selecione o aluno e a turma.' });
    await client.query('BEGIN');
    await client.query(
      'UPDATE matriculas SET ativo=false WHERE aluno_id=$1 AND id<>$2 AND (ativo IS NULL OR ativo=true)',
      [aluno_id, req.params.id]
    );
    const updated = await client.query(
      'UPDATE matriculas SET aluno_id=$1,turma_id=$2,ativo=true WHERE id=$3 RETURNING id',
      [aluno_id, turma_id, req.params.id]
    );
    if (!updated.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ erro:'Matrícula não encontrada.' });
    }
    await client.query('COMMIT');
    res.json({ mensagem:'Matrícula atualizada; as demais matrículas do aluno foram inativadas.' });
  } catch(e) {
    await client.query('ROLLBACK');
    console.error('[PUT /matriculas/:id]', e);
    res.status(400).json({ erro:e.message });
  } finally { client.release(); }
});
app.delete('/api/matriculas/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
  if (preservar) { await pool.query('UPDATE matriculas SET ativo=false WHERE id=$1', [req.params.id]); return res.json({ mensagem:'Matrícula inativada, histórico preservado' }); }
  await pool.query('DELETE FROM matriculas WHERE id=$1', [req.params.id]);
  res.json({ mensagem:'Matrícula excluída permanentemente' });
});

// --- FALTAS / FREQUENCIA - FIX DISTINCT ---
app.get('/api/faltas/turmas/:id/alunos', autenticar, async (req,res)=>{
  const vinculoId = req.params.id;
  const data = req.query.data || new Date().toISOString().slice(0,10);
  try {
    const vinculo = await pool.query(`SELECT turma_id FROM turmas_disciplinas WHERE id=$1
      ${req.usuario.perfil === 'professor'
        ? 'AND professor_id=(SELECT id FROM professores WHERE usuario_id=$2)'
        : ''} UNION SELECT turma_id FROM turma_disciplina WHERE id=$1
      ${req.usuario.perfil === 'professor'
        ? 'AND professor_id=(SELECT id FROM professores WHERE usuario_id=$2)'
        : ''} LIMIT 1`, req.usuario.perfil === 'professor' ? [vinculoId, req.usuario.id] : [vinculoId]);
    if (!['admin', 'professor'].includes(req.usuario.perfil)) return res.status(403).json({ erro:'Seu perfil não pode consultar a chamada.' });
    if (!vinculo.rowCount) return res.status(404).json({ erro:'Vínculo de turma e disciplina não encontrado.' });
    const turmaId = vinculo.rows[0].turma_id;
    const r = await pool.query(`
      SELECT DISTINCT a.id, a.nome, a.matricula,
             (SELECT jsonb_agg(jsonb_build_object('id', r.id, 'nome', r.nome, 'telefone', r.telefone))
              FROM responsaveis r JOIN aluno_responsavel ar ON ar.responsavel_id=r.id WHERE ar.aluno_id=a.id) as responsaveis,
             f.presente, f.detalhes
      FROM alunos a
      JOIN matriculas m ON m.aluno_id=a.id AND m.turma_id=$2 AND (m.ativo IS NULL OR m.ativo=true)
      LEFT JOIN frequencias f ON f.aluno_id=a.id AND f.data=$3 AND f.turma_disciplina_id=$1
      WHERE a.ativo IS NULL OR a.ativo=true
      ORDER BY a.nome
    `, [vinculoId, turmaId, data]);
    // Normaliza presente
    const alunos = r.rows.map(row=>({ ...row, presente: row.presente !== false, detalhes: row.detalhes||'', responsaveis: row.responsaveis||[] }));
    res.json(alunos);
  } catch(e){
    console.error('Erro faltas:', e);
    res.status(500).json({ erro: e.message });
  }
});
app.post('/api/faltas/chamada', autenticar, async (req,res)=>{
  const { turma_disciplina_id, data, registros } = req.body;
  if (!turma_disciplina_id || !data || !Array.isArray(registros)) return res.status(400).json({ erro:'Dados inválidos' });
  if (!['admin', 'professor'].includes(req.usuario.perfil)) return res.status(403).json({ erro:'Seu perfil não pode registrar frequência.' });
  const vinculo = await pool.query(`SELECT turma_id, professor_id FROM turmas_disciplinas WHERE id=$1
    UNION SELECT turma_id, professor_id FROM turma_disciplina WHERE id=$1 LIMIT 1`, [turma_disciplina_id]);
  if (!vinculo.rowCount) return res.status(404).json({ erro:'Vínculo de turma e disciplina não encontrado.' });
  if (req.usuario.perfil === 'professor') {
    const teacher = await pool.query('SELECT id FROM professores WHERE usuario_id=$1 AND (ativo IS NULL OR ativo=true)', [req.usuario.id]);
    if (!teacher.rowCount || Number(teacher.rows[0].id) !== Number(vinculo.rows[0].professor_id)) return res.status(403).json({ erro:'Este vínculo não pertence ao professor.' });
  }
  const turmaId = vinculo.rows[0].turma_id;
  const studentIds = [...new Set(registros.map((reg) => Number(reg.aluno_id)).filter(Number.isInteger))];
  if (studentIds.length !== registros.length) return res.status(400).json({ erro:'A lista de alunos contém identificadores inválidos.' });
  const enrolled = await pool.query('SELECT aluno_id FROM matriculas WHERE turma_id=$1 AND aluno_id=ANY($2::int[]) AND (ativo IS NULL OR ativo=true)', [turmaId, studentIds]);
  if (enrolled.rowCount !== studentIds.length) return res.status(400).json({ erro:'A chamada contém aluno(s) não matriculado(s) nesta turma.' });
  let faltas=0;
  for (const reg of registros) {
    const presente = reg.presente !== false;
    if (!presente) faltas++;
    await pool.query(`INSERT INTO frequencias (turma_disciplina_id, aluno_id, data, presente, detalhes) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (turma_disciplina_id, aluno_id, data) DO UPDATE SET presente=$4, detalhes=$5`, [turma_disciplina_id, reg.aluno_id, data, presente, reg.detalhes||'']);
  }
  res.json({ mensagem:`Chamada salva para ${data}`, faltas });
});
app.get('/api/faltas/aluno/:id', autenticar, async (req,res)=>{
  if (!['admin', 'professor', 'responsavel'].includes(req.usuario.perfil)) return res.status(403).json({ erro:'Seu perfil não pode consultar frequência.' });
  if (req.usuario.perfil === 'responsavel') {
    const linked = await pool.query('SELECT 1 FROM aluno_responsavel ar JOIN responsaveis r ON r.id=ar.responsavel_id WHERE ar.aluno_id=$1 AND r.usuario_id=$2', [req.params.id, req.usuario.id]);
    if (!linked.rowCount) return res.status(403).json({ erro:'Este aluno não está vinculado ao seu acesso.' });
  } else if (req.usuario.perfil === 'professor') {
    const assigned = await pool.query(`SELECT 1 FROM frequencias f
      JOIN professores p ON p.usuario_id=$2
      JOIN (
        SELECT id, professor_id FROM turmas_disciplinas
        UNION
        SELECT id, professor_id FROM turma_disciplina
      ) td ON td.id=f.turma_disciplina_id AND td.professor_id=p.id
      WHERE f.aluno_id=$1 LIMIT 1`, [req.params.id, req.usuario.id]);
    if (!assigned.rowCount) return res.status(403).json({ erro:'Este aluno não pertence às turmas deste professor.' });
  }
  const r = await pool.query(`
    SELECT f.*, t.nome as turma, d.nome as disciplina, p.nome as professor
    FROM frequencias f
    LEFT JOIN (
      SELECT id, turma_id, disciplina_id, professor_id FROM turmas_disciplinas
      UNION
      SELECT id, turma_id, disciplina_id, professor_id FROM turma_disciplina
    ) td ON td.id=f.turma_disciplina_id
    LEFT JOIN turmas t ON t.id=td.turma_id
    LEFT JOIN disciplinas d ON d.id=td.disciplina_id
    LEFT JOIN professores p ON p.id=td.professor_id
    WHERE f.aluno_id=$1 AND f.presente=false
    ORDER BY f.data DESC
  `, [req.params.id]);
  const total = r.rows.length;
  // justificativas
  for (const row of r.rows) {
    const j = await pool.query('SELECT id, nome_original FROM justificativas WHERE falta_id=$1', [row.id]);
    row.justificativas = j.rows;
  }
  res.json({ total, faltas: r.rows });
});

// --- PERFIL FOTO ---
app.get('/api/perfil/foto', autenticar, async (req,res)=>{
  // Retorna placeholder - implementar storage real se quiser
  const u = await pool.query('SELECT foto_url FROM usuarios WHERE id=$1', [req.usuario.id]);
  if (!u.rows[0]?.foto_url) return res.status(404).json({ erro:'Foto do perfil não encontrada.' });
  res.json({ foto_url: u.rows[0].foto_url });
});
app.put('/api/perfil/foto', autenticar, async (req,res)=>{
  const { imagem } = req.body;
  await pool.query('UPDATE usuarios SET foto_url=$1 WHERE id=$2', ['foto_existe', req.usuario.id]);
  res.json({ mensagem:'Foto do perfil atualizada' });
});

// --- RESPONSAVEL / FILHOS ---
app.get('/api/responsavel/filhos', autenticar, exigirPerfil('responsavel'), async (req,res)=>{
  try {
    const r = await pool.query(`
      SELECT a.id, a.nome, a.matricula, a.data_nascimento, a.ativo, a.created_at,
             CASE WHEN a.foto_url LIKE 'data:image/%'
               THEN '/api/alunos/' || a.id || '/foto-arquivo'
               ELSE NULL
             END AS foto_url,
             enrollment.turma_id, t.nome AS turma, t.ano_letivo
      FROM alunos a
      LEFT JOIN LATERAL (
        SELECT m.turma_id
        FROM matriculas m
        WHERE m.aluno_id=a.id AND (m.ativo IS NULL OR m.ativo=true)
        ORDER BY m.id DESC
        LIMIT 1
      ) enrollment ON true
      LEFT JOIN turmas t ON t.id=enrollment.turma_id
      WHERE a.id IN (
        SELECT ar.aluno_id FROM aluno_responsavel ar
        JOIN responsaveis rr ON rr.id=ar.responsavel_id
        WHERE rr.usuario_id=$1 OR rr.id=(
          SELECT u.responsavel_id FROM usuarios u WHERE u.id=$1
        )
      )
      ORDER BY a.nome
    `, [req.usuario.id]);
    res.json(r.rows);
  } catch(e) {
    console.error('[GET /api/responsavel/filhos]', e);
    res.status(500).json({ erro:'Não foi possível carregar os alunos vinculados.' });
  }
});
app.get('/api/responsavel/professores', autenticar, exigirPerfil('responsavel'), async (req,res)=>{
  try {
    const teachers = await pool.query(`SELECT DISTINCT p.id, p.nome, p.telefone, t.nome AS turma, d.nome AS disciplina
      FROM professores p
      JOIN turmas_disciplinas td ON td.professor_id=p.id
      JOIN turmas t ON t.id=td.turma_id
      JOIN disciplinas d ON d.id=td.disciplina_id
      JOIN matriculas m ON m.turma_id=t.id AND (m.ativo IS NULL OR m.ativo=true)
      JOIN aluno_responsavel ar ON ar.aluno_id=m.aluno_id
      JOIN responsaveis r ON r.id=ar.responsavel_id
      WHERE r.usuario_id=$1 AND (p.ativo IS NULL OR p.ativo=true)
      ORDER BY t.nome, d.nome, p.nome`, [req.usuario.id]);
    res.json(teachers.rows);
  } catch(e) { console.error('[GET /responsavel/professores]', e); res.status(400).json({ erro:e.message }); }
});

// --- AVISOS ---
app.get('/api/avisos', autenticar, async (req,res)=>{
  try {
    let r;
    if (req.usuario.perfil === 'admin') {
      r = await pool.query('SELECT * FROM avisos WHERE ativo IS NULL OR ativo=true ORDER BY created_at DESC');
    } else if (req.usuario.perfil === 'responsavel') {
      r = await pool.query(`
        SELECT DISTINCT a.* FROM avisos a
        WHERE (a.ativo IS NULL OR a.ativo=true)
          AND (
            (a.turma_id IS NULL AND a.aluno_id IS NULL)
            OR EXISTS (
            SELECT 1 FROM matriculas m
            JOIN aluno_responsavel ar ON ar.aluno_id=m.aluno_id
            JOIN responsaveis r ON r.id=ar.responsavel_id
            WHERE m.turma_id=a.turma_id AND (m.ativo IS NULL OR m.ativo=true)
              AND (r.usuario_id=$1 OR r.id=(
                SELECT u.responsavel_id FROM usuarios u WHERE u.id=$1
              ))
            )
            OR EXISTS (
              SELECT 1 FROM aluno_responsavel ar
              JOIN responsaveis r ON r.id=ar.responsavel_id
              WHERE ar.aluno_id=a.aluno_id AND (r.usuario_id=$1 OR r.id=(
                SELECT u.responsavel_id FROM usuarios u WHERE u.id=$1
              ))
            )
          )
        ORDER BY a.created_at DESC
      `, [req.usuario.id]);
    } else if (req.usuario.perfil === 'professor') {
      r = await pool.query(`
        SELECT DISTINCT a.* FROM avisos a
        WHERE (a.ativo IS NULL OR a.ativo=true)
          AND (
            (a.turma_id IS NULL AND a.aluno_id IS NULL)
            OR EXISTS (
              SELECT 1 FROM (
                SELECT turma_id, professor_id FROM turmas_disciplinas
                UNION
                SELECT turma_id, professor_id FROM turma_disciplina
              ) td
              JOIN professores p ON p.id=td.professor_id
              WHERE td.turma_id=a.turma_id
                AND (p.usuario_id=$1 OR p.id=$2)
                AND (p.ativo IS NULL OR p.ativo=true)
            )
            OR EXISTS (
              SELECT 1 FROM matriculas m
              JOIN (
                SELECT turma_id, professor_id FROM turmas_disciplinas
                UNION
                SELECT turma_id, professor_id FROM turma_disciplina
              ) td ON td.turma_id=m.turma_id
              JOIN professores p ON p.id=td.professor_id
              WHERE m.aluno_id=a.aluno_id AND (m.ativo IS NULL OR m.ativo=true)
                AND (p.usuario_id=$1 OR p.id=$2)
                AND (p.ativo IS NULL OR p.ativo=true)
            )
          )
        ORDER BY a.created_at DESC
      `, [req.usuario.id, req.usuario.professor_id || 0]);
    } else {
      r = await pool.query(`SELECT * FROM avisos
        WHERE (ativo IS NULL OR ativo=true) AND turma_id IS NULL AND aluno_id IS NULL
        ORDER BY created_at DESC`);
    }
    res.json(r.rows);
  } catch(e) {
    console.error('[GET /api/avisos]', e);
    res.status(500).json({ erro:'Não foi possível carregar os avisos. Confira o schema do banco e os logs do serviço.' });
  }
});
app.delete('/api/avisos/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try {
    await pool.query('DELETE FROM avisos WHERE id=$1', [req.params.id]);
    res.json({ mensagem:'Aviso excluído permanentemente.' });
  } catch(e) { res.status(400).json({ erro:e.message }); }
});

// --- USUARIOS ---
app.delete('/api/usuarios/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try {
    const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
    const ret = await excluirComOpcaoHistorico({ tabela:'usuarios', id:req.params.id, preservarHistorico:preservar, tabelasDependentes:[] });
    res.json(ret);
  } catch(e){ res.status(400).json({ erro:e.message }); }
});

// JUSTIFICATIVAS
app.post('/api/faltas/:id/justificativas', autenticar, async (req,res)=>{
  try {
    if (req.usuario.perfil !== 'responsavel') return res.status(403).json({ erro:'Somente o responsável pode anexar documentos.' });
    const { nome_original, mime_type, dados_base64 } = req.body;
    if (!nome_original || !['application/pdf', 'image/jpeg', 'image/png'].includes(mime_type) || typeof dados_base64 !== 'string') {
      return res.status(400).json({ erro:'Envie um arquivo PDF, JPEG ou PNG válido.' });
    }
    const falta = await pool.query(`SELECT f.aluno_id FROM frequencias f
      JOIN aluno_responsavel ar ON ar.aluno_id=f.aluno_id
      JOIN responsaveis r ON r.id=ar.responsavel_id
      WHERE f.id=$1 AND f.presente=false AND r.usuario_id=$2`, [req.params.id, req.usuario.id]);
    if (!falta.rowCount) return res.status(404).json({ erro:'Falta não encontrada para um aluno vinculado a este responsável.' });
    const encoded = dados_base64.replace(/^data:[^,]+,/, '');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) return res.status(400).json({ erro:'O conteúdo do arquivo está inválido.' });
    const bytes = Buffer.from(encoded, 'base64');
    if (!bytes.length || bytes.length > 8 * 1024 * 1024) return res.status(400).json({ erro:'O documento deve ter até 8 MB.' });
    const saved = await pool.query(`INSERT INTO justificativas (falta_id, nome_original, mime_type, dados)
      VALUES ($1,$2,$3,$4) RETURNING id`, [req.params.id, nome_original, mime_type, bytes]);
    res.json({ mensagem:'Documento anexado para análise do professor.', id: saved.rows[0].id });
  } catch(e) { console.error('[POST /faltas/:id/justificativas]', e); res.status(400).json({ erro:e.message }); }
});
app.get('/api/justificativas/:id/arquivo', autenticar, async (req,res)=>{
  try {
    const result = await pool.query(`SELECT j.nome_original, j.mime_type, j.dados, f.aluno_id, td.professor_id
      FROM justificativas j JOIN frequencias f ON f.id=j.falta_id
      LEFT JOIN turmas_disciplinas td ON td.id=f.turma_disciplina_id WHERE j.id=$1`, [req.params.id]);
    const file = result.rows[0];
    if (!file?.dados) return res.status(404).json({ erro:'Documento não encontrado.' });
    if (req.usuario.perfil === 'responsavel') {
      const linked = await pool.query('SELECT 1 FROM aluno_responsavel ar JOIN responsaveis r ON r.id=ar.responsavel_id WHERE ar.aluno_id=$1 AND r.usuario_id=$2', [file.aluno_id, req.usuario.id]);
      if (!linked.rowCount) return res.status(403).json({ erro:'Este documento não pertence a um aluno vinculado ao seu acesso.' });
    } else if (req.usuario.perfil === 'professor') {
      const teacher = await pool.query('SELECT id FROM professores WHERE usuario_id=$1', [req.usuario.id]);
      if (!teacher.rowCount || Number(teacher.rows[0].id) !== Number(file.professor_id)) return res.status(403).json({ erro:'Este documento não pertence a uma turma deste professor.' });
    } else if (req.usuario.perfil !== 'admin') {
      return res.status(403).json({ erro:'Seu perfil não pode consultar este documento.' });
    }
    res.setHeader('Content-Type', file.mime_type);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(file.nome_original)}`);
    res.send(file.dados);
  } catch(e) { console.error('[GET /justificativas/:id/arquivo]', e); res.status(400).json({ erro:e.message }); }
});

(async ()=>{
  await garantirTabelasFrequencias();

// ===== PRODUÇÃO: FINALIZAÇÃO =====
// Professores: garante coluna whatsapp/telefone
// Avisos: editar + excluir permanente + listar destinatários p/ WhatsApp
app.post('/api/avisos', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try{
    const { titulo, mensagem, turma_id, aluno_id } = req.body;
    if(!titulo?.trim() || !mensagem?.trim()) return res.status(400).json({ erro:'Informe título e mensagem do aviso.' });
    const turmaId = turma_id === undefined || turma_id === null || turma_id === '' ? null : Number(turma_id);
    const alunoId = aluno_id === undefined || aluno_id === null || aluno_id === '' ? null : Number(aluno_id);
    if (turmaId !== null && alunoId !== null) return res.status(400).json({ erro:'O aviso deve ser direcionado a uma turma ou a um aluno, não aos dois.' });
    if (turmaId !== null && (!Number.isInteger(turmaId) || turmaId < 1)) return res.status(400).json({ erro:'Selecione uma turma válida.' });
    if (alunoId !== null && (!Number.isInteger(alunoId) || alunoId < 1)) return res.status(400).json({ erro:'Selecione um aluno válido.' });
    if (turmaId !== null && !(await pool.query('SELECT 1 FROM turmas WHERE id=$1', [turmaId])).rowCount) {
      return res.status(400).json({ erro:'A turma selecionada não existe.' });
    }
    if (alunoId !== null && !(await pool.query('SELECT 1 FROM alunos WHERE id=$1 AND (ativo IS NULL OR ativo=true)', [alunoId])).rowCount) {
      return res.status(400).json({ erro:'O aluno selecionado não existe ou está inativo.' });
    }
    const r = await pool.query(
      'INSERT INTO avisos (titulo,mensagem,turma_id,aluno_id,ativo) VALUES ($1,$2,$3,$4,true) RETURNING *',
      [titulo.trim(), mensagem.trim(), turmaId, alunoId]
    );
    res.json(r.rows[0]);
  }catch(e){ res.status(400).json({ erro:e.message }); }
});
app.put('/api/avisos/:id', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try{
    const { titulo, mensagem, turma_id, aluno_id } = req.body;
    if(!titulo?.trim() || !mensagem?.trim()) return res.status(400).json({ erro:'Informe título e mensagem do aviso.' });
    const turmaId = turma_id === undefined || turma_id === null || turma_id === '' ? null : Number(turma_id);
    const alunoId = aluno_id === undefined || aluno_id === null || aluno_id === '' ? null : Number(aluno_id);
    if (turmaId !== null && alunoId !== null) return res.status(400).json({ erro:'O aviso deve ser direcionado a uma turma ou a um aluno, não aos dois.' });
    if (turmaId !== null && (!Number.isInteger(turmaId) || turmaId < 1)) return res.status(400).json({ erro:'Selecione uma turma válida.' });
    if (alunoId !== null && (!Number.isInteger(alunoId) || alunoId < 1)) return res.status(400).json({ erro:'Selecione um aluno válido.' });
    if (turmaId !== null && !(await pool.query('SELECT 1 FROM turmas WHERE id=$1', [turmaId])).rowCount) {
      return res.status(400).json({ erro:'A turma selecionada não existe.' });
    }
    if (alunoId !== null && !(await pool.query('SELECT 1 FROM alunos WHERE id=$1 AND (ativo IS NULL OR ativo=true)', [alunoId])).rowCount) {
      return res.status(400).json({ erro:'O aluno selecionado não existe ou está inativo.' });
    }
    const updated = await pool.query(
      'UPDATE avisos SET titulo=$1, mensagem=$2, turma_id=$3, aluno_id=$4 WHERE id=$5 RETURNING id',
      [titulo.trim(), mensagem.trim(), turmaId, alunoId, req.params.id]
    );
    if (!updated.rowCount) return res.status(404).json({ erro:'Aviso não encontrado.' });
    res.json({ mensagem:'Aviso atualizado' });
  }catch(e){ res.status(400).json({ erro:e.message }); }
});
app.get('/api/avisos/destinatarios', autenticar, exigirPerfil('admin'), async (req,res)=>{
  try{
    const [teachers, responsibleRows, orphanResponsibleUsers] = await Promise.all([
      pool.query(`
        SELECT p.id, p.nome, p.telefone,
          ARRAY(
            SELECT DISTINCT classes.turma_id FROM (
              SELECT turma_id FROM turmas_disciplinas WHERE professor_id=p.id
              UNION
              SELECT turma_id FROM turma_disciplina WHERE professor_id=p.id
            ) classes ORDER BY classes.turma_id
          ) AS turmas_ids
        FROM professores p WHERE (p.ativo IS NULL OR p.ativo=true) ORDER BY p.nome
      `),
      pool.query(`
        SELECT r.id, r.nome, COALESCE(NULLIF(r.telefone, ''), u.telefone) AS telefone,
               STRING_AGG(DISTINCT a.nome, ', ' ORDER BY a.nome) AS alunos,
               ARRAY_REMOVE(ARRAY_AGG(DISTINCT m.turma_id), NULL) AS turmas_ids,
               ARRAY_REMOVE(ARRAY_AGG(DISTINCT a.id), NULL) AS alunos_ids
        FROM responsaveis r
        LEFT JOIN usuarios u ON u.id=r.usuario_id
        LEFT JOIN aluno_responsavel ar ON ar.responsavel_id=r.id
        LEFT JOIN alunos a ON a.id=ar.aluno_id
        LEFT JOIN matriculas m ON m.aluno_id=a.id AND (m.ativo IS NULL OR m.ativo=true)
        WHERE (r.ativo IS NULL OR r.ativo=true) AND (u.ativo IS NULL OR u.ativo=true)
        GROUP BY r.id, r.nome, r.telefone, u.telefone
      `),
      pool.query(`
        SELECT u.id, u.nome, u.telefone, NULL::text AS alunos,
               ARRAY[]::int[] AS turmas_ids, ARRAY[]::int[] AS alunos_ids
        FROM usuarios u
        WHERE u.perfil='responsavel' AND (u.ativo IS NULL OR u.ativo=true)
          AND NOT EXISTS (SELECT 1 FROM responsaveis r WHERE r.usuario_id=u.id)
      `)
    ]);
    const responsaveis = [...responsibleRows.rows, ...orphanResponsibleUsers.rows]
      .sort((left, right) => String(left.nome || '').localeCompare(String(right.nome || ''), 'pt-BR'));
    res.json({
      professores: teachers.rows,
      responsaveis
    });
  }catch(e){ console.error('[GET /avisos/destinatarios]', e); res.status(500).json({ erro:'Não foi possível carregar os destinatários do aviso.' }); }
});
app.post('/api/professor/avisos', autenticar, exigirPerfil('professor'), async (req,res)=>{
  try {
    const { titulo, mensagem, turma_id, disciplina_id, aluno_id } = req.body;
    const turmaId = Number(turma_id);
    const disciplinaId = Number(disciplina_id);
    const alunoId = aluno_id === undefined || aluno_id === null || aluno_id === '' ? null : Number(aluno_id);
    if (!titulo?.trim() || !mensagem?.trim()) {
      return res.status(400).json({ erro:'Informe o título e a mensagem do aviso.' });
    }
    if (titulo.trim().length > 200) return res.status(400).json({ erro:'O título pode ter no máximo 200 caracteres.' });
    if (!Number.isInteger(turmaId) || turmaId < 1 || !Number.isInteger(disciplinaId) || disciplinaId < 1) {
      return res.status(400).json({ erro:'Selecione uma turma e disciplina válidas.' });
    }
    if (alunoId !== null && (!Number.isInteger(alunoId) || alunoId < 1)) {
      return res.status(400).json({ erro:'Selecione um aluno válido.' });
    }
    const teacher = await pool.query(
      'SELECT id FROM professores WHERE usuario_id=$1 AND (ativo IS NULL OR ativo=true)',
      [req.usuario.id]
    );
    if (!teacher.rowCount) return res.status(403).json({ erro:'Não foi encontrado um cadastro ativo para este professor.' });
    const assignment = await pool.query(`
      SELECT 1 FROM turmas_disciplinas
      WHERE turma_id=$1 AND disciplina_id=$2 AND professor_id=$3
      UNION
      SELECT 1 FROM turma_disciplina
      WHERE turma_id=$1 AND disciplina_id=$2 AND professor_id=$3
      LIMIT 1
    `, [turmaId, disciplinaId, teacher.rows[0].id]);
    if (!assignment.rowCount) return res.status(403).json({ erro:'Esta turma e disciplina não estão vinculadas a este professor.' });
    if (alunoId !== null && !(await pool.query(`
      SELECT 1 FROM matriculas
      WHERE aluno_id=$1 AND turma_id=$2 AND (ativo IS NULL OR ativo=true)
    `, [alunoId, turmaId])).rowCount) {
      return res.status(400).json({ erro:'O aluno selecionado não está matriculado nesta turma.' });
    }
    const notice = await pool.query(`
      INSERT INTO avisos (titulo, mensagem, turma_id, aluno_id, ativo)
      VALUES ($1, $2, $3, $4, true)
      RETURNING *
    `, [titulo.trim(), mensagem.trim(), alunoId === null ? turmaId : null, alunoId]);
    res.status(201).json(notice.rows[0]);
  } catch(e) {
    console.error('[POST /api/professor/avisos]', e);
    res.status(500).json({ erro:'Não foi possível publicar o aviso no app.' });
  }
});
app.get('/api/professor/avisos/destinatarios', autenticar, exigirPerfil('professor'), async (req,res)=>{
  try{
    const turmaId = Number(req.query.turma_id);
    const disciplinaId = Number(req.query.disciplina_id);
    const alunoId = req.query.aluno_id ? Number(req.query.aluno_id) : null;
    if (!Number.isInteger(turmaId) || turmaId < 1 || !Number.isInteger(disciplinaId) || disciplinaId < 1 ||
        (alunoId !== null && (!Number.isInteger(alunoId) || alunoId < 1))) {
      return res.status(400).json({ erro:'Selecione uma turma, disciplina e aluno válidos.' });
    }
    const teacher = await pool.query(
      'SELECT id FROM professores WHERE usuario_id=$1 AND (ativo IS NULL OR ativo=true)',
      [req.usuario.id]
    );
    if (!teacher.rowCount) return res.status(403).json({ erro:'Não foi encontrado um cadastro ativo para este professor.' });
    const assignment = await pool.query(`
      SELECT 1 FROM turmas_disciplinas WHERE turma_id=$1 AND disciplina_id=$2 AND professor_id=$3
      UNION
      SELECT 1 FROM turma_disciplina WHERE turma_id=$1 AND disciplina_id=$2 AND professor_id=$3
      LIMIT 1
    `, [turmaId, disciplinaId, teacher.rows[0].id]);
    if (!assignment.rowCount) return res.status(403).json({ erro:'Esta turma e disciplina não estão vinculadas ao professor.' });
    const recipients = await pool.query(`
      SELECT DISTINCT a.nome AS aluno, r.nome, r.telefone
      FROM matriculas m
      JOIN alunos a ON a.id=m.aluno_id AND (a.ativo IS NULL OR a.ativo=true)
      JOIN aluno_responsavel ar ON ar.aluno_id=a.id
      JOIN responsaveis r ON r.id=ar.responsavel_id AND (r.ativo IS NULL OR r.ativo=true)
      WHERE m.turma_id=$1 AND (m.ativo IS NULL OR m.ativo=true)
        AND ($2::int IS NULL OR a.id=$2)
      ORDER BY a.nome, r.nome
    `, [turmaId, alunoId]);
    res.json(recipients.rows);
  }catch(e){ console.error('[GET /professor/avisos/destinatarios]', e); res.status(500).json({ erro:'Não foi possível carregar os responsáveis da turma.' }); }
});
app.get('/api/professor/turmas/:turmaId/alunos', autenticar, exigirPerfil('professor'), async (req,res)=>{
  try{
    const turmaId = Number(req.params.turmaId);
    const disciplinaId = Number(req.query.disciplina_id);
    if (!Number.isInteger(turmaId) || turmaId < 1 || !Number.isInteger(disciplinaId) || disciplinaId < 1) {
      return res.status(400).json({ erro:'Selecione uma turma e disciplina válidas.' });
    }
    const teacher = await pool.query(
      'SELECT id FROM professores WHERE usuario_id=$1 AND (ativo IS NULL OR ativo=true)',
      [req.usuario.id]
    );
    if (!teacher.rowCount) return res.status(403).json({ erro:'Não foi encontrado um cadastro ativo para este professor.' });
    const assignment = await pool.query(`
      SELECT 1 FROM turmas_disciplinas
      WHERE turma_id=$1 AND disciplina_id=$2 AND professor_id=$3
      UNION
      SELECT 1 FROM turma_disciplina
      WHERE turma_id=$1 AND disciplina_id=$2 AND professor_id=$3
      LIMIT 1
    `, [turmaId, disciplinaId, teacher.rows[0].id]);
    if (!assignment.rowCount) return res.status(403).json({ erro:'Esta turma e disciplina não estão vinculadas ao professor.' });
    const students = await pool.query(`
      SELECT DISTINCT a.id, a.nome, a.matricula
      FROM alunos a
      JOIN matriculas m ON m.aluno_id=a.id AND m.turma_id=$1
      WHERE (a.ativo IS NULL OR a.ativo=true) AND (m.ativo IS NULL OR m.ativo=true)
      ORDER BY a.nome
    `, [turmaId]);
    res.json(students.rows);
  }catch(e){ console.error('[GET /professor/turmas/:turmaId/alunos]', e); res.status(500).json({ erro:'Não foi possível carregar os alunos matriculados nesta turma.' }); }
});
// Notas: editar / excluir (professor) - histórico lê daqui automaticamente
app.post('/api/notas', autenticar, exigirPerfil('admin', 'professor'), async (req,res)=>{
  try{
    const { aluno_id, disciplina_id, turma_id, professor_id, bimestre, nota, observacao } = req.body;
    if(!aluno_id || !disciplina_id || !turma_id || ![1,2,3,4].includes(Number(bimestre)) || nota===undefined || nota===null || !Number.isFinite(Number(nota)) || Number(nota)<0 || Number(nota)>10) return res.status(400).json({ erro:'Informe turma, aluno, disciplina, bimestre válido e uma nota entre 0 e 10.' });
    let professorId = professor_id || null;
    if (req.usuario.perfil === 'professor') {
      const teacher = await pool.query('SELECT id FROM professores WHERE usuario_id=$1 AND (ativo IS NULL OR ativo=true)', [req.usuario.id]);
      professorId = teacher.rows[0]?.id;
      if (!professorId) return res.status(403).json({ erro:'Não foi encontrado um cadastro ativo para este professor.' });
      const assignment = await pool.query(`SELECT 1 FROM turmas_disciplinas
        WHERE turma_id=$1 AND disciplina_id=$2 AND professor_id=$3
        UNION SELECT 1 FROM turma_disciplina
        WHERE turma_id=$1 AND disciplina_id=$2 AND professor_id=$3 LIMIT 1`, [turma_id, disciplina_id, professorId]);
      if (!assignment.rowCount) return res.status(403).json({ erro:'A turma e a disciplina não estão vinculadas a este professor.' });
      const enrolled = await pool.query('SELECT 1 FROM matriculas WHERE aluno_id=$1 AND turma_id=$2 AND (ativo IS NULL OR ativo=true)', [aluno_id, turma_id]);
      if (!enrolled.rowCount) return res.status(400).json({ erro:'O aluno não está matriculado nesta turma.' });
    }
    // Evita duplicar: mesmo aluno + disciplina + turma + bimestre atualiza em vez de duplicar
    const ex = await pool.query('SELECT id FROM notas WHERE aluno_id=$1 AND disciplina_id=$2 AND COALESCE(turma_id,0)=COALESCE($3,0) AND COALESCE(bimestre,0)=COALESCE($4,0) LIMIT 1', [aluno_id, disciplina_id, turma_id||null, bimestre||null]);
    if(ex.rows.length){
      await pool.query('UPDATE notas SET nota=$1, observacao=$2, professor_id=$3 WHERE id=$4', [nota, observacao||null, professorId, ex.rows[0].id]);
      return res.json({ mensagem:'Nota atualizada (já existia para este bimestre).' });
    }
    const r = await pool.query('INSERT INTO notas (aluno_id, disciplina_id, turma_id, professor_id, bimestre, nota, observacao) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [aluno_id, disciplina_id, turma_id||null, professorId, bimestre||null, nota, observacao||null]);
    res.json(r.rows[0]);
  }catch(e){ console.error('[POST /notas]', e); res.status(400).json({ erro:e.message }); }
});
app.get('/api/notas', autenticar, async (req,res)=>{
  try{
    const { aluno_id, turma_id, disciplina_id } = req.query;
    let q = 'SELECT n.*, d.nome as disciplina, t.nome as turma, a.nome as aluno FROM notas n LEFT JOIN disciplinas d ON d.id=n.disciplina_id LEFT JOIN turmas t ON t.id=n.turma_id LEFT JOIN alunos a ON a.id=n.aluno_id WHERE 1=1';
    const vals=[]; let i=1;
    if(aluno_id){ q+=` AND n.aluno_id=$${i++}`; vals.push(aluno_id); }
    if(turma_id){ q+=` AND n.turma_id=$${i++}`; vals.push(turma_id); }
    if(disciplina_id){ q+=` AND n.disciplina_id=$${i++}`; vals.push(disciplina_id); }
    if (req.usuario.perfil === 'responsavel') {
      q += ` AND n.aluno_id IN (
        SELECT ar.aluno_id FROM aluno_responsavel ar
        JOIN responsaveis r ON r.id=ar.responsavel_id
        WHERE r.usuario_id=$${i} OR r.id=(
          SELECT u.responsavel_id FROM usuarios u WHERE u.id=$${i}
        )
      )`;
      vals.push(req.usuario.id);
      i++;
    } else if (req.usuario.perfil === 'professor') {
      q += ` AND n.professor_id=(SELECT id FROM professores WHERE usuario_id=$${i++} LIMIT 1)`;
      vals.push(req.usuario.id);
    } else if (req.usuario.perfil !== 'admin') {
      return res.status(403).json({ erro:'Seu perfil não pode consultar notas.' });
    }
    q+=' ORDER BY a.nome, d.nome, n.bimestre';
    const r = await pool.query(q, vals); res.json(r.rows);
  }catch(e){ res.status(400).json({ erro:e.message }); }
});
app.put('/api/notas/:id', autenticar, exigirPerfil('admin', 'professor'), async (req,res)=>{
  try{
    const { nota, bimestre, observacao } = req.body;
    if (!Number.isFinite(Number(nota)) || Number(nota)<0 || Number(nota)>10) return res.status(400).json({ erro:'A nota deve estar entre 0 e 10.' });
    if (![1,2,3,4].includes(Number(bimestre))) return res.status(400).json({ erro:'O bimestre deve estar entre 1 e 4.' });
    const values = [nota, bimestre||null, observacao||null, req.params.id];
    let ownership = '';
    if (req.usuario.perfil === 'professor') {
      ownership = ' AND professor_id=(SELECT id FROM professores WHERE usuario_id=$5 LIMIT 1)';
      values.push(req.usuario.id);
    }
    const updated = await pool.query(`UPDATE notas SET nota=$1, bimestre=$2, observacao=$3 WHERE id=$4${ownership} RETURNING id`, values);
    if (!updated.rowCount) return res.status(404).json({ erro:'Nota não encontrada ou não pertence a este professor.' });
    res.json({ mensagem:'Nota atualizada' });
  }catch(e){ res.status(400).json({ erro:e.message }); }
});
app.delete('/api/notas/:id', autenticar, exigirPerfil('admin', 'professor'), async (req,res)=>{
  try{
    const values = [req.params.id];
    const ownership = req.usuario.perfil === 'professor' ? ' AND professor_id=(SELECT id FROM professores WHERE usuario_id=$2 LIMIT 1)' : '';
    if (req.usuario.perfil === 'professor') values.push(req.usuario.id);
    const removed = await pool.query(`DELETE FROM notas WHERE id=$1${ownership} RETURNING id`, values);
    if (!removed.rowCount) return res.status(404).json({ erro:'Nota não encontrada ou não pertence a este professor.' });
    res.json({ mensagem:'Nota excluída permanentemente.' });
  }
  catch(e){ res.status(400).json({ erro:e.message }); }
});
// Histórico: lê direto das notas lançadas (sem tabela duplicada)
app.get('/api/historico/:alunoId', autenticar, async (req,res)=>{
  try{
    if (req.usuario.perfil === 'responsavel') {
      const linked = await pool.query('SELECT 1 FROM aluno_responsavel ar JOIN responsaveis r ON r.id=ar.responsavel_id WHERE ar.aluno_id=$1 AND r.usuario_id=$2', [req.params.alunoId, req.usuario.id]);
      if (!linked.rowCount) return res.status(403).json({ erro:'Este aluno não está vinculado ao seu acesso.' });
    } else if (req.usuario.perfil === 'professor') {
      const assigned = await pool.query(`SELECT 1 FROM matriculas m
        JOIN turmas_disciplinas td ON td.turma_id=m.turma_id
        JOIN professores p ON p.id=td.professor_id
        WHERE m.aluno_id=$1 AND p.usuario_id=$2 LIMIT 1`, [req.params.alunoId, req.usuario.id]);
      if (!assigned.rowCount) return res.status(403).json({ erro:'Este aluno não pertence às turmas deste professor.' });
    } else if (!['admin', 'professor'].includes(req.usuario.perfil)) {
      return res.status(403).json({ erro:'Seu perfil não pode consultar o histórico.' });
    }
    const r = await pool.query(`SELECT n.*, d.nome as disciplina, t.nome as turma FROM notas n LEFT JOIN disciplinas d ON d.id=n.disciplina_id LEFT JOIN turmas t ON t.id=n.turma_id WHERE n.aluno_id=$1 ORDER BY d.nome, n.bimestre`, [req.params.alunoId]);
    res.json(r.rows);
  }catch(e){ res.status(400).json({ erro:e.message }); }
});
// Frequência + justificativa: professor anota, responsável anexa documento (URL/base64)
app.put('/api/frequencias/:id/justificativa', autenticar, exigirPerfil('professor', 'admin'), async (req,res)=>{
  try{
    const { justificativa, anexo_url } = req.body;
    let ownership = '';
    const values = [justificativa||null, anexo_url||null, req.params.id];
    if (req.usuario.perfil === 'professor') {
      ownership = ` AND turma_disciplina_id IN (
        SELECT id FROM turmas_disciplinas WHERE professor_id=(SELECT id FROM professores WHERE usuario_id=$4)
        UNION SELECT id FROM turma_disciplina WHERE professor_id=(SELECT id FROM professores WHERE usuario_id=$4)
      )`;
      values.push(req.usuario.id);
    }
    const result = await pool.query(`UPDATE frequencias SET justificativa=$1, anexo_url=COALESCE($2, anexo_url) WHERE id=$3${ownership} RETURNING id`, values);
    if (!result.rowCount) return res.status(404).json({ erro:'Falta não encontrada ou fora das turmas deste professor.' });
    res.json({ mensagem:'Justificativa salva' });
  }catch(e){ res.status(400).json({ erro:e.message }); }
});
app.post('/api/frequencias/:id/anexo', autenticar, async (req,res)=>{
  try{
    if (req.usuario.perfil !== 'responsavel') return res.status(403).json({ erro:'Somente o responsável pode anexar documentos.' });
    const { anexo_url, descricao } = req.body;
    const updated = await pool.query(`UPDATE frequencias f SET anexo_url=$1, justificativa=COALESCE(f.justificativa,$2)
      WHERE f.id=$3 AND f.presente=false AND EXISTS (SELECT 1 FROM aluno_responsavel ar JOIN responsaveis r ON r.id=ar.responsavel_id
        WHERE ar.aluno_id=f.aluno_id AND r.usuario_id=$4) RETURNING f.id`,
      [anexo_url, descricao||'Documento anexado pelo responsável', req.params.id, req.usuario.id]);
    if (!updated.rowCount) return res.status(404).json({ erro:'Falta não encontrada para um aluno vinculado a este responsável.' });
    res.json({ mensagem:'Documento anexado' });
  }catch(e){ res.status(400).json({ erro:e.message }); }
});
// Responsável: trocar a própria senha (mínimo 8) + login = nome completo do filho
app.post('/api/responsaveis/trocar-senha', autenticar, exigirPerfil('responsavel'), async (req,res)=>{
  try{
    const { senha_atual, senha_nova } = req.body;
    if(!senha_nova || senha_nova.length < 8) return res.status(400).json({ erro:'A nova senha precisa ter pelo menos 8 caracteres.' });
    if (!senha_atual) return res.status(400).json({ erro:'Informe a senha atual.' });
    const u = await pool.query('SELECT id, senha, senha_hash FROM usuarios WHERE id=$1', [req.usuario.id]);
    if(!u.rows.length) return res.status(404).json({ erro:'Usuário não encontrado.' });
    const storedPassword = u.rows[0].senha_hash || u.rows[0].senha || '';
    const ok = storedPassword.startsWith('$2')
      ? await bcrypt.compare(senha_atual, storedPassword)
      : senha_atual === storedPassword;
    if(!ok) return res.status(400).json({ erro:'Senha atual incorreta.' });
    const hash = await bcrypt.hash(senha_nova, 10);
    await pool.query('UPDATE usuarios SET senha=$1, senha_hash=$1 WHERE id=$2', [hash, u.rows[0].id]);
    res.json({ mensagem:'Senha alterada com sucesso.' });
  }catch(e){ res.status(400).json({ erro:e.message }); }
});
// Professores: garantir telefone/whatsapp no PUT
app.use((req,res)=>res.status(404).json({ erro:`Rota ${req.method} ${req.path} não encontrada` }));
app.listen(PORT, ()=>console.log(`Santa Clara backend rodando na porta ${PORT}`));
})();
