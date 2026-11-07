
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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

async function garantirTabelasFrequencias() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS alunos (
        id SERIAL PRIMARY KEY, nome VARCHAR(150) NOT NULL, matricula VARCHAR(30) UNIQUE,
        data_nascimento DATE, foto_url TEXT, ativo BOOLEAN DEFAULT true, created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS turmas (
        id SERIAL PRIMARY KEY, nome VARCHAR(100) NOT NULL, ano_letivo INT DEFAULT 2026, ativo BOOLEAN DEFAULT true
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
        id SERIAL PRIMARY KEY, titulo VARCHAR(200), mensagem TEXT, turma_id INT, created_at TIMESTAMPTZ DEFAULT NOW(), ativo BOOLEAN DEFAULT true
      );
      CREATE TABLE IF NOT EXISTS justificativas (
        id SERIAL PRIMARY KEY, falta_id INT REFERENCES frequencias(id) ON DELETE CASCADE, nome_original VARCHAR(255), mime_type VARCHAR(100), dados BYTEA, created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
  } catch (e) { console.log('Aviso garantirTabelas:', e.message); }
}

function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ erro: 'Token não informado' });
  const token = auth.split(' ')[1];
  try { req.usuario = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ erro: 'Token inválido' }); }
}

// SAUDE
app.get('/api/saude', async (req,res)=>{
  try { await pool.query('SELECT 1'); res.json({status:'conectado', banco:'postgres'}); }
  catch(e){ res.json({status:'erro', erro:e.message}); }
});

// LOGIN - aceita hash e plain
app.post('/api/login', async (req,res)=>{
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ erro: 'Informe e-mail e senha' });
  try {
    const r = await pool.query('SELECT * FROM usuarios WHERE email=$1 LIMIT 1', [email.trim().toLowerCase()]);
    const usuario = r.rows[0];
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
    const token = jwt.sign({ id: usuario.id, perfil: usuario.perfil, email: usuario.email }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email, perfil: usuario.perfil } });
  } catch(e){ console.error(e); res.status(500).json({ erro: 'Erro interno no login' }); }
});

// --- TURMAS ---
app.get('/api/turmas', autenticar, async (req,res)=>{
  try {
    if (req.query.incluirInativas === 'true') { const r = await pool.query('SELECT * FROM turmas ORDER BY nome'); return res.json(r.rows); }
    const r = await pool.query('SELECT * FROM turmas WHERE ativo IS NULL OR ativo=true ORDER BY nome');
    res.json(r.rows);
  } catch(e){ console.error('GET turmas', e); res.json([]); }
});
app.post('/api/turmas/:id/reativar', autenticar, async (req,res)=>{
  try { await pool.query('UPDATE turmas SET ativo=true WHERE id=$1', [req.params.id]); res.json({ mensagem: 'Turma reativada com sucesso!' }); }
  catch(e){ res.status(400).json({ erro: e.message }); }
});
app.post('/api/turmas', autenticar, async (req,res)=>{
  const { nome, ano_letivo } = req.body;
  const r = await pool.query('INSERT INTO turmas (nome, ano_letivo) VALUES ($1,$2) RETURNING *', [nome, ano_letivo||2026]);
  res.json({ mensagem: 'Turma criada', turma: r.rows[0] });
});
app.put('/api/turmas/:id', autenticar, async (req,res)=>{
  const { nome, ano_letivo } = req.body;
  await pool.query('UPDATE turmas SET nome=$1, ano_letivo=$2 WHERE id=$3', [nome, ano_letivo, req.params.id]);
  res.json({ mensagem: 'Turma atualizada' });
});
app.delete('/api/turmas/:id', autenticar, async (req,res)=>{
  try {
    // DEFAULT = PRESERVAR. Só apaga de vez se vier explicitamente ?preservarHistorico=false
    // Isso protege contra frontend antigo que não manda o parâmetro
    const param = req.query.preservarHistorico;
    const preservar = param === undefined ? true : param === 'true';
    const id = req.params.id;
    console.log(`[DELETE turma ${id}] preservar=${preservar} param=${param}`);
    if (preservar) {
      await pool.query('UPDATE turmas SET ativo=false WHERE id=$1', [id]);
      return res.json({ mensagem: 'Turma inativada. Histórico preservado. Para reativar, use o botão Reativar.', preservado: true });
    }
    // Excluir TUDO - solta FKs antes
    try { await pool.query('UPDATE alunos SET turma_id=NULL WHERE turma_id=$1', [id]); } catch(e){ console.log('alunos turma_id:', e.message); }
    try { await pool.query('DELETE FROM matriculas WHERE turma_id=$1', [id]); } catch(e){}
    try { await pool.query('DELETE FROM turmas_disciplinas WHERE turma_id=$1', [id]); } catch(e){}
    try { await pool.query('DELETE FROM turma_disciplina WHERE turma_id=$1', [id]); } catch(e){}
    try { await pool.query('DELETE FROM avisos WHERE turma_id=$1', [id]); } catch(e){}
    await pool.query('DELETE FROM turmas WHERE id=$1', [id]);
    res.json({ mensagem: 'Turma e vínculos excluídos permanentemente. Alunos foram desvinculados mas não apagados.', preservado: false });
  } catch(e){
    console.error('Delete turma', e);
    if (e.message.includes('foreign key')) return res.status(400).json({ erro: 'Essa turma ainda tem alunos/faltas vinculados. Escolha Preservar histórico para inativar sem apagar.' });
    res.status(400).json({ erro: e.message });
  }
});

// --- DISCIPLINAS ---
app.get('/api/disciplinas', autenticar, async (req,res)=>{
  try {
    if (req.query.incluirInativas === 'true') { const r = await pool.query('SELECT * FROM disciplinas ORDER BY nome'); return res.json(r.rows); }
    const r = await pool.query('SELECT * FROM disciplinas WHERE ativo IS NULL OR ativo=true ORDER BY nome');
    res.json(r.rows);
  } catch(e){ console.error('GET disciplinas', e); res.json([]); }
});
app.post('/api/disciplinas/:id/reativar', autenticar, async (req,res)=>{
  try { await pool.query('UPDATE disciplinas SET ativo=true WHERE id=$1', [req.params.id]); res.json({ mensagem: 'Disciplina reativada!' }); }
  catch(e){ res.status(400).json({ erro: e.message }); }
});
app.post('/api/disciplinas', autenticar, async (req,res)=>{
  const r = await pool.query('INSERT INTO disciplinas (nome) VALUES ($1) RETURNING *', [req.body.nome]);
  res.json({ mensagem:'Disciplina criada', disciplina:r.rows[0] });
});
app.put('/api/disciplinas/:id', autenticar, async (req,res)=>{
  await pool.query('UPDATE disciplinas SET nome=$1 WHERE id=$2', [req.body.nome, req.params.id]);
  res.json({ mensagem:'Disciplina atualizada' });
});
app.delete('/api/disciplinas/:id', autenticar, async (req,res)=>{
  try {
    const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
    const ret = await excluirComOpcaoHistorico({ tabela:'disciplinas', id:req.params.id, preservarHistorico:preservar, tabelasDependentes:[{tabela:'turmas_disciplinas',coluna:'disciplina_id'},{tabela:'turma_disciplina',coluna:'disciplina_id'}] });
    res.json(ret);
  } catch(e){ res.status(400).json({ erro:e.message }); }
});

// --- PROFESSORES ---
app.get('/api/professores', autenticar, async (req,res)=>{
  try {
    if (req.query.incluirInativas === 'true') { const r = await pool.query('SELECT * FROM professores ORDER BY nome'); return res.json(r.rows); }
    const r = await pool.query('SELECT * FROM professores WHERE ativo IS NULL OR ativo=true ORDER BY nome');
    res.json(r.rows);
  } catch(e){
    try { const r2 = await pool.query('SELECT * FROM professores ORDER BY nome'); return res.json(r2.rows); }
    catch(e2){ console.error('GET professores', e2); res.json([]); }
  }
});
app.post('/api/professores/:id/reativar', autenticar, async (req,res)=>{
  try { await pool.query('UPDATE professores SET ativo=true WHERE id=$1', [req.params.id]); res.json({ mensagem: 'Professor reativado!' }); }
  catch(e){ res.status(400).json({ erro: e.message }); }
});
app.post('/api/professores', autenticar, async (req,res)=>{
  const { nome, email, senha } = req.body;
  const hash = senha ? await bcrypt.hash(senha,10) : null;
  const u = await pool.query('INSERT INTO usuarios (nome,email,senha,senha_hash,perfil,ativo) VALUES ($1,$2,$3,$4,$5,true) RETURNING id', [nome,email,hash||senha,hash||senha,'professor']);
  const p = await pool.query('INSERT INTO professores (nome,email,usuario_id) VALUES ($1,$2,$3) RETURNING *', [nome,email,u.rows[0].id]);
  await pool.query('UPDATE usuarios SET professor_id=$1 WHERE id=$2', [p.rows[0].id, u.rows[0].id]);
  res.json({ mensagem:'Professor criado' });
});
app.put('/api/professores/:id', autenticar, async (req,res)=>{
  const { nome, email, senha } = req.body;
  await pool.query('UPDATE professores SET nome=$1, email=$2 WHERE id=$3', [nome,email,req.params.id]);
  const prof = await pool.query('SELECT usuario_id FROM professores WHERE id=$1', [req.params.id]);
  if (prof.rows[0]?.usuario_id) {
    if (senha) {
      const hash = await bcrypt.hash(senha,10);
      await pool.query('UPDATE usuarios SET nome=$1,email=$2,senha=$3,senha_hash=$4 WHERE id=$5', [nome,email,hash,hash,prof.rows[0].usuario_id]);
    } else {
      await pool.query('UPDATE usuarios SET nome=$1,email=$2 WHERE id=$3', [nome,email,prof.rows[0].usuario_id]);
    }
  }
  res.json({ mensagem:'Professor atualizado' });
});
app.delete('/api/professores/:id', autenticar, async (req,res)=>{
  try {
    const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
    const ret = await excluirComOpcaoHistorico({ tabela:'professores', id:req.params.id, preservarHistorico:preservar, tabelasDependentes:[{tabela:'turmas_disciplinas',coluna:'professor_id'},{tabela:'turma_disciplina',coluna:'professor_id'}] });
    res.json(ret);
  } catch(e){ res.status(400).json({ erro:e.message }); }
});

// --- ALUNOS ---
app.get('/api/alunos', autenticar, async (req,res)=>{
  try {
    if (req.query.incluirInativas === 'true') { const r = await pool.query('SELECT * FROM alunos ORDER BY nome'); return res.json(r.rows); }
    const r = await pool.query('SELECT * FROM alunos WHERE ativo IS NULL OR ativo=true ORDER BY nome');
    res.json(r.rows);
  } catch(e){ console.error('GET alunos', e); res.json([]); }
});
app.post('/api/alunos/:id/reativar', autenticar, async (req,res)=>{ try { await pool.query('UPDATE alunos SET ativo=true WHERE id=$1', [req.params.id]); res.json({ mensagem: 'Aluno reativado!' }); } catch(e){ res.status(400).json({ erro: e.message }); } });
app.post('/api/alunos', autenticar, async (req,res)=>{
  const { nome, matricula, data_nascimento } = req.body;
  const r = await pool.query('INSERT INTO alunos (nome,matricula,data_nascimento) VALUES ($1,$2,$3) RETURNING *', [nome,matricula, data_nascimento||null]);
  res.json({ mensagem:'Aluno cadastrado e salvo no servidor', aluno:r.rows[0] });
});
app.put('/api/alunos/:id', autenticar, async (req,res)=>{
  const { nome, matricula, data_nascimento } = req.body;
  await pool.query('UPDATE alunos SET nome=$1,matricula=$2,data_nascimento=$3 WHERE id=$4', [nome,matricula,data_nascimento||null,req.params.id]);
  res.json({ mensagem:'Aluno atualizado' });
});
app.put('/api/alunos/:id/foto', autenticar, async (req,res)=>{
  const { imagem } = req.body;
  // Salva como base64 ou url - simplificado salva url placeholder
  await pool.query('UPDATE alunos SET foto_url=$1 WHERE id=$2', ['foto_existe', req.params.id]);
  res.json({ mensagem:'Foto salva', foto_url:`/api/alunos/${req.params.id}/foto-arquivo` });
});
app.get('/api/alunos/:id/foto-arquivo', autenticar, async (req,res)=>{
  res.status(404).json({ erro:'Implementar storage de foto se necessário' });
});
app.delete('/api/alunos/:id', autenticar, async (req,res)=>{
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
    await pool.query('DELETE FROM alunos WHERE id=$1', [req.params.id]);
    res.json({ mensagem:'Aluno excluído permanentemente com histórico' });
  } catch(e){ res.status(400).json({ erro:e.message }); }
});

// --- RESPONSAVEIS ---
app.get('/api/responsaveis', autenticar, async (req,res)=>{
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
app.get('/api/alunos/:id/responsaveis', autenticar, async (req,res)=>{
  const r = await pool.query(`SELECT r.*, r.parentesco, u.email as usuario_email, r.telefone FROM responsaveis r JOIN aluno_responsavel ar ON ar.responsavel_id=r.id LEFT JOIN usuarios u ON u.id=r.usuario_id WHERE ar.aluno_id=$1 AND (r.ativo IS NULL OR r.ativo=true)`, [req.params.id]);
  res.json(r.rows);
});
app.post('/api/responsaveis', autenticar, async (req,res)=>{
  try{
  const { nome, email, senha, telefone, parentesco, alunos_ids } = req.body;
  if(!nome?.trim()) return res.status(400).json({ erro:'Informe o nome do responsável.' });
  if(!email?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) return res.status(400).json({ erro:'Informe um e-mail válido.' });
  if(!senha || senha.length < 8) return res.status(400).json({ erro:'A senha precisa ter pelo menos 8 caracteres.' });
  // Se o e-mail já existe MAS está inativo (foi excluído com histórico), REATIVA em vez de travar.
  // É esse o seu caso: você excluiu todos, mas o usuário ficou com ativo=false.
  const dup = await pool.query('SELECT id, ativo, responsavel_id FROM usuarios WHERE LOWER(email)=LOWER($1) LIMIT 1', [email.trim()]);
  // ÓRFÃO: usuário ativo mas sem linha em responsaveis (sobra do bug do Excluir TUDO) -> NÃO trava, cria a linha que falta
  if(dup.rows.length && dup.rows[0].ativo !== false){
    const respExiste = await pool.query('SELECT id FROM responsaveis WHERE usuario_id=$1 LIMIT 1', [dup.rows[0].id]);
    if(!respExiste.rows.length){
      const uid = dup.rows[0].id;
      const nr = await pool.query('INSERT INTO responsaveis (nome,telefone,usuario_id,parentesco,ativo) VALUES ($1,$2,$3,$4,true) RETURNING id', [nome.trim(), telefone.trim(), uid, parentesco||'Responsável']);
      await pool.query('UPDATE usuarios SET nome=$1, senha=$2, senha_hash=$2, telefone=$3, responsavel_id=$4 WHERE id=$5', [nome.trim(), hash, telefone.trim(), nr.rows[0].id, uid]);
      for (const aluno_id of (alunos_ids||[])) {
        const vex = await pool.query('SELECT id FROM aluno_responsavel WHERE aluno_id=$1 AND responsavel_id=$2 LIMIT 1', [aluno_id, nr.rows[0].id]);
        if(!vex.rows.length) await pool.query('INSERT INTO aluno_responsavel (aluno_id,responsavel_id) VALUES ($1,$2)', [aluno_id, nr.rows[0].id]);
      }
      return res.json({ mensagem:'Responsável recuperado (usuário órfão) e vinculado.' });
    }
    return res.status(400).json({ erro:'Este e-mail já está cadastrado e ativo. Use outro e-mail ou edite o responsável existente em VÍNCULOS > Responsáveis já cadastrados.' });
  }
  const hash = await bcrypt.hash(senha,10);
  // Reaproveita o usuário inativo: atualiza nome/senha/telefone e reativa
  if(dup.rows.length && dup.rows[0].ativo === false){
    const uid = dup.rows[0].id;
    await pool.query('UPDATE usuarios SET nome=$1, senha=$2, senha_hash=$2, telefone=$3, ativo=true WHERE id=$4', [nome.trim(), hash, telefone.trim(), uid]);
    // Reativa o responsável ligado a ele, se existir, ou cria um novo
    let respId = dup.rows[0].responsavel_id;
    if(respId){
      await pool.query('UPDATE responsaveis SET nome=$1, telefone=$2, ativo=true WHERE id=$3', [nome.trim(), telefone.trim(), respId]);
    } else {
      const nr = await pool.query('INSERT INTO responsaveis (nome,telefone,usuario_id,parentesco,ativo) VALUES ($1,$2,$3,$4,true) RETURNING id', [nome.trim(), telefone.trim(), uid, parentesco||'Responsável']);
      respId = nr.rows[0].id;
      await pool.query('UPDATE usuarios SET responsavel_id=$1 WHERE id=$2', [respId, uid]);
    }
    for (const aluno_id of (alunos_ids||[])) {
      const vex = await pool.query('SELECT id FROM aluno_responsavel WHERE aluno_id=$1 AND responsavel_id=$2 LIMIT 1', [aluno_id, respId]);
      if(!vex.rows.length) await pool.query('INSERT INTO aluno_responsavel (aluno_id,responsavel_id) VALUES ($1,$2)', [aluno_id, respId]);
    }
    return res.json({ mensagem:'Responsável reativado e vinculado (e-mail reaproveitado).' });
  }
  const u = await pool.query('INSERT INTO usuarios (nome,email,senha,senha_hash,perfil,telefone,ativo) VALUES ($1,$2,$3,$4,$5,$6,true) RETURNING id', [nome.trim(),email.trim(),hash,hash,'responsavel',telefone.trim()]);
  const resp = await pool.query('INSERT INTO responsaveis (nome,telefone,usuario_id,parentesco) VALUES ($1,$2,$3,$4) RETURNING *', [nome.trim(),telefone.trim(),u.rows[0].id,parentesco||'Responsável']);
  await pool.query('UPDATE usuarios SET responsavel_id=$1 WHERE id=$2', [resp.rows[0].id, u.rows[0].id]);
  for (const aluno_id of (alunos_ids||[])) {
    await pool.query('INSERT INTO aluno_responsavel (aluno_id,responsavel_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [aluno_id, resp.rows[0].id]);
  }
  res.json({ mensagem:'Responsável criado e vinculado' });
  }catch(e){ console.error('[POST /responsaveis]', e); res.status(400).json({ erro:e.message }); }
});
app.put('/api/responsaveis/:id', autenticar, async (req,res)=>{
  try{
    const { nome, email, telefone, alunos_ids } = req.body;
    // responsaveis NÃO tem email - email fica só em usuarios
    await pool.query('UPDATE responsaveis SET nome=$1,telefone=$2 WHERE id=$3', [nome,telefone,req.params.id]);
    const r = await pool.query('SELECT usuario_id FROM responsaveis WHERE id=$1', [req.params.id]);
    if (r.rows[0]?.usuario_id) await pool.query('UPDATE usuarios SET nome=$1,email=$2,telefone=$3 WHERE id=$4', [nome,email,telefone,r.rows[0].usuario_id]);
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
app.put('/api/alunos/:alunoId/responsaveis/:respId', autenticar, async (req,res)=>{
  try{
    // parentesco NÃO existe em aluno_responsavel, só em responsaveis
    await pool.query('UPDATE responsaveis SET parentesco=$1 WHERE id=$2', [req.body.parentesco||'Responsável', req.params.respId]);
    res.json({ mensagem:'Vínculo atualizado' });
  }catch(e){ console.error('[PUT aluno-responsavel]', e); res.status(400).json({ erro:e.message }); }
});
app.delete('/api/responsaveis/:id', autenticar, async (req,res)=>{
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
app.delete('/api/alunos/:alunoId/responsaveis/:respId', autenticar, async (req,res)=>{
  await pool.query('DELETE FROM aluno_responsavel WHERE aluno_id=$1 AND responsavel_id=$2', [req.params.alunoId, req.params.respId]);
  res.json({ mensagem:'Vínculo removido' });
});

// --- TURMAS-DISCIPLINAS ---
app.get('/api/turmas-disciplinas/todos', autenticar, async (req,res)=>{
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
    return res.json((await pool.query('SELECT td.id, t.nome as turma, d.nome as disciplina FROM turmas_disciplinas td JOIN turmas t ON t.id=td.turma_id JOIN disciplinas d ON d.id=td.disciplina_id LIMIT 50')).rows);
  }
  const r = await pool.query('SELECT td.id, t.nome as turma, d.nome as disciplina FROM turmas_disciplinas td JOIN turmas t ON t.id=td.turma_id JOIN disciplinas d ON d.id=td.disciplina_id WHERE td.professor_id=$1 UNION SELECT td.id, t.nome as turma, d.nome as disciplina FROM turma_disciplina td JOIN turmas t ON t.id=td.turma_id JOIN disciplinas d ON d.id=td.disciplina_id WHERE td.professor_id=$1', [profId]);
  res.json(r.rows);
});
app.post('/api/turmas-disciplinas', autenticar, async (req,res)=>{
  const { turma_id, disciplina_id, professor_id } = req.body;
  try {
    await pool.query('INSERT INTO turmas_disciplinas (turma_id,disciplina_id,professor_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [turma_id,disciplina_id,professor_id]);
    await pool.query('INSERT INTO turma_disciplina (turma_id,disciplina_id,professor_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [turma_id,disciplina_id,professor_id]);
    res.json({ mensagem:'Vínculo salvo' });
  } catch(e){ res.status(400).json({ erro:e.message }); }
});
app.put('/api/turmas-disciplinas/:id', autenticar, async (req,res)=>{
  const { turma_id, disciplina_id, professor_id } = req.body;
  await pool.query('UPDATE turmas_disciplinas SET turma_id=$1,disciplina_id=$2,professor_id=$3 WHERE id=$4', [turma_id,disciplina_id,professor_id,req.params.id]);
  await pool.query('UPDATE turma_disciplina SET turma_id=$1,disciplina_id=$2,professor_id=$3 WHERE id=$4', [turma_id,disciplina_id,professor_id,req.params.id]);
  res.json({ mensagem:'Vínculo atualizado' });
});
app.delete('/api/turmas-disciplinas/:id', autenticar, async (req,res)=>{
  try {
    const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
    if (preservar) return res.status(400).json({ erro:'Vínculo não tem histórico próprio, use exclusão permanente' });
    await pool.query('DELETE FROM turmas_disciplinas WHERE id=$1', [req.params.id]);
    await pool.query('DELETE FROM turma_disciplina WHERE id=$1', [req.params.id]);
    res.json({ mensagem:'Vínculo excluído' });
  } catch(e){ res.status(400).json({ erro:e.message }); }
});

// --- MATRICULAS ---
app.get('/api/matriculas', autenticar, async (req,res)=>{
  const r = await pool.query('SELECT m.id, m.aluno_id, m.turma_id, a.nome as aluno, t.nome as turma FROM matriculas m JOIN alunos a ON a.id=m.aluno_id JOIN turmas t ON t.id=m.turma_id WHERE m.ativo IS NULL OR m.ativo=true ORDER BY t.nome, a.nome');
  res.json(r.rows);
});
app.post('/api/matriculas', autenticar, async (req,res)=>{
  try{
    const { aluno_id, turma_id } = req.body;
    if(!aluno_id || !turma_id) return res.status(400).json({ erro:'Selecione o aluno e a turma.' });
    const ex = await pool.query('SELECT id FROM matriculas WHERE aluno_id=$1 AND turma_id=$2 LIMIT 1', [aluno_id, turma_id]);
    if(ex.rows.length){ await pool.query('UPDATE matriculas SET ativo=true WHERE id=$1', [ex.rows[0].id]); return res.json({ mensagem:'Aluno já estava matriculado - matrícula reativada.' }); }
    await pool.query('INSERT INTO matriculas (aluno_id,turma_id,ativo) VALUES ($1,$2,true)', [aluno_id, turma_id]);
    res.json({ mensagem:'Matrícula salva' });
  }catch(e){ console.error('[POST /matriculas]', e); res.status(400).json({ erro:e.message }); }
});
app.put('/api/matriculas/:id', autenticar, async (req,res)=>{
  await pool.query('UPDATE matriculas SET aluno_id=$1,turma_id=$2 WHERE id=$3', [req.body.aluno_id, req.body.turma_id, req.params.id]);
  res.json({ mensagem:'Matrícula atualizada' });
});
app.delete('/api/matriculas/:id', autenticar, async (req,res)=>{
  const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
  if (preservar) { await pool.query('UPDATE matriculas SET ativo=false WHERE id=$1', [req.params.id]); return res.json({ mensagem:'Matrícula inativada, histórico preservado' }); }
  await pool.query('DELETE FROM matriculas WHERE id=$1', [req.params.id]);
  res.json({ mensagem:'Matrícula excluída permanentemente' });
});

// --- FALTAS / FREQUENCIA - FIX DISTINCT ---
app.get('/api/faltas/turmas/:id/alunos', autenticar, async (req,res)=>{
  const turmaId = req.params.id;
  const data = req.query.data || new Date().toISOString().slice(0,10);
  try {
    // FIX DISTINCT - não usar JOIN com turmas_disciplinas que duplica
    const r = await pool.query(`
      SELECT DISTINCT a.id, a.nome, a.matricula,
             (SELECT json_agg(json_build_object('id', r.id, 'nome', r.nome, 'telefone', r.telefone)
              ) FROM responsaveis r JOIN aluno_responsavel ar ON ar.responsavel_id=r.id WHERE ar.aluno_id=a.id) as responsaveis,
             f.presente, f.detalhes
      FROM alunos a
      JOIN matriculas m ON m.aluno_id=a.id AND m.turma_id=$1 AND (m.ativo IS NULL OR m.ativo=true)
      LEFT JOIN frequencias f ON f.aluno_id=a.id AND f.data=$2 AND f.turma_disciplina_id=$1
      WHERE a.ativo IS NULL OR a.ativo=true
      ORDER BY a.nome
    `, [turmaId, data]);
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
  let faltas=0;
  for (const reg of registros) {
    const presente = reg.presente !== false;
    if (!presente) faltas++;
    await pool.query(`INSERT INTO frequencias (turma_disciplina_id, aluno_id, data, presente, detalhes) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (turma_disciplina_id, aluno_id, data) DO UPDATE SET presente=$4, detalhes=$5`, [turma_disciplina_id, reg.aluno_id, data, presente, reg.detalhes||'']);
  }
  res.json({ mensagem:`Chamada salva para ${data}`, faltas });
});
app.get('/api/faltas/aluno/:id', autenticar, async (req,res)=>{
  const r = await pool.query(`SELECT f.*, t.nome as turma, d.nome as disciplina, p.nome as professor FROM frequencias f LEFT JOIN turmas_disciplinas td ON td.id=f.turma_disciplina_id LEFT JOIN turmas t ON t.id=td.turma_id LEFT JOIN disciplinas d ON d.id=td.disciplina_id LEFT JOIN professores p ON p.id=td.professor_id WHERE f.aluno_id=$1 AND f.presente=false ORDER BY f.data DESC`, [req.params.id]);
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
app.get('/api/responsavel/filhos', autenticar, async (req,res)=>{
  const r = await pool.query(`SELECT a.*, t.nome as turma FROM alunos a LEFT JOIN matriculas m ON m.aluno_id=a.id AND (m.ativo IS NULL OR m.ativo=true) LEFT JOIN turmas t ON t.id=m.turma_id WHERE a.id IN (SELECT ar.aluno_id FROM aluno_responsavel ar JOIN responsaveis rr ON rr.id=ar.responsavel_id WHERE rr.usuario_id=$1)`, [req.usuario.id]);
  res.json(r.rows);
});

// --- AVISOS ---
app.get('/api/avisos', autenticar, async (req,res)=>{
  const r = await pool.query('SELECT * FROM avisos WHERE ativo IS NULL OR ativo=true ORDER BY created_at DESC');
  res.json(r.rows);
});
app.delete('/api/avisos/:id', autenticar, async (req,res)=>{
  const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
  if (preservar) { await pool.query('UPDATE avisos SET ativo=false WHERE id=$1', [req.params.id]); return res.json({ mensagem:'Aviso inativado, histórico preservado' }); }
  await pool.query('DELETE FROM avisos WHERE id=$1', [req.params.id]);
  res.json({ mensagem:'Aviso excluído' });
});

// --- USUARIOS ---
app.delete('/api/usuarios/:id', autenticar, async (req,res)=>{
  try {
    const preservar = req.query.preservarHistorico === undefined ? true : req.query.preservarHistorico === 'true';
    const ret = await excluirComOpcaoHistorico({ tabela:'usuarios', id:req.params.id, preservarHistorico:preservar, tabelasDependentes:[] });
    res.json(ret);
  } catch(e){ res.status(400).json({ erro:e.message }); }
});

// JUSTIFICATIVAS
app.post('/api/faltas/:id/justificativas', autenticar, async (req,res)=>{
  // Simplificado - salva sem arquivo real
  await pool.query('INSERT INTO justificativas (falta_id, nome_original, mime_type) VALUES ($1,$2,$3)', [req.params.id, decodeURIComponent(req.headers['x-file-name']||'justificativa.pdf'), 'application/pdf']);
  res.json({ mensagem:'Justificativa enviada' });
});
app.get('/api/justificativas/:id/arquivo', autenticar, async (req,res)=>{
  res.status(404).json({ erro:'Arquivo não armazenado neste modo simplificado' });
});

app.use((req,res)=>res.status(404).json({ erro:`Rota ${req.method} ${req.path} não encontrada` }));

(async ()=>{
  await garantirTabelasFrequencias();
  app.listen(PORT, ()=>console.log(`Santa Clara backend rodando na porta ${PORT}`));
})();
