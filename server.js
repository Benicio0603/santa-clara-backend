require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET não configurado no arquivo .env');
}

const pool = new Pool(
    process.env.DATABASE_URL
        ? { connectionString: process.env.DATABASE_URL }
        : {
            host: process.env.DB_HOST,
            port: Number(process.env.DB_PORT || 5432),
            database: process.env.DB_NAME,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD
        }
);

async function autenticarToken(req, res, next) {
    const cabecalho = req.headers.authorization;

    if (!cabecalho || !cabecalho.startsWith('Bearer ')) {
        return res.status(401).json({
            erro: 'Acesso negado. Faça login para continuar.'
        });
    }

    const token = cabecalho.split(' ')[1];

    try {
        const dados = jwt.verify(token, process.env.JWT_SECRET);
        const usuarioId = Number(dados.sub);

        if (!Number.isSafeInteger(usuarioId) || usuarioId <= 0) {
            return res.status(401).json({
                erro: 'Token inválido. Faça login novamente.'
            });
        }

        const resultado = await pool.query(
            `SELECT id, perfil, professor_id, ativo
             FROM usuarios
             WHERE id = $1`,
            [usuarioId]
        );

        const usuario = resultado.rows[0];

        if (!usuario || !usuario.ativo) {
            return res.status(401).json({
                erro: 'Usuário inexistente ou inativo. Faça login novamente.'
            });
        }

        if (
            !['admin', 'professor', 'responsavel'].includes(usuario.perfil) ||
            (
                usuario.perfil === 'professor' &&
                !usuario.professor_id
            )
        ) {
            return res.status(403).json({
                erro: 'Usuário sem perfil ou vínculo autorizado.'
            });
        }

        req.usuario = {
            sub: String(usuario.id),
            perfil: usuario.perfil,
            professor_id: usuario.professor_id
                ? String(usuario.professor_id)
                : null
        };

        return next();
    } catch (erro) {
        if (erro.name === 'JsonWebTokenError' ||
            erro.name === 'TokenExpiredError') {
            return res.status(401).json({
                erro: 'Token inválido ou expirado. Faça login novamente.'
            });
        }

        console.error('Erro ao validar usuário:', erro.message);

        return res.status(500).json({
            erro: 'Não foi possível validar o usuário.'
        });
    }
}

function autorizar(...perfisPermitidos) {
  return (req, res, next) => {
    if (!perfisPermitidos.includes(req.usuario.perfil)) {
      return res.status(403).json({ erro: 'Sem permissão para esta ação.' });
    }
    next();
  };
}

function dataIsoValida(data) {
  if (typeof data !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(data)) return false;
  const parsed = new Date(`${data}T00:00:00.000Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === data;
}


app.use(cors());
app.use(express.json({ limit: '2mb' }));

app.use('/uploads/alunos', (req, res) => res.status(404).end());
app.use('/uploads/perfis', (req, res) => res.status(404).end());
app.use('/uploads/justificativas', (req, res) => res.status(404).end());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, '..', 'frontend', 'index.html');
    if (fs.existsSync(indexPath)) {
        return res.sendFile(indexPath, (err) => {
          if(err){
            console.error('Erro ao enviar index.html:', err.message);
            return res.status(500).json({ erro: 'Erro ao carregar frontend', detalhe: err.message, path: indexPath });
          }
        });
    }
    return res.json({ status: 'online', mensagem: 'O frontend é publicado separadamente no Netlify.' });
});

app.get('/api/saude', async (req, res) => {
    try {
        const resultado = await pool.query(
            'SELECT NOW() AS horario, current_database() AS banco'
        );
        res.json({
            status: 'conectado',
            banco: resultado.rows[0].banco,
            horario: resultado.rows[0].horario
        });
    } catch (erro) {
        console.error('Erro ao conectar ao PostgreSQL:', erro.message);
        res.status(500).json({
            erro: 'Não foi possível conectar ao banco de dados.'
        });
    }
});

// LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const { email, senha } = req.body || {};
        if (
            typeof email !== 'string' ||
            typeof senha !== 'string' ||
            !email.trim() ||
            !senha
        ) {
            return res.status(400).json({ erro: 'Informe o e-mail e a senha.' });
        }
        const resultado = await pool.query(
            `SELECT id, nome, email, senha_hash, perfil, ativo, professor_id
             FROM usuarios WHERE email = $1`,
            [email.trim().toLowerCase()]
        );
        const usuario = resultado.rows[0];
        if (!usuario || !usuario.ativo) {
            return res.status(401).json({ erro: 'E-mail ou senha inválidos.' });
        }

        const senhaArmazenada = usuario.senha_hash;
        let senhaValida = false;
        if (typeof senhaArmazenada === 'string' && /^\$2[aby]\$\d{2}\$/.test(senhaArmazenada)) {
            senhaValida = await bcrypt.compare(senha, senhaArmazenada);
        } else if (typeof senhaArmazenada === 'string' && senha === senhaArmazenada) {
            const novoHash = await bcrypt.hash(senha, 10);
            const atualizacao = await pool.query(
                'UPDATE usuarios SET senha_hash = $1 WHERE id = $2 AND senha_hash = $3',
                [novoHash, usuario.id, senhaArmazenada]
            );
            if (atualizacao.rowCount === 1) {
                senhaValida = true;
            } else {
                const senhaAtual = await pool.query(
                    'SELECT senha_hash FROM usuarios WHERE id = $1 AND ativo = TRUE',
                    [usuario.id]
                );
                const hashAtual = senhaAtual.rows[0]?.senha_hash;
                senhaValida = typeof hashAtual === 'string' &&
                    /^\$2[aby]\$\d{2}\$/.test(hashAtual) &&
                    await bcrypt.compare(senha, hashAtual);
            }
        }

        if (!senhaValida) {
            return res.status(401).json({ erro: 'E-mail ou senha inválidos.' });
        }

        if (usuario.perfil === 'professor' && !usuario.professor_id) {
            return res.status(403).json({ erro: 'Este usuário ainda não está vinculado a um professor.' });
        }
        const token = jwt.sign(
            { perfil: usuario.perfil, professor_id: usuario.professor_id ? String(usuario.professor_id) : null },
            process.env.JWT_SECRET,
            { subject: String(usuario.id), expiresIn: '2h' }
        );
        return res.json({
            mensagem: 'Login realizado com sucesso.',
            token,
            usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email, perfil: usuario.perfil, professor_id: usuario.professor_id }
        });
    } catch (erro) {
        console.error('Erro no login:', erro.message);
        return res.status(500).json({ erro: 'Não foi possível realizar o login.' });
    }
});

// TURMAS
app.get('/api/turmas', autenticarToken, async (req, res) => {
    try {
        const resultado = await pool.query(`SELECT id, nome, ano_letivo, ativo FROM turmas ORDER BY ano_letivo DESC, nome`);
        return res.json(resultado.rows);
    } catch (erro) {
        console.error('Erro ao consultar turmas:', erro.message);
        return res.status(500).json({ erro: 'Não foi possível consultar as turmas.' });
    }
});

app.post('/api/turmas', autenticarToken, async (req, res) => {
    if (req.usuario.perfil !== 'admin') {
        return res.status(403).json({ erro: 'Somente o administrador pode cadastrar turmas.' });
    }
    try {
        const nome = String(req.body.nome || '').trim();
        const anoLetivo = Number(req.body.ano_letivo);
        if (!nome || nome.length > 80) return res.status(400).json({ erro: 'Informe o nome da turma, com até 80 caracteres.' });
        if (!Number.isInteger(anoLetivo) || anoLetivo < 2000 || anoLetivo > 2100) return res.status(400).json({ erro: 'Informe um ano letivo válido.' });
        const resultado = await pool.query(`INSERT INTO turmas (nome, ano_letivo) VALUES ($1, $2) RETURNING id, nome, ano_letivo, ativo`, [nome, anoLetivo]);
        return res.status(201).json({ mensagem: 'Turma cadastrada com sucesso.', turma: resultado.rows[0] });
    } catch (erro) {
        if (erro.code === '23505') return res.status(409).json({ erro: 'Já existe uma turma com esse nome nesse ano letivo.' });
        console.error('Erro ao cadastrar turma:', erro.message);
        return res.status(500).json({ erro: 'Não foi possível cadastrar a turma.' });
    }
});

// ALUNOS
app.get('/api/alunos', autenticarToken, async (req, res) => {
    try {
        const pesquisa = (req.query.busca || '').trim();
        const resultado = await pool.query(
            `SELECT id, nome, matricula, ativo
             FROM alunos
             WHERE nome ILIKE $1 OR matricula ILIKE $1
             ORDER BY nome`,
            [`%${pesquisa}%`]
        );
        res.json(resultado.rows);
    } catch (erro) {
        console.error('Erro ao consultar alunos:', erro.message);
        res.status(500).json({ erro: 'Não foi possível consultar os alunos.' });
    }
});

app.post('/api/alunos', autenticarToken, async (req, res) => {
    if (req.usuario.perfil !== 'admin') return res.status(403).json({ erro: 'Somente o administrador pode cadastrar alunos.' });
    try {
        const nome = String(req.body.nome || '').trim();
        const matricula = String(req.body.matricula || '').trim();
        const dataNascimento = req.body.data_nascimento || null;
        if (!nome || !matricula) return res.status(400).json({ erro: 'Nome e matrícula são obrigatórios.' });
        if (nome.length > 150 || matricula.length > 30) return res.status(400).json({ erro: 'Nome ou matrícula excede o limite permitido.' });
        const resultado = await pool.query(`INSERT INTO alunos (nome, matricula, data_nascimento) VALUES ($1, $2, $3) RETURNING id, nome, matricula, data_nascimento, ativo`, [nome, matricula, dataNascimento]);
        res.status(201).json({ mensagem: 'Aluno cadastrado com sucesso.', aluno: resultado.rows[0] });
    } catch (erro) {
        if (erro.code === '23505') return res.status(409).json({ erro: 'Já existe um aluno com essa matrícula.' });
        if (erro.code === '22007' || erro.code === '22008') return res.status(400).json({ erro: 'Data de nascimento inválida.' });
        console.error('Erro ao cadastrar aluno:', erro.message);
        res.status(500).json({ erro: 'Não foi possível cadastrar o aluno.' });
    }
});

app.put('/api/alunos/:id', autenticarToken, async (req, res) => {
    if (req.usuario.perfil !== 'admin') return res.status(403).json({ erro: 'Somente o administrador pode editar alunos.' });
    try {
        const id = Number(req.params.id);
        const nome = String(req.body.nome || '').trim();
        const matricula = String(req.body.matricula || '').trim();
        const dataNascimento = req.body.data_nascimento || null;
        if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ erro: 'ID inválido.' });
        if (!nome || !matricula) return res.status(400).json({ erro: 'Nome e matrícula são obrigatórios.' });
        const resultado = await pool.query(`UPDATE alunos SET nome = $1, matricula = $2, data_nascimento = $3 WHERE id = $4 RETURNING id, nome, matricula, data_nascimento, ativo`, [nome, matricula, dataNascimento, id]);
        if (resultado.rowCount === 0) return res.status(404).json({ erro: 'Aluno não encontrado.' });
        res.json({ mensagem: 'Aluno atualizado com sucesso.', aluno: resultado.rows[0] });
    } catch (erro) {
        if (erro.code === '23505') return res.status(409).json({ erro: 'Já existe um aluno com essa matrícula.' });
        console.error('Erro ao editar aluno:', erro.message);
        res.status(500).json({ erro: 'Não foi possível editar o aluno.' });
    }
});

app.patch('/api/alunos/:id/inativar', autenticarToken, async (req, res) => {
    if (req.usuario.perfil !== 'admin') return res.status(403).json({ erro: 'Somente o administrador pode inativar alunos.' });
    try {
        const id = Number(req.params.id);
        if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ erro: 'ID inválido.' });
        const resultado = await pool.query(`UPDATE alunos SET ativo = FALSE WHERE id = $1 RETURNING id, nome, matricula, ativo`, [id]);
        if (resultado.rowCount === 0) return res.status(404).json({ erro: 'Aluno não encontrado.' });
        res.json({ mensagem: 'Aluno inativado com sucesso.', aluno: resultado.rows[0] });
    } catch (erro) {
        console.error('Erro ao inativar aluno:', erro.message);
        res.status(500).json({ erro: 'Não foi possível inativar o aluno.' });
    }
});

app.delete('/api/alunos/:id', autenticarToken, autorizar('admin'), async (req, res) => {
    if (req.body?.confirmar_exclusao_com_historico !== true) {
        return res.status(409).json({
            erro: 'Nenhum dado foi excluído. O administrador deve atualizar/recarregar o aplicativo e confirmar a exclusão permanente.'
        });
    }

    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ erro: 'ID de aluno inválido.' });

    const client = await pool.connect();
    let fotoAluno = null;
    let arquivosJustificativas = [];
    try {
        await client.query('BEGIN');
        const aluno = await client.query('SELECT id, foto_url FROM alunos WHERE id = $1 FOR UPDATE', [id]);
        if (!aluno.rowCount) {
            await client.query('ROLLBACK');
            return res.status(404).json({ erro: 'Aluno não encontrado.' });
        }
        fotoAluno = aluno.rows[0].foto_url;

        const justificativas = await client.query(
            `SELECT j.arquivo_nome
             FROM justificativas_falta j
             JOIN frequencias f ON f.id = j.frequencia_id
             WHERE f.aluno_id = $1`,
            [id]
        );
        arquivosJustificativas = justificativas.rows.map((item) => item.arquivo_nome);

        await client.query(
            `DELETE FROM justificativas_falta
             WHERE frequencia_id IN (SELECT id FROM frequencias WHERE aluno_id = $1)`,
            [id]
        );
        await client.query('DELETE FROM frequencias WHERE aluno_id = $1', [id]);
        await client.query('DELETE FROM notas WHERE aluno_id = $1', [id]);
        await client.query('DELETE FROM historico_notas WHERE aluno_id = $1', [id]);
        await client.query('DELETE FROM avisos WHERE aluno_id = $1', [id]);
        await client.query('DELETE FROM responsavel_aluno WHERE aluno_id = $1', [id]);
        await client.query('DELETE FROM alunos_responsaveis WHERE aluno_id = $1', [id]);
        await client.query('DELETE FROM matriculas WHERE aluno_id = $1', [id]);

        const result = await client.query('DELETE FROM alunos WHERE id = $1 RETURNING id', [id]);
        if (!result.rowCount) {
            await client.query('ROLLBACK');
            return res.status(404).json({ erro: 'Aluno não encontrado.' });
        }
        await client.query('COMMIT');

        const fotoMatch = typeof fotoAluno === 'string'
            ? fotoAluno.match(/^\/uploads\/alunos\/([^/]+)$/)
            : null;
        const arquivosRelacionados = [
            ...(fotoMatch ? [path.join(__dirname, 'uploads', 'alunos', fotoMatch[1])] : []),
            ...arquivosJustificativas.map((nome) => path.join(__dirname, 'uploads', 'justificativas', path.basename(nome)))
        ];
        const falhasLimpeza = [];
        for (const arquivo of arquivosRelacionados) {
            try {
                await fs.promises.unlink(arquivo);
            } catch (erroArquivo) {
                if (erroArquivo.code !== 'ENOENT') {
                    falhasLimpeza.push(path.basename(arquivo));
                    console.error('Erro ao remover arquivo do aluno excluído:', erroArquivo.message);
                }
            }
        }

        return res.json({
            mensagem: 'Cadastro do aluno, vínculos e histórico escolar excluídos permanentemente.',
            ...(falhasLimpeza.length ? { aviso: 'Não foi possível remover alguns arquivos anexos do armazenamento.' } : {})
        });
    } catch (erro) {
        try {
            await client.query('ROLLBACK');
        } catch (erroRollback) {
            console.error('Erro ao cancelar exclusão do aluno:', erroRollback.message);
        }
        if (erro.code === '23503') return res.status(409).json({ erro: 'Há outro registro vinculado ao aluno. A exclusão foi cancelada e nenhum dado foi removido.' });
        console.error('Erro ao excluir aluno:', erro.message);
        return res.status(500).json({ erro: 'Não foi possível excluir o aluno.' });
    } finally {
        client.release();
    }
});

// NOTAS
app.get('/api/notas', autenticarToken, async (req, res) => {
    try {
        let consulta; let parametros = [];
        if (req.usuario.perfil === 'admin') {
            consulta = `SELECT n.id, a.nome AS aluno, d.nome AS disciplina, av.titulo AS avaliacao, n.nota, av.nota_maxima FROM notas n JOIN alunos a ON a.id = n.aluno_id JOIN avaliacoes av ON av.id = n.avaliacao_id JOIN turmas_disciplinas td ON td.id = av.turma_disciplina_id JOIN disciplinas d ON d.id = td.disciplina_id ORDER BY a.nome, av.data_avaliacao DESC`;
        } else if (req.usuario.perfil === 'professor' && req.usuario.professor_id) {
            consulta = `SELECT n.id, a.nome AS aluno, d.nome AS disciplina, av.titulo AS avaliacao, n.nota, av.nota_maxima FROM notas n JOIN alunos a ON a.id = n.aluno_id JOIN avaliacoes av ON av.id = n.avaliacao_id JOIN turmas_disciplinas td ON td.id = av.turma_disciplina_id JOIN disciplinas d ON d.id = td.disciplina_id WHERE td.professor_id = $1 ORDER BY a.nome, av.data_avaliacao DESC`;
            parametros = [Number(req.usuario.professor_id)];
        } else { return res.status(403).json({ erro: 'Perfil sem permissão para consultar notas.' }); }
        const resultado = await pool.query(consulta, parametros);
        return res.json(resultado.rows);
    } catch (erro) {
        console.error('Erro ao consultar notas:', erro.message);
        return res.status(500).json({ erro: 'Não foi possível consultar as notas.' });
    }
});

app.get('/api/turmas-disciplinas', autenticarToken, async (req, res) => {
    try {
        let consulta; let parametros = [];
        if (req.usuario.perfil === 'admin') {
            consulta = `SELECT td.id, td.turma_id, td.disciplina_id, td.professor_id, t.nome AS turma, d.nome AS disciplina, p.nome AS professor FROM turmas_disciplinas td JOIN turmas t ON t.id = td.turma_id JOIN disciplinas d ON d.id = td.disciplina_id JOIN professores p ON p.id = td.professor_id ORDER BY t.nome, d.nome`;
        } else if (req.usuario.perfil === 'professor' && req.usuario.professor_id) {
            consulta = `SELECT td.id, td.turma_id, td.disciplina_id, td.professor_id, t.nome AS turma, d.nome AS disciplina, p.nome AS professor FROM turmas_disciplinas td JOIN turmas t ON t.id = td.turma_id JOIN disciplinas d ON d.id = td.disciplina_id JOIN professores p ON p.id = td.professor_id WHERE td.professor_id = $1 ORDER BY t.nome, d.nome`;
            parametros = [req.usuario.professor_id];
        } else { return res.status(403).json({ erro: 'Perfil sem permissão para consultar disciplinas.' }); }
        const resultado = await pool.query(consulta, parametros);
        res.json(resultado.rows);
    } catch (erro) {
        console.error('Erro ao consultar disciplinas:', erro.message);
        res.status(500).json({ erro: 'Não foi possível consultar as disciplinas.' });
    }
});

app.get('/api/turmas-disciplinas/:id/alunos', autenticarToken, async (req, res) => {
    try {
        const turmaDisciplinaId = Number(req.params.id);
        if (!Number.isSafeInteger(turmaDisciplinaId) || turmaDisciplinaId <= 0) return res.status(400).json({ erro: 'Identificador de turma e disciplina inválido.' });
        let consultaVinculo = `SELECT id, turma_id FROM turmas_disciplinas WHERE id = $1`;
        const parametrosVinculo = [turmaDisciplinaId];
        if (req.usuario.perfil === 'professor') {
            if (!req.usuario.professor_id) return res.status(403).json({ erro: 'Usuário sem vínculo com um professor.' });
            consultaVinculo += ' AND professor_id = $2';
            parametrosVinculo.push(req.usuario.professor_id);
        } else if (req.usuario.perfil !== 'admin') return res.status(403).json({ erro: 'Você não tem permissão para consultar estes alunos.' });
        const vinculo = await pool.query(consultaVinculo, parametrosVinculo);
        if (vinculo.rowCount === 0) return res.status(404).json({ erro: 'Turma e disciplina não encontradas ou sem permissão.' });
        const resultado = await pool.query(`SELECT a.id, a.nome, a.matricula FROM matriculas m JOIN alunos a ON a.id = m.aluno_id WHERE m.turma_id = $1 AND a.ativo = TRUE ORDER BY a.nome`, [vinculo.rows[0].turma_id]);
        res.json(resultado.rows);
    } catch (erro) {
        console.error('Erro ao consultar alunos:', erro.message);
        res.status(500).json({ erro: 'Não foi possível consultar os alunos.' });
    }
});

app.get('/api/turmas-disciplinas/:id/avaliacoes', autenticarToken, async (req, res) => {
    try {
        const turmaDisciplinaId = req.params.id;
        const { perfil, professor_id } = req.usuario;
        if (!['admin', 'professor'].includes(perfil)) return res.status(403).json({ erro: 'Você não tem permissão para consultar avaliações.' });
        const parametros = [turmaDisciplinaId];
        let consulta = `SELECT a.id, a.titulo, a.data_avaliacao, a.nota_maxima FROM avaliacoes a INNER JOIN turmas_disciplinas td ON td.id = a.turma_disciplina_id WHERE td.id = $1`;
        if (perfil === 'professor') {
            if (!professor_id) return res.status(403).json({ erro: 'Usuário não vinculado a um professor.' });
            consulta += ` AND td.professor_id = $2`;
            parametros.push(professor_id);
        }
        consulta += ` ORDER BY a.data_avaliacao DESC NULLS LAST, a.id DESC`;
        const resultado = await pool.query(consulta, parametros);
        return res.json(resultado.rows);
    } catch (erro) {
        console.error('Erro ao listar avaliações:', erro.message);
        return res.status(500).json({ erro: 'Não foi possível listar as avaliações.' });
    }
});

app.post('/api/avaliacoes', autenticarToken, async (req, res) => {
    try {
        const turmaDisciplinaId = Number(req.body.turma_disciplina_id);
        const titulo = String(req.body.titulo || '').trim();
        const dataAvaliacao = req.body.data_avaliacao || null;
        const notaMaxima = Number(req.body.nota_maxima ?? 10);
        if (!Number.isSafeInteger(turmaDisciplinaId) || turmaDisciplinaId <= 0 || !titulo || titulo.length > 150 || !Number.isFinite(notaMaxima) || notaMaxima <= 0 || notaMaxima > 999.99) return res.status(400).json({ erro: 'Informe turma/disciplina, título e nota máxima válidos.' });
        if (dataAvaliacao !== null && (typeof dataAvaliacao !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(dataAvaliacao))) return res.status(400).json({ erro: 'Data da avaliação inválida.' });
        let consultaVinculo = `SELECT id FROM turmas_disciplinas WHERE id = $1`;
        const parametrosVinculo = [turmaDisciplinaId];
        if (req.usuario.perfil === 'professor') {
            if (!req.usuario.professor_id) return res.status(403).json({ erro: 'Usuário sem vínculo com um professor.' });
            consultaVinculo += ' AND professor_id = $2';
            parametrosVinculo.push(req.usuario.professor_id);
        } else if (req.usuario.perfil !== 'admin') return res.status(403).json({ erro: 'Você não tem permissão para criar avaliações.' });
        const vinculo = await pool.query(consultaVinculo, parametrosVinculo);
        if (vinculo.rowCount === 0) return res.status(403).json({ erro: 'Turma/disciplina não encontrada ou sem permissão.' });
        const resultado = await pool.query(`INSERT INTO avaliacoes (turma_disciplina_id, titulo, data_avaliacao, nota_maxima) VALUES ($1, $2, $3, $4) RETURNING id, turma_disciplina_id, titulo, data_avaliacao, nota_maxima`, [turmaDisciplinaId, titulo, dataAvaliacao, notaMaxima]);
        res.status(201).json({ mensagem: 'Avaliação criada com sucesso.', avaliacao: resultado.rows[0] });
    } catch (erro) {
        console.error('Erro ao criar avaliação:', erro.message);
        res.status(500).json({ erro: 'Não foi possível criar a avaliação.' });
    }
});

app.get('/api/avaliacoes/:id/notas', autenticarToken, async (req, res) => {
    try {
        const avaliacaoId = Number(req.params.id);
        if (!Number.isInteger(avaliacaoId) || avaliacaoId <= 0) return res.status(400).json({ mensagem: 'ID da avaliação inválido.' });
        const parametros = [avaliacaoId];
        let filtroProfessor = '';
        if (req.usuario.perfil === 'professor') {
            if (!req.usuario.professor_id) return res.status(403).json({ mensagem: 'Usuário sem vínculo com um professor.' });
            parametros.push(Number(req.usuario.professor_id));
            filtroProfessor = 'AND td.professor_id = $2';
        } else if (req.usuario.perfil !== 'admin') return res.status(403).json({ mensagem: 'Você não tem permissão para consultar notas.' });
        const resultado = await pool.query(`SELECT a.id AS avaliacao_id, a.titulo, a.nota_maxima, al.id AS aluno_id, al.nome AS aluno, n.nota, n.observacao FROM avaliacoes a JOIN turmas_disciplinas td ON td.id = a.turma_disciplina_id JOIN matriculas m ON m.turma_id = td.turma_id JOIN alunos al ON al.id = m.aluno_id AND al.ativo = true LEFT JOIN notas n ON n.avaliacao_id = a.id AND n.aluno_id = al.id WHERE a.id = $1 ${filtroProfessor} ORDER BY al.nome`, parametros);
        if (resultado.rows.length === 0) return res.status(404).json({ mensagem: 'Avaliação não encontrada ou sem alunos matriculados.' });
        res.json({ avaliacao: { id: resultado.rows[0].avaliacao_id, titulo: resultado.rows[0].titulo, nota_maxima: resultado.rows[0].nota_maxima }, alunos: resultado.rows.map(linha => ({ id: linha.aluno_id, nome: linha.aluno, nota: linha.nota, observacao: linha.observacao })) });
    } catch (erro) {
        console.error('Erro ao consultar notas da avaliação:', erro);
        res.status(500).json({ mensagem: 'Erro ao consultar notas da avaliação.' });
    }
});

app.post('/api/notas/lote', autenticarToken, async (req, res) => {
    let client; let transacaoIniciada = false;
    try {
        const { avaliacao_id, notas } = req.body || {};
        const avaliacaoId = Number(avaliacao_id);
        if (!Number.isSafeInteger(avaliacaoId) || avaliacaoId <= 0 || !Array.isArray(notas) || notas.length === 0) return res.status(400).json({ mensagem: 'Informe uma avaliação e pelo menos uma nota.' });
        if (!['admin', 'professor'].includes(req.usuario.perfil)) return res.status(403).json({ mensagem: 'Você não tem permissão para lançar notas.' });
        client = await pool.connect();
        await client.query('BEGIN'); transacaoIniciada = true;
        const parametrosAvaliacao = [avaliacaoId];
        let filtroProfessor = '';
        if (req.usuario.perfil === 'professor') {
            parametrosAvaliacao.push(Number(req.usuario.professor_id));
            filtroProfessor = 'AND td.professor_id = $2';
        }
        const consultaAvaliacao = await client.query(`SELECT a.id, a.nota_maxima, td.turma_id FROM avaliacoes a JOIN turmas_disciplinas td ON td.id = a.turma_disciplina_id WHERE a.id = $1 ${filtroProfessor} FOR UPDATE OF a`, parametrosAvaliacao);
        if (consultaAvaliacao.rowCount === 0) throw Object.assign(new Error('Avaliação não encontrada ou sem permissão.'), { status: 403 });
        const avaliacao = consultaAvaliacao.rows[0];
        for (const item of notas) {
            const alunoId = Number(item.aluno_id); const nota = Number(item.nota);
            const matricula = await client.query(`SELECT al.id FROM matriculas m JOIN alunos al ON al.id = m.aluno_id WHERE m.aluno_id = $1 AND m.turma_id = $2 AND al.ativo = TRUE LIMIT 1`, [alunoId, avaliacao.turma_id]);
            if (matricula.rowCount === 0) throw new Error(`O aluno ${alunoId} não está ativo e matriculado nesta turma.`);
            const notaExistente = await client.query(`SELECT nota FROM notas WHERE avaliacao_id = $1 AND aluno_id = $2 FOR UPDATE`, [avaliacaoId, alunoId]);
            const notaAnterior = notaExistente.rowCount > 0 ? notaExistente.rows[0].nota : null;
            await client.query(`INSERT INTO notas (avaliacao_id, aluno_id, nota) VALUES ($1, $2, $3) ON CONFLICT (avaliacao_id, aluno_id) DO UPDATE SET nota = EXCLUDED.nota, atualizado_em = CURRENT_TIMESTAMP`, [avaliacaoId, alunoId, nota]);
            await client.query(`INSERT INTO historico_notas (avaliacao_id, aluno_id, nota_anterior, nota_nova, usuario_id) VALUES ($1, $2, $3, $4, $5)`, [avaliacaoId, alunoId, notaAnterior, nota, Number(req.usuario.sub)]);
        }
        await client.query('COMMIT'); transacaoIniciada = false;
        return res.json({ mensagem: 'Todas as notas foram salvas com sucesso!', quantidade: notas.length });
    } catch (erro) {
        if (transacaoIniciada && client) { try { await client.query('ROLLBACK'); } catch {} }
        console.error('Erro ao salvar notas em lote:', erro);
        return res.status(erro.status || 400).json({ mensagem: erro.message || 'Erro ao salvar as notas.' });
    } finally { if (client) client.release(); }
});

app.post('/api/notas', autenticarToken, async (req, res) => {
    try {
        const avaliacaoId = Number(req.body.avaliacao_id); const alunoId = Number(req.body.aluno_id); const nota = Number(req.body.nota);
        const observacao = req.body.observacao == null ? null : String(req.body.observacao).trim();
        if (!Number.isSafeInteger(avaliacaoId) || avaliacaoId <= 0 || !Number.isSafeInteger(alunoId) || alunoId <= 0 || !Number.isFinite(nota) || nota < 0) return res.status(400).json({ erro: 'Informe avaliação, aluno e nota válidos.' });
        const avaliacaoResultado = await pool.query(`SELECT av.id, av.nota_maxima, td.turma_id, td.professor_id FROM avaliacoes av JOIN turmas_disciplinas td ON td.id = av.turma_disciplina_id WHERE av.id = $1`, [avaliacaoId]);
        if (avaliacaoResultado.rowCount === 0) return res.status(404).json({ erro: 'Avaliação não encontrada.' });
        const avaliacao = avaliacaoResultado.rows[0];
        if (req.usuario.perfil === 'professor' && String(avaliacao.professor_id) !== String(req.usuario.professor_id)) return res.status(403).json({ erro: 'Você não pode lançar notas nesta avaliação.' });
        const resultado = await pool.query(`INSERT INTO notas (avaliacao_id, aluno_id, nota, observacao, atualizado_em) VALUES ($1, $2, $3, $4, NOW()) ON CONFLICT (avaliacao_id, aluno_id) DO UPDATE SET nota = EXCLUDED.nota, observacao = EXCLUDED.observacao, atualizado_em = NOW() RETURNING id, avaliacao_id, aluno_id, nota, observacao, atualizado_em`, [avaliacaoId, alunoId, nota, observacao]);
        res.status(200).json({ mensagem: 'Nota salva com sucesso.', nota: resultado.rows[0] });
    } catch (erro) {
        console.error('Erro ao salvar nota:', erro.message);
        res.status(500).json({ erro: 'Não foi possível salvar a nota.' });
    }
});

app.get('/api/avisos', autenticarToken, async (req, res) => {
    try {
        const resultado = await pool.query(`SELECT av.id, av.titulo, av.mensagem, t.nome AS turma, av.criado_em FROM avisos av LEFT JOIN turmas t ON t.id = av.turma_id WHERE av.publicado = TRUE ORDER BY av.criado_em DESC`);
        res.json(resultado.rows);
    } catch (erro) {
        console.error('Erro ao consultar avisos:', erro.message);
        res.status(500).json({ erro: 'Não foi possível consultar os avisos.' });
    }
});

app.get('/api/historico-notas', autenticarToken, async (req, res) => {
    try {
        if (!['admin', 'professor'].includes(req.usuario.perfil)) return res.status(403).json({ mensagem: 'Você não tem permissão para consultar o histórico.' });
        const parametros = []; let filtroProfessor = '';
        if (req.usuario.perfil === 'professor') { parametros.push(Number(req.usuario.professor_id)); filtroProfessor = 'WHERE td.professor_id = $1'; }
        const consulta = await pool.query(`SELECT hn.id AS historico_id, al.id AS aluno_id, al.nome AS aluno, a.id AS avaliacao_id, a.titulo AS avaliacao, t.nome AS turma, d.nome AS disciplina, hn.nota_anterior, hn.nota_nova, u.nome AS usuario_responsavel, hn.alterado_em FROM historico_notas hn JOIN alunos al ON al.id = hn.aluno_id JOIN avaliacoes a ON a.id = hn.avaliacao_id JOIN turmas_disciplinas td ON td.id = a.turma_disciplina_id JOIN turmas t ON t.id = td.turma_id JOIN disciplinas d ON d.id = td.disciplina_id LEFT JOIN usuarios u ON u.id = hn.usuario_id ${filtroProfessor} ORDER BY hn.alterado_em DESC LIMIT 200`, parametros);
        return res.json(consulta.rows);
    } catch (erro) {
        console.error('Erro ao consultar histórico de notas:', erro);
        return res.status(500).json({ mensagem: 'Não foi possível consultar o histórico de notas.' });
    }
});

// ===== ÁREA RESPONSÁVEL =====
app.post('/api/responsaveis', autenticarToken, autorizar('admin'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { nome, email, senha, telefone, alunos_ids, parentesco } = req.body || {};
    if (!nome || !email || !senha) return res.status(400).json({ erro: 'Nome, email e senha são obrigatórios.' });
    if (senha.length < 8) return res.status(400).json({ erro: 'Senha deve ter pelo menos 8 caracteres.' });
    let telefoneNormalizado = String(telefone || '').replace(/\D/g, '');
    if (telefoneNormalizado.startsWith('0')) telefoneNormalizado = telefoneNormalizado.slice(1);
    if (telefoneNormalizado.length === 10 || telefoneNormalizado.length === 11) telefoneNormalizado = `55${telefoneNormalizado}`;
    if (!/^55\d{10,11}$/.test(telefoneNormalizado)) {
      return res.status(400).json({ erro: 'Informe um WhatsApp válido com DDD.' });
    }
    await client.query('BEGIN');
    const hash = await bcrypt.hash(senha, 12);
    const user = await client.query(`INSERT INTO usuarios (nome, email, senha_hash, perfil) VALUES ($1,$2,$3,'responsavel') RETURNING id`, [nome.trim(), email.trim().toLowerCase(), hash]);
    const resp = await client.query(`INSERT INTO responsaveis (usuario_id, telefone, parentesco) VALUES ($1,$2,$3) RETURNING id`, [user.rows[0].id, telefoneNormalizado, parentesco || 'responsável']);
    if (Array.isArray(alunos_ids)) {
      for (const alunoId of alunos_ids) {
        const idNum = Number(alunoId);
        if (Number.isSafeInteger(idNum) && idNum > 0) {
          await client.query(`INSERT INTO responsavel_aluno (responsavel_id, aluno_id, parentesco) VALUES ($1,$2,$3) ON CONFLICT (responsavel_id, aluno_id) DO UPDATE SET parentesco = EXCLUDED.parentesco`, [resp.rows[0].id, idNum, parentesco || 'responsável']);
          await client.query(`INSERT INTO alunos_responsaveis (responsavel_id, aluno_id, parentesco) VALUES ($1,$2,$3) ON CONFLICT (responsavel_id, aluno_id) DO UPDATE SET parentesco = EXCLUDED.parentesco`, [resp.rows[0].id, idNum, parentesco || 'responsável']).catch(()=>{});
        }
      }
    }
    await client.query('COMMIT');
    return res.status(201).json({ mensagem: 'Responsável criado com sucesso.', responsavel_id: resp.rows[0].id, usuario_id: user.rows[0].id });
  } catch (e) {
    await client.query('ROLLBACK');
    if (e.code === '23505') return res.status(409).json({ erro: 'E-mail já cadastrado.' });
    console.error('Erro ao criar responsável:', e.message);
    return res.status(500).json({ erro: 'Erro ao criar responsável.' });
  } finally { client.release(); }
});

app.get('/api/responsaveis', autenticarToken, autorizar('admin'), async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT r.id, u.nome, u.email, r.telefone, r.parentesco, u.ativo,
             ARRAY_AGG(a.nome) FILTER (WHERE a.id IS NOT NULL) as filhos
      FROM responsaveis r
      JOIN usuarios u ON u.id = r.usuario_id
      LEFT JOIN responsavel_aluno ra ON ra.responsavel_id = r.id
      LEFT JOIN alunos a ON a.id = ra.aluno_id
      GROUP BY r.id, u.nome, u.email, r.telefone, r.parentesco, u.ativo
      ORDER BY u.nome
    `);
    return res.json(r.rows);
  } catch (e) { console.error(e); return res.status(500).json({ erro: 'Erro ao listar responsáveis.' }); }
});

app.get('/api/responsavel/filhos', autenticarToken, autorizar('responsavel','admin'), async (req, res) => {
  try {
    const usuarioId = Number(req.usuario.sub);
    const perfil = req.usuario.perfil;
    let query = `SELECT a.id, a.nome, a.matricula, CASE WHEN a.foto_url IS NOT NULL THEN '/api/alunos/' || a.id || '/foto' END AS foto_url, t.nome as turma, t.ano_letivo FROM alunos a LEFT JOIN matriculas m ON m.aluno_id = a.id LEFT JOIN turmas t ON t.id = m.turma_id WHERE a.ativo = true`;
    let params = [];
    if (perfil === 'responsavel') {
      query = `SELECT DISTINCT a.id, a.nome, a.matricula, CASE WHEN a.foto_url IS NOT NULL THEN '/api/alunos/' || a.id || '/foto' END AS foto_url, t.nome as turma, t.ano_letivo, ra.parentesco FROM responsaveis r JOIN ( SELECT responsavel_id, aluno_id, COALESCE(MAX(NULLIF(parentesco, '')), 'Responsável') AS parentesco FROM ( SELECT responsavel_id, aluno_id, parentesco FROM responsavel_aluno UNION ALL SELECT responsavel_id, aluno_id, parentesco FROM alunos_responsaveis ) links GROUP BY responsavel_id, aluno_id ) ra ON ra.responsavel_id = r.id JOIN alunos a ON a.id = ra.aluno_id LEFT JOIN matriculas m ON m.aluno_id = a.id LEFT JOIN turmas t ON t.id = m.turma_id WHERE r.usuario_id = $1 AND a.ativo = true ORDER BY a.nome`;
      params = [usuarioId];
    }
    const result = await pool.query(query, params);
    return res.json(result.rows);
  } catch (e) { console.error(e); return res.status(500).json({ erro: 'Erro ao buscar filhos.' }); }
});

app.put('/api/alunos/:id/foto', autenticarToken, autorizar('admin', 'responsavel'), async (req, res) => {
  let uploadedPath;
  try {
    const alunoId = Number(req.params.id);
    if (!Number.isSafeInteger(alunoId) || alunoId <= 0) {
      return res.status(400).json({ erro: 'ID do aluno inválido.' });
    }

    if (req.usuario.perfil === 'responsavel') {
      const vinculo = await pool.query(
        `SELECT 1
         FROM responsaveis r
         WHERE r.usuario_id = $1 AND (
           EXISTS (SELECT 1 FROM responsavel_aluno ra WHERE ra.responsavel_id = r.id AND ra.aluno_id = $2)
           OR EXISTS (SELECT 1 FROM alunos_responsaveis ar WHERE ar.responsavel_id = r.id AND ar.aluno_id = $2)
         )`,
        [Number(req.usuario.sub), alunoId]
      );
      if (vinculo.rowCount === 0) {
        return res.status(403).json({ erro: 'Você não está autorizado a alterar a foto deste aluno.' });
      }
    }

    const imagem = req.body && req.body.imagem;
    const correspondencia = typeof imagem === 'string'
      ? /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/.exec(imagem)
      : null;
    if (!correspondencia) {
      return res.status(400).json({ erro: 'Envie uma imagem JPEG válida.' });
    }

    const conteudo = Buffer.from(correspondencia[1], 'base64');
    if (
      conteudo.length < 4 ||
      conteudo.length > 1024 * 1024 ||
      conteudo[0] !== 0xff ||
      conteudo[1] !== 0xd8 ||
      conteudo[2] !== 0xff
    ) {
      return res.status(400).json({ erro: 'A foto deve ser um JPEG válido de até 1 MB.' });
    }

    const aluno = await pool.query('SELECT foto_url FROM alunos WHERE id = $1', [alunoId]);
    if (aluno.rowCount === 0) {
      return res.status(404).json({ erro: 'Aluno não encontrado.' });
    }

    const diretorio = path.join(__dirname, 'uploads', 'alunos');
    await fs.promises.mkdir(diretorio, { recursive: true });
    const nomeArquivo = `aluno-${alunoId}-${crypto.randomUUID()}.jpg`;
    uploadedPath = path.join(diretorio, nomeArquivo);
    await fs.promises.writeFile(uploadedPath, conteudo, { flag: 'wx' });

    const fotoUrl = `/uploads/alunos/${nomeArquivo}`;
    await pool.query('UPDATE alunos SET foto_url = $1 WHERE id = $2', [fotoUrl, alunoId]);

    const fotoAnterior = aluno.rows[0].foto_url;
    if (typeof fotoAnterior === 'string') {
      const nomeAnterior = path.basename(fotoAnterior);
      if (/^aluno-\d+-[0-9a-f-]+\.jpg$/i.test(nomeAnterior)) {
        await fs.promises.unlink(path.join(diretorio, nomeAnterior)).catch((erro) => {
          if (erro.code !== 'ENOENT') console.error('Erro ao remover foto anterior do aluno:', erro.message);
        });
      }
    }

    return res.json({ mensagem: 'Foto do aluno atualizada.', foto_url: `/api/alunos/${alunoId}/foto` });
  } catch (erro) {
    if (uploadedPath) {
      await fs.promises.unlink(uploadedPath).catch((cleanupError) => {
        if (cleanupError.code !== 'ENOENT') console.error('Erro ao remover upload incompleto:', cleanupError.message);
      });
    }
    console.error('Erro ao atualizar foto do aluno:', erro.message);
    return res.status(500).json({ erro: 'Não foi possível atualizar a foto do aluno.' });
  }
});

app.get('/api/alunos/:id/foto', autenticarToken, autorizar('admin', 'responsavel'), async (req, res) => {
  try {
    const alunoId = Number(req.params.id);
    if (!Number.isSafeInteger(alunoId) || alunoId <= 0) {
      return res.status(400).json({ erro: 'ID do aluno inválido.' });
    }

    if (req.usuario.perfil === 'responsavel') {
      const vinculo = await pool.query(
        `SELECT 1
         FROM responsaveis r
         WHERE r.usuario_id = $1 AND (
           EXISTS (SELECT 1 FROM responsavel_aluno ra WHERE ra.responsavel_id = r.id AND ra.aluno_id = $2)
           OR EXISTS (SELECT 1 FROM alunos_responsaveis ar WHERE ar.responsavel_id = r.id AND ar.aluno_id = $2)
         )`,
        [Number(req.usuario.sub), alunoId]
      );
      if (vinculo.rowCount === 0) {
        return res.status(403).json({ erro: 'Você não está autorizado a visualizar a foto deste aluno.' });
      }
    }

    const aluno = await pool.query('SELECT foto_url FROM alunos WHERE id = $1', [alunoId]);
    if (aluno.rowCount === 0) return res.status(404).json({ erro: 'Aluno não encontrado.' });

    const nomeArquivo = typeof aluno.rows[0].foto_url === 'string'
      ? path.basename(aluno.rows[0].foto_url)
      : '';
    if (!new RegExp(`^aluno-${alunoId}-[0-9a-f-]+\\.jpg$`, 'i').test(nomeArquivo)) {
      return res.status(404).json({ erro: 'Foto do aluno não encontrada.' });
    }

    const arquivo = path.join(__dirname, 'uploads', 'alunos', nomeArquivo);
    res.set('Cache-Control', 'private, no-store');
    return res.sendFile(arquivo, (erro) => {
      if (erro && !res.headersSent) {
        if (erro.statusCode === 404) return res.status(404).json({ erro: 'Foto do aluno não encontrada.' });
        console.error('Erro ao enviar foto do aluno:', erro.message);
        return res.status(500).json({ erro: 'Não foi possível carregar a foto do aluno.' });
      }
    });
  } catch (erro) {
    console.error('Erro ao carregar foto do aluno:', erro.message);
    return res.status(500).json({ erro: 'Não foi possível carregar a foto do aluno.' });
  }
});

app.put('/api/perfil/foto', autenticarToken, autorizar('admin', 'professor'), async (req, res) => {
  let uploadedPath;
  try {
    const imagem = req.body && req.body.imagem;
    const correspondencia = typeof imagem === 'string'
      ? /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/.exec(imagem)
      : null;
    if (!correspondencia) return res.status(400).json({ erro: 'Envie uma imagem JPEG válida.' });

    const conteudo = Buffer.from(correspondencia[1], 'base64');
    if (
      conteudo.length < 4 ||
      conteudo.length > 1024 * 1024 ||
      conteudo[0] !== 0xff ||
      conteudo[1] !== 0xd8 ||
      conteudo[2] !== 0xff
    ) {
      return res.status(400).json({ erro: 'A foto deve ser um JPEG válido de até 1 MB.' });
    }

    const usuarioId = Number(req.usuario.sub);
    const usuario = await pool.query('SELECT foto_url FROM usuarios WHERE id = $1', [usuarioId]);
    if (usuario.rowCount === 0) return res.status(404).json({ erro: 'Usuário não encontrado.' });

    const diretorio = path.join(__dirname, 'uploads', 'perfis');
    await fs.promises.mkdir(diretorio, { recursive: true });
    const nomeArquivo = `perfil-${usuarioId}-${crypto.randomUUID()}.jpg`;
    uploadedPath = path.join(diretorio, nomeArquivo);
    await fs.promises.writeFile(uploadedPath, conteudo, { flag: 'wx' });

    const fotoUrl = `/uploads/perfis/${nomeArquivo}`;
    await pool.query('UPDATE usuarios SET foto_url = $1 WHERE id = $2', [fotoUrl, usuarioId]);

    const fotoAnterior = usuario.rows[0].foto_url;
    if (typeof fotoAnterior === 'string') {
      const nomeAnterior = path.basename(fotoAnterior);
      if (new RegExp(`^perfil-${usuarioId}-[0-9a-f-]+\\.jpg$`, 'i').test(nomeAnterior)) {
        await fs.promises.unlink(path.join(diretorio, nomeAnterior)).catch((erro) => {
          if (erro.code !== 'ENOENT') console.error('Erro ao remover foto anterior do perfil:', erro.message);
        });
      }
    }

    return res.json({ mensagem: 'Foto do perfil atualizada.', foto_url: '/api/perfil/foto' });
  } catch (erro) {
    if (uploadedPath) {
      await fs.promises.unlink(uploadedPath).catch((erroLimpeza) => {
        if (erroLimpeza.code !== 'ENOENT') console.error('Erro ao remover foto de perfil incompleta:', erroLimpeza.message);
      });
    }
    console.error('Erro ao atualizar foto do perfil:', erro.message);
    return res.status(500).json({ erro: 'Não foi possível atualizar a foto do perfil.' });
  }
});

app.get('/api/perfil/foto', autenticarToken, autorizar('admin', 'professor'), async (req, res) => {
  try {
    const usuarioId = Number(req.usuario.sub);
    const usuario = await pool.query('SELECT foto_url FROM usuarios WHERE id = $1', [usuarioId]);
    if (usuario.rowCount === 0) return res.status(404).json({ erro: 'Usuário não encontrado.' });

    const nomeArquivo = typeof usuario.rows[0].foto_url === 'string'
      ? path.basename(usuario.rows[0].foto_url)
      : '';
    if (!new RegExp(`^perfil-${usuarioId}-[0-9a-f-]+\\.jpg$`, 'i').test(nomeArquivo)) {
      return res.status(404).json({ erro: 'Foto do perfil não encontrada.' });
    }

    res.set({ 'Cache-Control': 'private, no-store', 'Content-Type': 'image/jpeg' });
    return res.sendFile(path.join(__dirname, 'uploads', 'perfis', nomeArquivo), (erro) => {
      if (erro && !res.headersSent) {
        if (erro.statusCode === 404) return res.status(404).json({ erro: 'Foto do perfil não encontrada.' });
        console.error('Erro ao enviar foto do perfil:', erro.message);
        return res.status(500).json({ erro: 'Não foi possível carregar a foto do perfil.' });
      }
    });
  } catch (erro) {
    console.error('Erro ao carregar foto do perfil:', erro.message);
    return res.status(500).json({ erro: 'Não foi possível carregar a foto do perfil.' });
  }
});

app.get('/api/responsavel/filhos/:id/notas', autenticarToken, autorizar('responsavel','admin'), async (req, res) => {
  try {
    const alunoId = Number(req.params.id); const usuarioId = Number(req.usuario.sub);
    if (!Number.isSafeInteger(alunoId) || alunoId <= 0) return res.status(400).json({ erro: 'ID inválido.' });
    if (req.usuario.perfil === 'responsavel') {
      const vinculo = await pool.query(`SELECT 1 FROM responsaveis r JOIN responsavel_aluno ra ON ra.responsavel_id = r.id WHERE r.usuario_id = $1 AND ra.aluno_id = $2`, [usuarioId, alunoId]);
      if (vinculo.rowCount === 0) return res.status(403).json({ erro: 'Você não é responsável por este aluno.' });
    }
    const notas = await pool.query(`SELECT d.nome as disciplina, av.titulo as avaliacao, av.data_avaliacao, n.nota, av.nota_maxima FROM notas n JOIN avaliacoes av ON av.id = n.avaliacao_id JOIN turmas_disciplinas td ON td.id = av.turma_disciplina_id JOIN disciplinas d ON d.id = td.disciplina_id WHERE n.aluno_id = $1 ORDER BY d.nome, av.data_avaliacao DESC`, [alunoId]);
    const medias = await pool.query(`SELECT d.nome as disciplina, ROUND(AVG(n.nota)::numeric,2) as media, COUNT(*) as total_avaliacoes FROM notas n JOIN avaliacoes av ON av.id = n.avaliacao_id JOIN turmas_disciplinas td ON td.id = av.turma_disciplina_id JOIN disciplinas d ON d.id = td.disciplina_id WHERE n.aluno_id = $1 GROUP BY d.nome`, [alunoId]);
    return res.json({ aluno_id: alunoId, boletim: notas.rows, medias: medias.rows });
  } catch (e) { console.error(e); return res.status(500).json({ erro: 'Erro ao buscar boletim.' }); }
});

app.get('/api/faltas/turmas/:turmaDisciplinaId/alunos', autenticarToken, autorizar('professor', 'admin'), async (req, res) => {
  try {
    const turmaDisciplinaId = Number(req.params.turmaDisciplinaId);
    const data = req.query.data;
    if (!Number.isSafeInteger(turmaDisciplinaId) || turmaDisciplinaId <= 0) return res.status(400).json({ erro: 'Turma/disciplina inválida.' });
    if (!dataIsoValida(data)) return res.status(400).json({ erro: 'Informe uma data válida.' });

    const parametrosTurma = [turmaDisciplinaId];
    if (req.usuario.perfil === 'professor') {
      if (!req.usuario.professor_id) return res.status(403).json({ erro: 'Usuário sem vínculo com um professor.' });
      parametrosTurma.push(Number(req.usuario.professor_id));
    }

    const turmaResult = await pool.query(
      `SELECT turma_id FROM turmas_disciplinas td WHERE td.id = $1 ${req.usuario.perfil === 'professor' ? 'AND td.professor_id = $2' : ''}`,
      parametrosTurma
    );

    if (turmaResult.rowCount === 0) return res.status(403).json({ erro: 'Turma/disciplina não encontrada ou sem permissão.' });

    const turmaId = turmaResult.rows[0].turma_id;

    // ✅ CORREÇÃO: DISTINCT e SEM JOIN que triplicava
    const alunosResult = await pool.query(
      `SELECT DISTINCT a.id, a.nome, a.turma_id,
              COALESCE((
                SELECT json_agg(json_build_object('nome', contatos.nome, 'telefone', contatos.telefone))
                FROM (
                  SELECT DISTINCT r.id, u.nome, r.telefone
                  FROM (
                    SELECT responsavel_id FROM responsavel_aluno WHERE aluno_id = a.id
                    UNION
                    SELECT responsavel_id FROM alunos_responsaveis WHERE aluno_id = a.id
                  ) vinculos
                  JOIN responsaveis r ON r.id = vinculos.responsavel_id
                  JOIN usuarios u ON u.id = r.usuario_id
                  WHERE u.ativo = TRUE
                ) contatos
              ), '[]'::json) AS responsaveis
       FROM alunos a
       WHERE a.turma_id = $1
       ORDER BY a.nome`,
      [turmaId]
    );

    res.json(alunosResult.rows);

  } catch (err) {
    console.error('Erro faltas/turmas/alunos:', err);
    res.status(500).json({ erro: 'Erro ao buscar alunos' });
  }
});

app.post('/api/faltas/chamada', autenticarToken, autorizar('professor', 'admin'), async (req, res) => {
  let client;
  let transacaoIniciada = false;
  try {
    const turmaDisciplinaId = Number(req.body?.turma_disciplina_id);
    const data = req.body?.data;
    const registros = req.body?.registros;
    if (!Number.isSafeInteger(turmaDisciplinaId) || turmaDisciplinaId <= 0) return res.status(400).json({ erro: 'Turma/disciplina inválida.' });
    if (!dataIsoValida(data)) return res.status(400).json({ erro: 'Informe uma data válida.' });
    if (!Array.isArray(registros) || registros.length === 0 || registros.length > 300) return res.status(400).json({ erro: 'Informe os alunos da chamada (limite de 300).' });

    const ids = [];
    for (const registro of registros) {
      if (!registro || typeof registro !== 'object') return res.status(400).json({ erro: 'A chamada contém aluno duplicado ou registro inválido.' });
      const alunoId = Number(registro?.aluno_id);
      if (!Number.isSafeInteger(alunoId) || alunoId <= 0 || ids.includes(alunoId) || typeof registro.presente !== 'boolean') {
        return res.status(400).json({ erro: 'A chamada contém aluno duplicado ou registro inválido.' });
      }
      if (typeof (registro.detalhes ?? '') !== 'string' || (registro.detalhes ?? '').trim().length > 1000) {
        return res.status(400).json({ erro: 'O detalhe da falta deve ter até 1.000 caracteres.' });
      }
      ids.push(alunoId);
    }

    client = await pool.connect();
    await client.query('BEGIN');
    transacaoIniciada = true;
    const parametrosTurma = [turmaDisciplinaId];
    let filtroProfessor = '';
    if (req.usuario.perfil === 'professor') {
      if (!req.usuario.professor_id) throw Object.assign(new Error('Usuário sem vínculo com um professor.'), { status: 403 });
      parametrosTurma.push(Number(req.usuario.professor_id));
      filtroProfessor = 'AND professor_id = $2';
    }
    const turma = await client.query(
      `SELECT turma_id, professor_id FROM turmas_disciplinas WHERE id = $1 ${filtroProfessor} FOR UPDATE`,
      parametrosTurma
    );
    if (turma.rowCount === 0) throw Object.assign(new Error('Turma/disciplina não encontrada ou sem permissão.'), { status: 403 });

    const matriculas = await client.query(
      `SELECT a.id
       FROM matriculas m JOIN alunos a ON a.id = m.aluno_id
       WHERE m.turma_id = $1 AND a.ativo = TRUE AND a.id = ANY($2::int[])`,
      [turma.rows[0].turma_id, ids]
    );
    if (matriculas.rowCount !== ids.length) throw Object.assign(new Error('A chamada contém aluno que não está ativo e matriculado nesta turma.'), { status: 400 });

    for (const registro of registros) {
      await client.query(
        `INSERT INTO frequencias (aluno_id, turma_disciplina_id, data, presente, detalhes, professor_id, atualizado_em)
         VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
         ON CONFLICT (aluno_id, turma_disciplina_id, data)
         DO UPDATE SET presente = EXCLUDED.presente,
                       detalhes = EXCLUDED.detalhes,
                       professor_id = EXCLUDED.professor_id,
                       atualizado_em = CURRENT_TIMESTAMP`,
        [
          Number(registro.aluno_id),
          turmaDisciplinaId,
          data,
          registro.presente,
          registro.presente ? '' : String(registro.detalhes || '').trim(),
          turma.rows[0].professor_id
        ]
      );
    }

    await client.query('COMMIT');
    transacaoIniciada = false;
    return res.json({ mensagem: 'Chamada salva com sucesso.', alunos: registros.length, faltas: registros.filter((registro) => !registro.presente).length });
  } catch (erro) {
    if (transacaoIniciada && client) {
      try { await client.query('ROLLBACK'); } catch (erroRollback) { console.error('Erro ao cancelar chamada:', erroRollback.message); }
    }
    if (erro.status) return res.status(erro.status).json({ erro: erro.message });
    if (erro.code === '22008' || erro.code === '22007') return res.status(400).json({ erro: 'Data inválida.' });
    console.error('Erro ao salvar chamada:', erro.message);
    return res.status(500).json({ erro: 'Não foi possível salvar a chamada.' });
  } finally {
    if (client) client.release();
  }
});

app.get('/api/faltas/aluno/:alunoId', autenticarToken, autorizar('admin', 'professor', 'responsavel'), async (req, res) => {
  try {
    const alunoId = Number(req.params.alunoId);
    if (!Number.isSafeInteger(alunoId) || alunoId <= 0) return res.status(400).json({ erro: 'ID do aluno inválido.' });

    if (req.usuario.perfil === 'responsavel') {
      const vinculo = await pool.query(
        `SELECT 1 FROM responsaveis r
         WHERE r.usuario_id = $1 AND (
           EXISTS (SELECT 1 FROM responsavel_aluno ra WHERE ra.responsavel_id = r.id AND ra.aluno_id = $2)
           OR EXISTS (SELECT 1 FROM alunos_responsaveis ar WHERE ar.responsavel_id = r.id AND ar.aluno_id = $2)
         )`,
        [Number(req.usuario.sub), alunoId]
      );
      if (vinculo.rowCount === 0) return res.status(403).json({ erro: 'Você não é responsável por este aluno.' });
    }

    const parametros = [alunoId];
    let filtroProfessor = '';
    if (req.usuario.perfil === 'professor') {
      if (!req.usuario.professor_id) return res.status(403).json({ erro: 'Usuário sem vínculo com um professor.' });
      parametros.push(Number(req.usuario.professor_id));
      filtroProfessor = 'AND td.professor_id = $2';
    }
    const resultado = await pool.query(
      `SELECT f.id, f.data, f.detalhes, f.atualizado_em,
              t.nome AS turma, d.nome AS disciplina, p.nome AS professor,
              COALESCE((
                SELECT json_agg(json_build_object(
                  'id', j.id,
                  'nome_original', j.nome_original,
                  'criado_em', j.criado_em
                ) ORDER BY j.criado_em DESC)
                FROM justificativas_falta j WHERE j.frequencia_id = f.id
              ), '[]'::json) AS justificativas
       FROM frequencias f
       JOIN turmas_disciplinas td ON td.id = f.turma_disciplina_id
       JOIN turmas t ON t.id = td.turma_id
       JOIN disciplinas d ON d.id = td.disciplina_id
       LEFT JOIN professores p ON p.id = f.professor_id
       WHERE f.aluno_id = $1 AND f.presente = FALSE ${filtroProfessor}
       ORDER BY f.data DESC, f.id DESC`,
      parametros
    );
    return res.json({ total: resultado.rowCount, faltas: resultado.rows });
  } catch (erro) {
    console.error('Erro ao consultar faltas do aluno:', erro.message);
    return res.status(500).json({ erro: 'Não foi possível consultar as faltas do aluno.' });
  }
});

app.post('/api/faltas/:id/justificativas', autenticarToken, autorizar('responsavel'), express.raw({ type: 'application/octet-stream', limit: '5mb' }), async (req, res) => {
  let arquivoPath;
  try {
    const faltaId = Number(req.params.id);
    if (!Number.isSafeInteger(faltaId) || faltaId <= 0) return res.status(400).json({ erro: 'Falta inválida.' });
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) return res.status(400).json({ erro: 'Selecione um documento para enviar.' });
    if (req.body.length < 5) return res.status(400).json({ erro: 'O documento enviado é inválido.' });

    let nomeOriginal;
    try {
      nomeOriginal = decodeURIComponent(String(req.headers['x-file-name'] || ''));
    } catch {
      return res.status(400).json({ erro: 'Nome do arquivo inválido.' });
    }
    nomeOriginal = path.basename(nomeOriginal.replace(/\\/g, '/')).trim();
    if (!nomeOriginal || nomeOriginal.length > 180) return res.status(400).json({ erro: 'Nome de arquivo inválido (máximo de 180 caracteres).' });

    const tipo = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    const assinaturas = {
      'application/pdf': req.body.subarray(0, 5).toString('ascii') === '%PDF-',
      'image/jpeg': req.body[0] === 0xff && req.body[1] === 0xd8 && req.body[2] === 0xff,
      'image/png': req.body.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
    };
    if (!Object.prototype.hasOwnProperty.call(assinaturas, tipo) || !assinaturas[tipo]) {
      return res.status(400).json({ erro: 'Envie um documento PDF, JPEG ou PNG válido.' });
    }

    const falta = await pool.query(
      `SELECT f.id, f.aluno_id
       FROM frequencias f
       WHERE f.id = $1 AND f.presente = FALSE
         AND EXISTS (
           SELECT 1 FROM responsaveis r
           WHERE r.usuario_id = $2 AND (
             EXISTS (SELECT 1 FROM responsavel_aluno ra WHERE ra.responsavel_id = r.id AND ra.aluno_id = f.aluno_id)
             OR EXISTS (SELECT 1 FROM alunos_responsaveis ar WHERE ar.responsavel_id = r.id AND ar.aluno_id = f.aluno_id)
           )
         )`,
      [faltaId, Number(req.usuario.sub)]
    );
    if (falta.rowCount === 0) return res.status(404).json({ erro: 'Falta não encontrada para um aluno vinculado a este responsável.' });

    const diretorio = path.join(__dirname, 'uploads', 'justificativas');
    await fs.promises.mkdir(diretorio, { recursive: true });
    const extensao = { 'application/pdf': '.pdf', 'image/jpeg': '.jpg', 'image/png': '.png' }[tipo];
    const nomeArquivo = `${crypto.randomUUID()}${extensao}`;
    arquivoPath = path.join(diretorio, nomeArquivo);
    await fs.promises.writeFile(arquivoPath, req.body, { flag: 'wx' });
    const resultado = await pool.query(
      `INSERT INTO justificativas_falta (frequencia_id, usuario_id, nome_original, arquivo_nome, content_type)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, nome_original, criado_em`,
      [faltaId, Number(req.usuario.sub), nomeOriginal, nomeArquivo, tipo]
    );
    return res.status(201).json({ mensagem: 'Documento de justificativa enviado.', justificativa: resultado.rows[0] });
  } catch (erro) {
    if (arquivoPath) {
      await fs.promises.unlink(arquivoPath).catch((erroLimpeza) => {
        if (erroLimpeza.code !== 'ENOENT') console.error('Erro ao remover justificativa incompleta:', erroLimpeza.message);
      });
    }
    if (erro.status === 413) return res.status(413).json({ erro: 'O documento deve ter no máximo 5 MB.' });
    console.error('Erro ao enviar justificativa de falta:', erro.message);
    return res.status(500).json({ erro: 'Não foi possível enviar a justificativa.' });
  }
});

app.get('/api/justificativas/:id/arquivo', autenticarToken, autorizar('admin', 'professor', 'responsavel'), async (req, res) => {
  try {
    const justificativaId = Number(req.params.id);
    if (!Number.isSafeInteger(justificativaId) || justificativaId <= 0) return res.status(400).json({ erro: 'Documento inválido.' });
    const parametros = [justificativaId];
    let filtroAcesso = '';
    if (req.usuario.perfil === 'responsavel') {
      parametros.push(Number(req.usuario.sub));
      filtroAcesso = `AND EXISTS (
        SELECT 1 FROM responsaveis r
        WHERE r.usuario_id = $2 AND (
          EXISTS (SELECT 1 FROM responsavel_aluno ra WHERE ra.responsavel_id = r.id AND ra.aluno_id = f.aluno_id)
          OR EXISTS (SELECT 1 FROM alunos_responsaveis ar WHERE ar.responsavel_id = r.id AND ar.aluno_id = f.aluno_id)
        )
      )`;
    } else if (req.usuario.perfil === 'professor') {
      if (!req.usuario.professor_id) return res.status(403).json({ erro: 'Usuário sem vínculo com um professor.' });
      parametros.push(Number(req.usuario.professor_id));
      filtroAcesso = 'AND td.professor_id = $2';
    }
    const resultado = await pool.query(
      `SELECT j.arquivo_nome, j.nome_original, j.content_type
       FROM justificativas_falta j
       JOIN frequencias f ON f.id = j.frequencia_id
       JOIN turmas_disciplinas td ON td.id = f.turma_disciplina_id
       WHERE j.id = $1 ${filtroAcesso}`,
      parametros
    );
    if (resultado.rowCount === 0) return res.status(404).json({ erro: 'Documento não encontrado ou sem permissão.' });
    const documento = resultado.rows[0];
    const arquivo = path.join(__dirname, 'uploads', 'justificativas', path.basename(documento.arquivo_nome));
    res.set({
      'Cache-Control': 'private, no-store',
      'Content-Type': documento.content_type,
      'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(documento.nome_original)}`
    });
    return res.sendFile(arquivo, (erro) => {
      if (erro && !res.headersSent) {
        if (erro.statusCode === 404) return res.status(404).json({ erro: 'Arquivo não encontrado.' });
        console.error('Erro ao baixar justificativa:', erro.message);
        return res.status(500).json({ erro: 'Não foi possível baixar o documento.' });
      }
    });
  } catch (erro) {
    console.error('Erro ao consultar documento de justificativa:', erro.message);
    return res.status(500).json({ erro: 'Não foi possível baixar o documento.' });
  }
});

app.post('/api/avisos', autenticarToken, autorizar('admin','professor'), async (req, res) => {
  try {
    const { titulo, mensagem, turma_id } = req.body || {};
    if (!titulo || !mensagem) return res.status(400).json({ erro: 'Título e mensagem obrigatórios.' });
    const result = await pool.query(`INSERT INTO avisos (titulo, mensagem, turma_id, autor_id, publicado) VALUES ($1,$2,$3,$4,true) RETURNING id, titulo, mensagem, turma_id, criado_em`, [String(titulo).trim(), String(mensagem).trim(), turma_id ? Number(turma_id) : null, Number(req.usuario.sub)]);
    return res.status(201).json({ mensagem: 'Aviso publicado com sucesso.', aviso: result.rows[0] });
  } catch (e) { console.error(e); return res.status(500).json({ erro: 'Erro ao publicar aviso.' }); }
});

app.get('/api/avisos/meus', autenticarToken, autorizar('responsavel'), async (req, res) => {
  try {
    const usuarioId = Number(req.usuario.sub);
    const result = await pool.query(`SELECT av.id, av.titulo, av.mensagem, av.criado_em, t.nome as turma FROM avisos av LEFT JOIN turmas t ON t.id = av.turma_id WHERE av.publicado = true AND (av.turma_id IS NULL OR av.turma_id IN (SELECT m.turma_id FROM matriculas m JOIN responsavel_aluno ra ON ra.aluno_id = m.aluno_id JOIN responsaveis r ON r.id = ra.responsavel_id WHERE r.usuario_id = $1)) ORDER BY av.criado_em DESC LIMIT 50`, [usuarioId]);
    return res.json(result.rows);
  } catch (e) { console.error(e); return res.status(500).json({ erro: 'Erro ao buscar avisos.' }); }
});

// VÍNCULOS ADMIN
app.post('/api/turmas-disciplinas', autenticarToken, autorizar('admin'), async (req, res) => {
  try {
    const { turma_id, disciplina_id, professor_id } = req.body||{};
    if(!turma_id || !disciplina_id || !professor_id) return res.status(400).json({erro:'turma_id, disciplina_id e professor_id obrigatórios'});
    const existe = await pool.query('SELECT id FROM turmas_disciplinas WHERE turma_id=$1 AND disciplina_id=$2', [Number(turma_id), Number(disciplina_id)]);
    if(existe.rows.length>0){
      await pool.query('UPDATE turmas_disciplinas SET professor_id=$1 WHERE id=$2', [Number(professor_id), existe.rows[0].id]);
      return res.json({mensagem:'Vínculo atualizado', id: existe.rows[0].id});
    } else {
      const r = await pool.query('INSERT INTO turmas_disciplinas (turma_id, disciplina_id, professor_id) VALUES ($1,$2,$3) RETURNING id', [Number(turma_id), Number(disciplina_id), Number(professor_id)]);
      return res.status(201).json({mensagem:'Vínculo criado', id: r.rows[0].id});
    }
  }catch(e){ console.error(e); return res.status(500).json({erro:'Erro: '+e.message}); }
});

app.get('/api/turmas-disciplinas/todos', autenticarToken, autorizar('admin'), async (req, res) => {
  try{ const r = await pool.query(`SELECT td.id, t.nome as turma, d.nome as disciplina, p.nome as professor FROM turmas_disciplinas td JOIN turmas t ON t.id=td.turma_id JOIN disciplinas d ON d.id=td.disciplina_id LEFT JOIN professores p ON p.id=td.professor_id ORDER BY t.nome, d.nome`); return res.json(r.rows); }
  catch(e){ return res.status(500).json({erro:'Erro'}); }
});

app.post('/api/matriculas', autenticarToken, autorizar('admin'), async (req, res) => {
  try {
    const alunoId = Number(req.body?.aluno_id);
    const turmaId = Number(req.body?.turma_id);
    if (!Number.isSafeInteger(alunoId) || alunoId <= 0 || !Number.isSafeInteger(turmaId) || turmaId <= 0) {
      return res.status(400).json({ erro: 'Selecione um aluno e uma turma válidos.' });
    }
    const resultado = await pool.query(
      `INSERT INTO matriculas (aluno_id, turma_id)
       VALUES ($1, $2)
       ON CONFLICT (aluno_id) DO UPDATE SET turma_id = EXCLUDED.turma_id
       RETURNING id`,
      [alunoId, turmaId]
    );
    return res.status(201).json({ mensagem: 'Matrícula atualizada com sucesso.', id: resultado.rows[0].id });
  } catch (erro) {
    console.error('Erro ao matricular aluno:', erro.message);
    return res.status(500).json({ erro: 'Não foi possível matricular o aluno.' });
  }
});

app.get('/api/matriculas', autenticarToken, autorizar('admin'), async (req, res) => {
  try{ const r = await pool.query(`SELECT m.id, a.nome as aluno, t.nome as turma FROM matriculas m JOIN alunos a ON a.id=m.aluno_id JOIN turmas t ON t.id=m.turma_id ORDER BY t.nome, a.nome`); return res.json(r.rows); }
  catch(e){ return res.status(500).json({erro:'Erro'}); }
});

app.get('/api/disciplinas', autenticarToken, autorizar('admin','professor'), async (req, res) => {
  try { const r = await pool.query('SELECT id, nome FROM disciplinas ORDER BY nome'); return res.json(r.rows); }
  catch(e){ return res.status(500).json({erro:'Erro ao listar disciplinas'}); }
});
app.post('/api/disciplinas', autenticarToken, autorizar('admin'), async (req, res) => {
  try {
    const { nome } = req.body||{};
    if(!nome||!String(nome).trim()) return res.status(400).json({erro:'Nome obrigatório'});
    const r = await pool.query('INSERT INTO disciplinas (nome) VALUES ($1) RETURNING id, nome', [String(nome).trim()]);
    return res.status(201).json(r.rows[0]);
  } catch(e){ if(e.code==='23505') return res.status(409).json({erro:'Disciplina já existe'}); return res.status(500).json({erro:'Erro'}); }
});
app.delete('/api/disciplinas/:id', autenticarToken, autorizar('admin'), async (req, res) => {
  try { await pool.query('DELETE FROM disciplinas WHERE id=$1', [Number(req.params.id)]); return res.json({mensagem:'Removida'}); }
  catch(e){ return res.status(500).json({erro:'Erro'}); }
});
app.get('/api/professores', autenticarToken, autorizar('admin'), async (req, res) => {
  try { const r = await pool.query(`SELECT p.id, p.nome, u.email, u.ativo FROM professores p LEFT JOIN usuarios u ON u.professor_id = p.id ORDER BY p.nome`); return res.json(r.rows); }
  catch(e){ return res.status(500).json({erro:'Erro'}); }
});
app.post('/api/professores', autenticarToken, autorizar('admin'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { nome, email, senha } = req.body||{};
    if(!nome||!email||!senha) return res.status(400).json({erro:'Nome, email e senha obrigatórios'});
    await client.query('BEGIN');
    const prof = await client.query('INSERT INTO professores (nome) VALUES ($1) RETURNING id', [String(nome).trim()]);
    const hash = await bcrypt.hash(String(senha), 10);
    const user = await client.query('INSERT INTO usuarios (nome, email, senha_hash, perfil, professor_id, ativo) VALUES ($1,$2,$3,$4,$5,true) RETURNING id', [String(nome).trim(), String(email).toLowerCase().trim(), hash, 'professor', prof.rows[0].id]);
    await client.query('COMMIT');
    return res.status(201).json({mensagem:'Professor criado', professor_id: prof.rows[0].id, usuario_id: user.rows[0].id});
  } catch(e){ await client.query('ROLLBACK'); if(e.code==='23505') return res.status(409).json({erro:'E-mail já existe'}); return res.status(500).json({erro:'Erro'}); }
  finally { client.release(); }
});
app.get('/api/turmas-disciplinas/minhas', autenticarToken, autorizar('professor','admin'), async (req, res) => {
  try {
    const schema = await pool.query(`
      SELECT
        EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = current_schema()
            AND table_name = 'turmas_disciplinas'
            AND column_name = 'disciplina_id'
        ) AS tem_disciplina_id,
        to_regclass('disciplinas') IS NOT NULL AS tem_tabela_disciplinas
    `);
    const temDisciplina = schema.rows[0].tem_disciplina_id && schema.rows[0].tem_tabela_disciplinas;
    const disciplinaSelect = temDisciplina ? 'd.nome' : "'Disciplina não vinculada'";
    const disciplinaJoin = temDisciplina
      ? 'JOIN disciplinas d ON d.id = td.disciplina_id'
      : '';
    if(req.usuario.perfil==='admin'){
      const r = await pool.query(`SELECT td.id, t.nome as turma, ${disciplinaSelect} as disciplina, t.id as turma_id, p.nome as professor FROM turmas_disciplinas td JOIN turmas t ON t.id=td.turma_id ${disciplinaJoin} LEFT JOIN professores p ON p.id=td.professor_id ORDER BY t.nome, disciplina`);
      return res.json(r.rows);
    } else {
      const professorId = Number(req.usuario.professor_id);
      if (!Number.isSafeInteger(professorId) || professorId <= 0) {
        return res.status(403).json({ erro: 'Este usuário ainda não está vinculado a um professor.' });
      }
      const r = await pool.query(`SELECT td.id, t.nome as turma, ${disciplinaSelect} as disciplina, t.id as turma_id, p.nome as professor FROM turmas_disciplinas td JOIN turmas t ON t.id=td.turma_id ${disciplinaJoin} LEFT JOIN professores p ON p.id=td.professor_id WHERE td.professor_id=$1 ORDER BY t.nome, disciplina`, [professorId]);
      return res.json(r.rows);
    }
  } catch (erro) {
    console.error('Erro ao carregar turmas e disciplinas do professor:', erro.message);
    if (erro.code === '42P01' || erro.code === '42703') {
      return res.status(500).json({ erro: 'O banco de dados não possui todas as tabelas ou colunas necessárias para carregar as turmas. Confira a migração do banco no Render.' });
    }
    return res.status(500).json({ erro: 'Não foi possível carregar as turmas e disciplinas do professor.' });
  }
});
app.get('/api/alunos/:id', autenticarToken, async (req, res) => {
  try {
    const r = await pool.query(`SELECT a.*, t.nome as turma_nome, t.ano_letivo FROM alunos a LEFT JOIN matriculas m ON m.aluno_id=a.id LEFT JOIN turmas t ON t.id=m.turma_id WHERE a.id=$1`, [Number(req.params.id)]);
    if(r.rows.length===0) return res.status(404).json({erro:'Não encontrado'});
    return res.json(r.rows[0]);
  }catch(e){ return res.status(500).json({erro:'Erro'}); }
});

// ===== AJUSTE FINAL - GARANTIR COLUNAS + ROTAS RESPONSAVEIS =====
async function garantirColunasAvisos() {
  const checks = [
    { sql: `ALTER TABLE avisos ADD COLUMN IF NOT EXISTS aluno_id INTEGER REFERENCES alunos(id)`, msg: '✅ Coluna avisos.aluno_id verificada/criada' },
    { sql: `ALTER TABLE avisos ADD COLUMN IF NOT EXISTS autor_id INTEGER REFERENCES usuarios(id)`, msg: '✅ Coluna avisos.autor_id verificada' },
    { sql: `ALTER TABLE alunos ADD COLUMN IF NOT EXISTS foto_url TEXT`, msg: '✅ Coluna alunos.foto_url verificada/criada' },
    { sql: `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS foto_url TEXT`, msg: '✅ Coluna usuarios.foto_url verificada/criada' },
    { sql: `ALTER TABLE responsaveis ADD COLUMN IF NOT EXISTS telefone VARCHAR(20)`, msg: '✅ Coluna responsaveis.telefone verificada' },
    { sql: `ALTER TABLE responsaveis ADD COLUMN IF NOT EXISTS parentesco VARCHAR(50) DEFAULT 'responsável'`, msg: '✅ Coluna responsaveis.parentesco verificada' },
    { sql: `ALTER TABLE responsavel_aluno ADD COLUMN IF NOT EXISTS parentesco VARCHAR(50) DEFAULT 'responsável'`, msg: '✅ Coluna responsavel_aluno.parentesco verificada' },
    { sql: `ALTER TABLE alunos_responsaveis ADD COLUMN IF NOT EXISTS parentesco VARCHAR(50) DEFAULT 'responsável'`, msg: '✅ Coluna alunos_responsaveis.parentesco verificada' },
  ];
  for (const c of checks) {
    try {
      await pool.query(c.sql);
      console.log(c.msg);
    } catch(e) {
      console.log(`Erro ao verificar: ${c.msg} -> ${e.message}`);
    }
  }
  // garante unique para ON CONFLICT funcionar
  try { await pool.query(`ALTER TABLE responsavel_aluno ADD CONSTRAINT IF NOT EXISTS uniq_resp_aluno UNIQUE (responsavel_id, aluno_id)`); } catch {}
  try { await pool.query(`ALTER TABLE alunos_responsaveis ADD CONSTRAINT IF NOT EXISTS uniq_alunos_resp UNIQUE (responsavel_id, aluno_id)`); } catch {}
  try { await pool.query(`ALTER TABLE responsavel_aluno ADD CONSTRAINT IF NOT EXISTS uniq_resp_aluno2 UNIQUE (aluno_id, responsavel_id)`); } catch {}
  console.log('✅ Coluna parentesco verificada/criada');
}

async function garantirColunasAlunos() {
  await pool.query('ALTER TABLE alunos ADD COLUMN IF NOT EXISTS data_nascimento DATE');
  console.log('Coluna alunos.data_nascimento verificada/criada.');
}

async function garantirResponsaveis() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(`
      INSERT INTO responsaveis (usuario_id, parentesco)
      SELECT u.id, 'responsável'
      FROM usuarios u
      WHERE u.perfil = 'responsavel'
        AND NOT EXISTS (
          SELECT 1 FROM responsaveis r WHERE r.usuario_id = u.id
        )
    `);
    await client.query('COMMIT');
    console.log(`Registros de responsáveis verificados; ${result.rowCount} conta(s) regularizada(s).`);
  } catch (erro) {
    try {
      await client.query('ROLLBACK');
    } catch (erroRollback) {
      console.error('Erro ao cancelar a migração de responsáveis:', erroRollback.message);
    }
    console.error('Erro ao preparar os registros de responsáveis:', erro.message);
    throw erro;
  } finally {
    client.release();
  }
}

async function garantirTabelaProfessores() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      CREATE TABLE IF NOT EXISTS professores (
        id BIGSERIAL PRIMARY KEY,
        nome VARCHAR(150) NOT NULL,
        email VARCHAR(180),
        ativo BOOLEAN NOT NULL DEFAULT TRUE,
        criado_em TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await client.query(`
      INSERT INTO professores (id, nome)
      OVERRIDING SYSTEM VALUE
      SELECT DISTINCT ON (professor_id)
             professor_id,
             COALESCE(NULLIF(BTRIM(nome), ''), 'Professor ' || professor_id)
      FROM usuarios
      WHERE perfil = 'professor' AND professor_id IS NOT NULL AND professor_id > 0
      ORDER BY professor_id, id
      ON CONFLICT (id) DO NOTHING
    `);

    const sequence = await client.query(
      "SELECT pg_get_serial_sequence('professores', 'id') AS nome"
    );
    if (sequence.rows[0].nome) {
      const sequenceState = await client.query(
        `SELECT last_value, is_called FROM ${sequence.rows[0].nome}`
      );
      const maxId = await client.query('SELECT COALESCE(MAX(id), 0) AS id FROM professores');
      const currentValue = Number(sequenceState.rows[0].last_value);
      const highestId = Number(maxId.rows[0].id);
      if (highestId > currentValue || (!sequenceState.rows[0].is_called && highestId === currentValue)) {
        await client.query('SELECT setval($1::regclass, $2, true)', [sequence.rows[0].nome, highestId]);
      }
    }

    await client.query('COMMIT');
    console.log('Tabela de professores verificada; vínculos existentes preservados.');
  } catch (erro) {
    try {
      await client.query('ROLLBACK');
    } catch (erroRollback) {
      console.error('Erro ao cancelar a migração da tabela de professores:', erroRollback.message);
    }
    console.error('Erro ao preparar a tabela de professores:', erro.message);
    throw erro;
  } finally {
    client.release();
  }
}

async function garantirTabelasFrequencias() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS frequencias (
      id BIGSERIAL PRIMARY KEY,
      aluno_id INTEGER NOT NULL REFERENCES alunos(id),
      turma_disciplina_id INTEGER NOT NULL REFERENCES turmas_disciplinas(id),
      data DATE NOT NULL,
      presente BOOLEAN NOT NULL,
      detalhes TEXT NOT NULL DEFAULT '',
      professor_id INTEGER REFERENCES professores(id),
      criado_em TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      atualizado_em TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (aluno_id, turma_disciplina_id, data)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS justificativas_falta (
      id BIGSERIAL PRIMARY KEY,
      frequencia_id BIGINT NOT NULL REFERENCES frequencias(id) ON DELETE CASCADE,
      usuario_id INTEGER NOT NULL REFERENCES usuarios(id),
      nome_original VARCHAR(180) NOT NULL,
      arquivo_nome VARCHAR(80) NOT NULL UNIQUE,
      content_type VARCHAR(40) NOT NULL,
      criado_em TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_frequencias_turma_data_aluno ON frequencias (turma_disciplina_id, data, aluno_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_justificativas_falta_frequencia ON justificativas_falta (frequencia_id)`);
  console.log('✅ Tabelas de frequência e justificativas verificadas/criadas');
}

app.get('/api/alunos/:id/responsaveis', autenticarToken, autorizar('admin','professor'), async (req,res)=>{
  try{
    const alunoId = parseInt(req.params.id);
    const result = await pool.query(`
      SELECT r.id, u.nome, u.email as usuario_email, r.telefone, 
             COALESCE(ra.parentesco, r.parentesco, 'Responsável') as parentesco
      FROM responsavel_aluno ra
      JOIN responsaveis r ON r.id = ra.responsavel_id
      JOIN usuarios u ON u.id = r.usuario_id
      WHERE ra.aluno_id = $1
      UNION
      SELECT r.id, u.nome, u.email as usuario_email, r.telefone,
             COALESCE(ar.parentesco, r.parentesco, 'Responsável') as parentesco
      FROM alunos_responsaveis ar
      JOIN responsaveis r ON r.id = ar.responsavel_id
      JOIN usuarios u ON u.id = r.usuario_id
      WHERE ar.aluno_id = $1
    `, [alunoId]);
    return res.json(result.rows);
  }catch(e){
    console.error('Erro buscar responsaveis do aluno', e.message);
    return res.status(500).json({erro:'Erro ao buscar responsáveis', detalhe: e.message});
  }
});

app.post('/api/alunos/:id/responsaveis', autenticarToken, autorizar('admin'), async (req,res)=>{
  try{
    const alunoId = parseInt(req.params.id);
    const { responsavel_id, parentesco } = req.body || {};
    if(!responsavel_id) return res.status(400).json({erro:'responsavel_id obrigatório'});
    const parentescoFinal = parentesco || 'responsável';
    await pool.query(`INSERT INTO responsavel_aluno (responsavel_id, aluno_id, parentesco) VALUES ($1,$2,$3) ON CONFLICT (responsavel_id, aluno_id) DO UPDATE SET parentesco = EXCLUDED.parentesco`, [Number(responsavel_id), alunoId, parentescoFinal]);
    await pool.query(`INSERT INTO alunos_responsaveis (responsavel_id, aluno_id, parentesco) VALUES ($1,$2,$3) ON CONFLICT (responsavel_id, aluno_id) DO UPDATE SET parentesco = EXCLUDED.parentesco`, [Number(responsavel_id), alunoId, parentescoFinal]).catch(()=>{});
    return res.json({ mensagem: 'Responsável vinculado com sucesso', parentesco: parentescoFinal });
  }catch(e){
    console.error('Erro vincular responsavel', e.message);
    return res.status(500).json({erro:'Erro ao vincular responsável', detalhe: e.message});
  }
});

app.delete('/api/alunos/:id/responsaveis/:responsavel_id', autenticarToken, autorizar('admin'), async (req,res)=>{
  try{
    const alunoId = parseInt(req.params.id);
    const respId = parseInt(req.params.responsavel_id);
    await pool.query(`DELETE FROM responsavel_aluno WHERE aluno_id=$1 AND responsavel_id=$2`, [alunoId, respId]);
    await pool.query(`DELETE FROM alunos_responsaveis WHERE aluno_id=$1 AND responsavel_id=$2`, [alunoId, respId]).catch(()=>{});
    return res.json({ mensagem: 'Vínculo removido' });
  }catch(e){
    return res.status(500).json({erro:'Erro ao remover vínculo'});
  }
});

app.get('/api/responsaveis/lista', autenticarToken, autorizar('admin','professor'), async (req,res)=>{
  try{
    const result = await pool.query(`SELECT r.id, u.nome, u.email as usuario_email, r.telefone, r.parentesco FROM responsaveis r JOIN usuarios u ON u.id = r.usuario_id WHERE u.ativo = true ORDER BY u.nome`);
    return res.json(result.rows);
  }catch(e){
    console.error(e);
    return res.status(500).json({erro:'Erro'});
  }
});


// ===== NOVO: ADMIN ALTERAR TELEFONE E PARENTESCO DO RESPONSÁVEL =====
app.put('/api/responsaveis/:id', autenticarToken, autorizar('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { telefone, parentesco, nome, email } = req.body || {};
    if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ erro: 'ID inválido' });

    // normaliza telefone
    let telNorm;
    if (telefone !== undefined) {
      if (telefone === '' || telefone === null) telNorm = null;
      else {
        let n = String(telefone).replace(/\D/g,'');
        if (n.startsWith('0')) n = n.slice(1);
        if (n.length === 11) n = '55'+n;
        if (!/^55\d{10,11}$/.test(n)) return res.status(400).json({ erro: 'Telefone inválido. Use DDD + número' });
        telNorm = n;
      }
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      if (telefone !== undefined || parentesco !== undefined) {
        let set = [];
        let params = [];
        let idx = 1;
        if (telNorm !== undefined) { set.push(`telefone = $${idx++}`); params.push(telNorm); }
        if (parentesco !== undefined) { set.push(`parentesco = $${idx++}`); params.push(String(parentesco).trim() || 'responsável'); }
        if (set.length > 0) {
          params.push(id);
          await client.query(`UPDATE responsaveis SET ${set.join(', ')} WHERE id = $${idx}`, params);
        }
      }
      if (nome !== undefined || email !== undefined) {
        const u = await client.query(`SELECT usuario_id FROM responsaveis WHERE id=$1`, [id]);
        if (u.rowCount === 0) throw new Error('Responsável não encontrado');
        if (nome !== undefined && String(nome).trim()) {
          await client.query(`UPDATE usuarios SET nome=$1 WHERE id=$2`, [String(nome).trim(), u.rows[0].usuario_id]);
        }
        if (email !== undefined && String(email).trim()) {
          await client.query(`UPDATE usuarios SET email=$1 WHERE id=$2`, [String(email).toLowerCase().trim(), u.rows[0].usuario_id]);
        }
      }
      await client.query('COMMIT');
      const r = await pool.query(`SELECT r.id, u.nome, u.email, r.telefone, r.parentesco FROM responsaveis r JOIN usuarios u ON u.id=r.usuario_id WHERE r.id=$1`, [id]);
      return res.json({ mensagem: 'Responsável atualizado', responsavel: r.rows[0] });
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally { client.release(); }
  } catch (e) {
    console.error('Erro atualizar responsável:', e.message);
    return res.status(500).json({ erro: 'Erro ao atualizar responsável', detalhe: e.message });
  }
});

// ADMIN pode alterar só o vínculo aluno-responsável (parentesco específico daquele aluno)
app.put('/api/alunos/:aluno_id/responsaveis/:responsavel_id', autenticarToken, autorizar('admin'), async (req, res) => {
  try {
    const alunoId = Number(req.params.aluno_id);
    const respId = Number(req.params.responsavel_id);
    const { parentesco } = req.body || {};
    if (!parentesco) return res.status(400).json({ erro: 'Informe o parentesco' });
    await pool.query(`UPDATE responsavel_aluno SET parentesco=$1 WHERE aluno_id=$2 AND responsavel_id=$3`, [String(parentesco).trim(), alunoId, respId]);
    await pool.query(`UPDATE alunos_responsaveis SET parentesco=$1 WHERE aluno_id=$2 AND responsavel_id=$3`, [String(parentesco).trim(), alunoId, respId]).catch(()=>{});
    return res.json({ mensagem: 'Parentesco atualizado' });
  } catch (e) {
    return res.status(500).json({ erro: 'Erro ao atualizar parentesco' });
  }
});

// ===== NOVO: RESPONSÁVEL ALTERA O PRÓPRIO TELEFONE =====
app.get('/api/responsavel/meu-perfil', autenticarToken, autorizar('responsavel','admin'), async (req, res) => {
  try {
    const usuarioId = Number(req.usuario.sub);
    const r = await pool.query(`SELECT r.id, u.nome, u.email, r.telefone, r.parentesco FROM responsaveis r JOIN usuarios u ON u.id=r.usuario_id WHERE r.usuario_id=$1`, [usuarioId]);
    if (r.rowCount === 0) return res.status(404).json({ erro: 'Responsável não encontrado' });
    return res.json(r.rows[0]);
  } catch (e) { return res.status(500).json({ erro: 'Erro ao buscar perfil' }); }
});

app.put('/api/responsavel/meu-perfil', autenticarToken, autorizar('responsavel'), async (req, res) => {
  try {
    const usuarioId = Number(req.usuario.sub);
    const { telefone, nome } = req.body || {};
    if (!telefone && !nome) return res.status(400).json({ erro: 'Informe telefone ou nome' });

    let telNorm = null;
    if (telefone !== undefined) {
      let n = String(telefone).replace(/\D/g,'');
      if (n.startsWith('0')) n = n.slice(1);
      if (n.length === 11) n = '55'+n;
      if (n.length < 10) return res.status(400).json({ erro: 'Telefone inválido. Use DDD + número. Ex: 21999998888' });
      telNorm = n;
    }

    if (telNorm) {
      await pool.query(`UPDATE responsaveis SET telefone=$1 WHERE usuario_id=$2`, [telNorm, usuarioId]);
    }
    if (nome && String(nome).trim()) {
      await pool.query(`UPDATE usuarios SET nome=$1 WHERE id=$2`, [String(nome).trim(), usuarioId]);
    }

    const r = await pool.query(`SELECT r.id, u.nome, u.email, r.telefone FROM responsaveis r JOIN usuarios u ON u.id=r.usuario_id WHERE r.usuario_id=$1`, [usuarioId]);
    return res.json({ mensagem: 'Perfil atualizado com sucesso', perfil: r.rows[0] });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ erro: 'Erro ao atualizar perfil' });
  }
});

app.listen(PORT, async () => {
    console.log(`Servidor iniciado em http://localhost:${PORT}`);
    await garantirColunasAvisos();
    await garantirColunasAlunos();
    await garantirResponsaveis();
    await garantirTabelaProfessores();
    await garantirTabelasFrequencias();
});
