const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS clinicas (
      id SERIAL PRIMARY KEY,
      nome VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      senha VARCHAR(255) NOT NULL,
      especialidade VARCHAR(100),
      plano VARCHAR(50) DEFAULT 'starter',
      criado_em TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pacientes (
      id SERIAL PRIMARY KEY,
      clinica_id INTEGER REFERENCES clinicas(id),
      nome VARCHAR(255) NOT NULL,
      telefone VARCHAR(20),
      email VARCHAR(255),
      data_nascimento DATE,
      cpf VARCHAR(20),
      rg VARCHAR(20),
      endereco TEXT,
      prontuario TEXT,
      medicamentos TEXT,
      alergias TEXT,
      observacoes TEXT,
      criado_em TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS procedimentos (
      id SERIAL PRIMARY KEY,
      clinica_id INTEGER REFERENCES clinicas(id),
      nome VARCHAR(255) NOT NULL,
      descricao TEXT,
      preco DECIMAL(10,2) DEFAULT 0,
      duracao_minutos INTEGER DEFAULT 60,
      criado_em TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS consultas (
      id SERIAL PRIMARY KEY,
      clinica_id INTEGER REFERENCES clinicas(id),
      paciente_id INTEGER REFERENCES pacientes(id),
      procedimento_id INTEGER REFERENCES procedimentos(id),
      data_hora TIMESTAMP NOT NULL,
      procedimento VARCHAR(255),
      status VARCHAR(50) DEFAULT 'agendada',
      observacoes TEXT,
      valor DECIMAL(10,2) DEFAULT 0,
      criado_em TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS orcamentos (
      id SERIAL PRIMARY KEY,
      clinica_id INTEGER REFERENCES clinicas(id),
      paciente_id INTEGER REFERENCES pacientes(id),
      descricao TEXT,
      valor_total DECIMAL(10,2) DEFAULT 0,
      status VARCHAR(50) DEFAULT 'pendente',
      validade DATE,
      criado_em TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS orcamento_itens (
      id SERIAL PRIMARY KEY,
      orcamento_id INTEGER REFERENCES orcamentos(id) ON DELETE CASCADE,
      procedimento_id INTEGER REFERENCES procedimentos(id),
      descricao VARCHAR(255),
      quantidade INTEGER DEFAULT 1,
      valor_unitario DECIMAL(10,2) DEFAULT 0,
      valor_total DECIMAL(10,2) DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS financeiro (
      id SERIAL PRIMARY KEY,
      clinica_id INTEGER REFERENCES clinicas(id),
      tipo VARCHAR(20) NOT NULL,
      descricao VARCHAR(255) NOT NULL,
      valor DECIMAL(10,2) NOT NULL,
      categoria VARCHAR(100),
      data_lancamento DATE DEFAULT CURRENT_DATE,
      paciente_id INTEGER REFERENCES pacientes(id),
      consulta_id INTEGER REFERENCES consultas(id),
      criado_em TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS estoque (
      id SERIAL PRIMARY KEY,
      clinica_id INTEGER REFERENCES clinicas(id),
      nome VARCHAR(255) NOT NULL,
      descricao TEXT,
      quantidade INTEGER DEFAULT 0,
      quantidade_minima INTEGER DEFAULT 5,
      unidade VARCHAR(50),
      preco_custo DECIMAL(10,2) DEFAULT 0,
      criado_em TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS retornos (
      id SERIAL PRIMARY KEY,
      clinica_id INTEGER REFERENCES clinicas(id),
      paciente_id INTEGER REFERENCES pacientes(id),
      consulta_id INTEGER REFERENCES consultas(id),
      data_retorno DATE NOT NULL,
      motivo VARCHAR(255),
      status VARCHAR(50) DEFAULT 'pendente',
      observacoes TEXT,
      criado_em TIMESTAMP DEFAULT NOW()
    );
  `);
  // Adiciona colunas novas se não existirem
  const alterations = [
    "ALTER TABLE pacientes ADD COLUMN IF NOT EXISTS rg VARCHAR(20)",
    "ALTER TABLE pacientes ADD COLUMN IF NOT EXISTS prontuario TEXT",
    "ALTER TABLE pacientes ADD COLUMN IF NOT EXISTS medicamentos TEXT",
    "ALTER TABLE pacientes ADD COLUMN IF NOT EXISTS alergias TEXT",
  ];
  for (const sql of alterations) {
    await pool.query(sql).catch(() => {});
  }
  console.log('✅ Tabelas criadas!');
}

// MIDDLEWARE AUTH
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Não autorizado' });
  try {
    req.clinica = jwt.verify(token, process.env.JWT_SECRET || 'clinicos-secret');
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido' });
  }
}

// ── AUTH ──
app.post('/api/registro', async (req, res) => {
  const { nome, email, senha, especialidade } = req.body;
  try {
    const hash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO clinicas (nome, email, senha, especialidade) VALUES ($1, $2, $3, $4) RETURNING id, nome, email, plano, especialidade',
      [nome, email, hash, especialidade]
    );
    const clinica = result.rows[0];
    const token = jwt.sign({ id: clinica.id, email: clinica.email }, process.env.JWT_SECRET || 'clinicos-secret', { expiresIn: '7d' });
    res.json({ token, clinica });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ erro: 'E-mail já cadastrado' });
    res.status(500).json({ erro: 'Erro ao criar conta' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, senha } = req.body;
  try {
    const result = await pool.query('SELECT * FROM clinicas WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
    const clinica = result.rows[0];
    const ok = await bcrypt.compare(senha, clinica.senha);
    if (!ok) return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
    const token = jwt.sign({ id: clinica.id, email: clinica.email }, process.env.JWT_SECRET || 'clinicos-secret', { expiresIn: '7d' });
    res.json({ token, clinica: { id: clinica.id, nome: clinica.nome, email: clinica.email, plano: clinica.plano, especialidade: clinica.especialidade } });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

// ── PACIENTES ──
app.get('/api/pacientes', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM pacientes WHERE clinica_id = $1 ORDER BY nome', [req.clinica.id]);
  res.json(result.rows);
});

app.post('/api/pacientes', auth, async (req, res) => {
  const { nome, telefone, email, data_nascimento, cpf, rg, endereco, prontuario, medicamentos, alergias, observacoes } = req.body;
  const result = await pool.query(
    'INSERT INTO pacientes (clinica_id, nome, telefone, email, data_nascimento, cpf, rg, endereco, prontuario, medicamentos, alergias, observacoes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *',
    [req.clinica.id, nome, telefone, email, data_nascimento, cpf, rg, endereco, prontuario, medicamentos, alergias, observacoes]
  );
  res.json(result.rows[0]);
});

app.put('/api/pacientes/:id', auth, async (req, res) => {
  const { nome, telefone, email, data_nascimento, cpf, rg, endereco, prontuario, medicamentos, alergias, observacoes } = req.body;
  const result = await pool.query(
    'UPDATE pacientes SET nome=$1, telefone=$2, email=$3, data_nascimento=$4, cpf=$5, rg=$6, endereco=$7, prontuario=$8, medicamentos=$9, alergias=$10, observacoes=$11 WHERE id=$12 AND clinica_id=$13 RETURNING *',
    [nome, telefone, email, data_nascimento, cpf, rg, endereco, prontuario, medicamentos, alergias, observacoes, req.params.id, req.clinica.id]
  );
  res.json(result.rows[0]);
});

app.delete('/api/pacientes/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM pacientes WHERE id=$1 AND clinica_id=$2', [req.params.id, req.clinica.id]);
  res.json({ ok: true });
});

// ── PROCEDIMENTOS ──
app.get('/api/procedimentos', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM procedimentos WHERE clinica_id = $1 ORDER BY nome', [req.clinica.id]);
  res.json(result.rows);
});

app.post('/api/procedimentos', auth, async (req, res) => {
  const { nome, descricao, preco, duracao_minutos } = req.body;
  const result = await pool.query(
    'INSERT INTO procedimentos (clinica_id, nome, descricao, preco, duracao_minutos) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [req.clinica.id, nome, descricao, preco || 0, duracao_minutos || 60]
  );
  res.json(result.rows[0]);
});

app.put('/api/procedimentos/:id', auth, async (req, res) => {
  const { nome, descricao, preco, duracao_minutos } = req.body;
  const result = await pool.query(
    'UPDATE procedimentos SET nome=$1, descricao=$2, preco=$3, duracao_minutos=$4 WHERE id=$5 AND clinica_id=$6 RETURNING *',
    [nome, descricao, preco, duracao_minutos, req.params.id, req.clinica.id]
  );
  res.json(result.rows[0]);
});

app.delete('/api/procedimentos/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM procedimentos WHERE id=$1 AND clinica_id=$2', [req.params.id, req.clinica.id]);
  res.json({ ok: true });
});

// ── CONSULTAS ──
app.get('/api/consultas', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT c.*, p.nome as paciente_nome, pr.nome as procedimento_nome
     FROM consultas c
     JOIN pacientes p ON c.paciente_id = p.id
     LEFT JOIN procedimentos pr ON c.procedimento_id = pr.id
     WHERE c.clinica_id = $1 ORDER BY c.data_hora DESC`,
    [req.clinica.id]
  );
  res.json(result.rows);
});

app.post('/api/consultas', auth, async (req, res) => {
  const { paciente_id, procedimento_id, data_hora, procedimento, observacoes, valor } = req.body;
  const result = await pool.query(
    'INSERT INTO consultas (clinica_id, paciente_id, procedimento_id, data_hora, procedimento, observacoes, valor) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [req.clinica.id, paciente_id, procedimento_id || null, data_hora, procedimento, observacoes, valor || 0]
  );
  res.json(result.rows[0]);
});

app.put('/api/consultas/:id', auth, async (req, res) => {
  const { status, observacoes, valor } = req.body;
  const result = await pool.query(
    'UPDATE consultas SET status=$1, observacoes=$2, valor=$3 WHERE id=$4 AND clinica_id=$5 RETURNING *',
    [status, observacoes, valor, req.params.id, req.clinica.id]
  );
  res.json(result.rows[0]);
});

// ── ORÇAMENTOS ──
app.get('/api/orcamentos', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT o.*, p.nome as paciente_nome FROM orcamentos o
     JOIN pacientes p ON o.paciente_id = p.id
     WHERE o.clinica_id = $1 ORDER BY o.criado_em DESC`,
    [req.clinica.id]
  );
  res.json(result.rows);
});

app.post('/api/orcamentos', auth, async (req, res) => {
  const { paciente_id, descricao, itens, validade } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const valor_total = itens?.reduce((s, i) => s + (i.valor_unitario * i.quantidade), 0) || 0;
    const orcResult = await client.query(
      'INSERT INTO orcamentos (clinica_id, paciente_id, descricao, valor_total, validade) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.clinica.id, paciente_id, descricao, valor_total, validade || null]
    );
    const orc = orcResult.rows[0];
    if (itens?.length) {
      for (const item of itens) {
        await client.query(
          'INSERT INTO orcamento_itens (orcamento_id, procedimento_id, descricao, quantidade, valor_unitario, valor_total) VALUES ($1,$2,$3,$4,$5,$6)',
          [orc.id, item.procedimento_id || null, item.descricao, item.quantidade, item.valor_unitario, item.quantidade * item.valor_unitario]
        );
      }
    }
    await client.query('COMMIT');
    res.json(orc);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ erro: 'Erro ao criar orçamento' });
  } finally {
    client.release();
  }
});

app.get('/api/orcamentos/:id/itens', auth, async (req, res) => {
  const result = await pool.query(
    'SELECT oi.*, p.nome as procedimento_nome FROM orcamento_itens oi LEFT JOIN procedimentos p ON oi.procedimento_id = p.id WHERE oi.orcamento_id = $1',
    [req.params.id]
  );
  res.json(result.rows);
});

app.put('/api/orcamentos/:id/status', auth, async (req, res) => {
  const { status } = req.body;
  const result = await pool.query(
    'UPDATE orcamentos SET status=$1 WHERE id=$2 AND clinica_id=$3 RETURNING *',
    [status, req.params.id, req.clinica.id]
  );
  res.json(result.rows[0]);
});

// ── FINANCEIRO ──
app.get('/api/financeiro', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT f.*, p.nome as paciente_nome FROM financeiro f
     LEFT JOIN pacientes p ON f.paciente_id = p.id
     WHERE f.clinica_id = $1 ORDER BY f.data_lancamento DESC`,
    [req.clinica.id]
  );
  res.json(result.rows);
});

app.post('/api/financeiro', auth, async (req, res) => {
  const { tipo, descricao, valor, categoria, data_lancamento, paciente_id } = req.body;
  const result = await pool.query(
    'INSERT INTO financeiro (clinica_id, tipo, descricao, valor, categoria, data_lancamento, paciente_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [req.clinica.id, tipo, descricao, valor, categoria, data_lancamento || new Date(), paciente_id || null]
  );
  res.json(result.rows[0]);
});

app.delete('/api/financeiro/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM financeiro WHERE id=$1 AND clinica_id=$2', [req.params.id, req.clinica.id]);
  res.json({ ok: true });
});

app.get('/api/financeiro/resumo', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT
      COALESCE(SUM(CASE WHEN tipo='receita' THEN valor ELSE 0 END), 0) as total_receitas,
      COALESCE(SUM(CASE WHEN tipo='despesa' THEN valor ELSE 0 END), 0) as total_despesas
     FROM financeiro WHERE clinica_id=$1 AND EXTRACT(MONTH FROM data_lancamento)=EXTRACT(MONTH FROM NOW())`,
    [req.clinica.id]
  );
  res.json(result.rows[0]);
});

// ── ESTOQUE ──
app.get('/api/estoque', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM estoque WHERE clinica_id = $1 ORDER BY nome', [req.clinica.id]);
  res.json(result.rows);
});

app.post('/api/estoque', auth, async (req, res) => {
  const { nome, descricao, quantidade, quantidade_minima, unidade, preco_custo } = req.body;
  const result = await pool.query(
    'INSERT INTO estoque (clinica_id, nome, descricao, quantidade, quantidade_minima, unidade, preco_custo) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [req.clinica.id, nome, descricao, quantidade || 0, quantidade_minima || 5, unidade, preco_custo || 0]
  );
  res.json(result.rows[0]);
});

app.put('/api/estoque/:id', auth, async (req, res) => {
  const { nome, descricao, quantidade, quantidade_minima, unidade, preco_custo } = req.body;
  const result = await pool.query(
    'UPDATE estoque SET nome=$1, descricao=$2, quantidade=$3, quantidade_minima=$4, unidade=$5, preco_custo=$6 WHERE id=$7 AND clinica_id=$8 RETURNING *',
    [nome, descricao, quantidade, quantidade_minima, unidade, preco_custo, req.params.id, req.clinica.id]
  );
  res.json(result.rows[0]);
});

app.delete('/api/estoque/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM estoque WHERE id=$1 AND clinica_id=$2', [req.params.id, req.clinica.id]);
  res.json({ ok: true });
});

// ── RETORNOS ──
app.get('/api/retornos', auth, async (req, res) => {
  const result = await pool.query(
    `SELECT r.*, p.nome as paciente_nome FROM retornos r
     JOIN pacientes p ON r.paciente_id = p.id
     WHERE r.clinica_id = $1 ORDER BY r.data_retorno ASC`,
    [req.clinica.id]
  );
  res.json(result.rows);
});

app.post('/api/retornos', auth, async (req, res) => {
  const { paciente_id, consulta_id, data_retorno, motivo, observacoes } = req.body;
  const result = await pool.query(
    'INSERT INTO retornos (clinica_id, paciente_id, consulta_id, data_retorno, motivo, observacoes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [req.clinica.id, paciente_id, consulta_id || null, data_retorno, motivo, observacoes]
  );
  res.json(result.rows[0]);
});

app.put('/api/retornos/:id/status', auth, async (req, res) => {
  const { status } = req.body;
  const result = await pool.query(
    'UPDATE retornos SET status=$1 WHERE id=$2 AND clinica_id=$3 RETURNING *',
    [status, req.params.id, req.clinica.id]
  );
  res.json(result.rows[0]);
});

// ── DASHBOARD STATS ──
app.get('/api/stats', auth, async (req, res) => {
  const [pacientes, consultas, retornos, financeiro] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM pacientes WHERE clinica_id=$1', [req.clinica.id]),
    pool.query("SELECT COUNT(*) FROM consultas WHERE clinica_id=$1 AND DATE(data_hora)=CURRENT_DATE", [req.clinica.id]),
    pool.query("SELECT COUNT(*) FROM retornos WHERE clinica_id=$1 AND status='pendente'", [req.clinica.id]),
    pool.query("SELECT COALESCE(SUM(CASE WHEN tipo='receita' THEN valor ELSE 0 END),0) as receitas, COALESCE(SUM(CASE WHEN tipo='despesa' THEN valor ELSE 0 END),0) as despesas FROM financeiro WHERE clinica_id=$1 AND EXTRACT(MONTH FROM data_lancamento)=EXTRACT(MONTH FROM NOW())", [req.clinica.id])
  ]);
  res.json({
    total_pacientes: parseInt(pacientes.rows[0].count),
    consultas_hoje: parseInt(consultas.rows[0].count),
    retornos_pendentes: parseInt(retornos.rows[0].count),
    receitas_mes: parseFloat(financeiro.rows[0].receitas),
    despesas_mes: parseFloat(financeiro.rows[0].despesas)
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, async () => {
  await initDB();
  console.log(`🦷 ClinicOS Backend rodando na porta ${PORT}`);
});