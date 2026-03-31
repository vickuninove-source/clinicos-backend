 const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Conexão com banco de dados
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Criar tabelas automaticamente
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
      criado_em TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS consultas (
      id SERIAL PRIMARY KEY,
      clinica_id INTEGER REFERENCES clinicas(id),
      paciente_id INTEGER REFERENCES pacientes(id),
      data_hora TIMESTAMP NOT NULL,
      procedimento VARCHAR(255),
      status VARCHAR(50) DEFAULT 'agendada',
      criado_em TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ Tabelas criadas!');
}

// ── ROTAS DE AUTENTICAÇÃO ──

// Registro de nova clínica
app.post('/api/registro', async (req, res) => {
  const { nome, email, senha, especialidade } = req.body;
  try {
    const hash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO clinicas (nome, email, senha, especialidade) VALUES ($1, $2, $3, $4) RETURNING id, nome, email, plano',
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

// Login
app.post('/api/login', async (req, res) => {
  const { email, senha } = req.body;
  try {
    const result = await pool.query('SELECT * FROM clinicas WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
    const clinica = result.rows[0];
    const ok = await bcrypt.compare(senha, clinica.senha);
    if (!ok) return res.status(401).json({ erro: 'E-mail ou senha incorretos' });
    const token = jwt.sign({ id: clinica.id, email: clinica.email }, process.env.JWT_SECRET || 'clinicos-secret', { expiresIn: '7d' });
    res.json({ token, clinica: { id: clinica.id, nome: clinica.nome, email: clinica.email, plano: clinica.plano } });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao fazer login' });
  }
});

// Middleware de autenticação
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

// ── ROTAS DE PACIENTES ──

app.get('/api/pacientes', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM pacientes WHERE clinica_id = $1 ORDER BY nome', [req.clinica.id]);
  res.json(result.rows);
});

app.post('/api/pacientes', auth, async (req, res) => {
  const { nome, telefone, email, data_nascimento } = req.body;
  const result = await pool.query(
    'INSERT INTO pacientes (clinica_id, nome, telefone, email, data_nascimento) VALUES ($1, $2, $3, $4, $5) RETURNING *',
    [req.clinica.id, nome, telefone, email, data_nascimento]
  );
  res.json(result.rows[0]);
});

// ── ROTAS DE CONSULTAS ──

app.get('/api/consultas', auth, async (req, res) => {
  const result = await pool.query(
    'SELECT c.*, p.nome as paciente_nome FROM consultas c JOIN pacientes p ON c.paciente_id = p.id WHERE c.clinica_id = $1 ORDER BY c.data_hora',
    [req.clinica.id]
  );
  res.json(result.rows);
});

app.post('/api/consultas', auth, async (req, res) => {
  const { paciente_id, data_hora, procedimento } = req.body;
  const result = await pool.query(
    'INSERT INTO consultas (clinica_id, paciente_id, data_hora, procedimento) VALUES ($1, $2, $3, $4) RETURNING *',
    [req.clinica.id, paciente_id, data_hora, procedimento]
  );
  res.json(result.rows[0]);
});

// Inicia servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, async () => {
  await initDB();
  console.log(`🦷 ClinicOS Backend rodando na porta ${PORT}`);
});
