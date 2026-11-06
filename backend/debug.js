require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST, port: Number(process.env.DB_PORT||5432),
  database: process.env.DB_NAME, user: process.env.DB_USER,
  password: String(process.env.DB_PASSWORD)
});
(async()=>{
  const r = await pool.query("SELECT r.id, u.nome, r.telefone FROM responsaveis r JOIN usuarios u ON u.id=r.usuario_id ORDER BY r.id");
  console.table(r.rows);
  await pool.end();
})();
