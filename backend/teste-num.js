require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST, port: Number(process.env.DB_PORT||5432),
  database: process.env.DB_NAME, user: process.env.DB_USER,
  password: String(process.env.DB_PASSWORD)
});
(async()=>{
  // TROCA AQUI PELO NÚMERO REAL QUE VOCÊ QUER TESTAR - com 55
  const numeroTeste = '5521SEUNUMEROAQUI';
  await pool.query("UPDATE responsaveis SET telefone=$1 WHERE id=5", [numeroTeste]);
  console.log("Sônia atualizada para " + numeroTeste);
  await pool.end();
})();
