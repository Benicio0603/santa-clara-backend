require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool({
  host: process.env.DB_HOST, port: Number(process.env.DB_PORT||5432),
  database: process.env.DB_NAME, user: process.env.DB_USER,
  password: String(process.env.DB_PASSWORD)
});
function normaliza(tel){
  if(!tel) return null;
  let n = String(tel).replace(/\D/g,'');
  if(n.startsWith('0')) n = n.slice(1);
  if(n.length === 11) n = '55'+n;
  return n;
}
(async()=>{
  const r = await pool.query("SELECT id, telefone FROM responsaveis WHERE telefone IS NOT NULL");
  for(const row of r.rows){
    const novo = normaliza(row.telefone);
    if(novo && novo !== row.telefone){
      await pool.query("UPDATE responsaveis SET telefone=$1 WHERE id=$2", [novo, row.id]);
      console.log(row.telefone + " -> " + novo);
    }
  }
  await pool.end();
  console.log("✅ Telefones corrigidos");
})();
