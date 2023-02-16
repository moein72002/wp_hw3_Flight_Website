
const { Pool } = require("pg");

// const pool = new Pool("postgres://postgres:alierfan@localhost:5433/postgres")
const pool = new Pool({
  user: 'postgres',
      database: 'postgres',
    password: 'alierfan',
    port: 5433,
    host: 'localhost',
})
module.exports = {
  query: (text, params) => pool.query(text, params),
};
