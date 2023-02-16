
const { Pool } = require("pg");

// const pool = new Pool("postgres://postgres:alierfan@localhost:5432/postgres")
const pool = new Pool({
  user: 'postgres',
      database: 'postgres',
    password: 'alierfan',
    port: 5432,
    host: 'ticket-postgres',
})
module.exports = {
  query: (text, params) => pool.query(text, params),
};
