import mysql from 'mysql';

const connection = mysql.createPool({
  connectionLimit: 20,
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.USER,
});

// connection.connect();

export default connection;
