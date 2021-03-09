import mysql from 'mysql';
import dotenv from 'dotenv';

dotenv.config();

const connection = mysql.createPool({
  connectionLimit: 20,
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
});
// connection.connect();

export default connection;
