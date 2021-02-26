import mysql from 'mysql';

const connection = mysql.createPool({
  connectionLimit: 20,
  host: 'ls-e89759f3dbbe271552940eef018fa3b71189b42e.c6xzx62teqsd.ap-southeast-1.rds.amazonaws.com',
  user: 'dbmasteruser',
  password: '=~:WfFAi3H3g+bO!lVWZ=ZapVw8%+,9f',
  database: 'rahul_pesto',
});

// connection.connect();

export default connection;
