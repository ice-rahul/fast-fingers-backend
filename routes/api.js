import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import fs from 'fs';
import connection from '../connection/dbConnect.js';

const router = express.Router();

dotenv.config();

router.use(express.json());

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) { res.sendStatus(401); }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      const refreshToken = req.headers.token;
      if (refreshToken == null) return res.sendStatus(401);
      connection.query('SELECT * from tokens where token = ?', [refreshToken], (tokenErr, results) => {
        if (tokenErr) throw tokenErr;
        if (results.length === 0) {
          res.sendStatus(403);
        } else {
          jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (jwtErr, userData) => {
            if (jwtErr) throw jwtErr;
            const accessToken = jwt.sign({ email: userData.email, name: userData.name, userId: userData.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' });
            res.user = {
              ...userData,
              accessToken,
            };
            next();
          });
        }
      });
    } else {
      req.user = {
        ...user,
        accessToken: token,
      };
      next();
    }
  });
}

router.post('/register', (req, res) => {
  const { name, email, password } = req.body;
  if (name && email && password) {
    const userId = uuidv4();
    connection.query('SELECT * from users where email = ? ', [email], (selectErr, result) => {
      if (selectErr) throw selectErr;

      if (result.length === 0) {
        // new user
        const data = {
          user_id: userId,
          name,
          email,
          password: bcrypt.hashSync(password, 10),
        };
        connection.query('INSERT into users SET ? ', data, (insertErr) => {
          if (insertErr) throw insertErr;
          connection.query('SELECT * from users where user_id = ? ', [userId], (err, records) => {
            if (err) throw err;
            res.send({ ...records[0], status: true, msg: 'User Created SuccessFully' });
          });
        });
      } else {
        // existing user
        res.send({ status: false, msg: 'User Already Exist' });
      }
    });
  } else {
    res.send({ status: false, msg: 'All Fields are mandatory' });
  }
});

router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (email && password) {
    connection.query('SELECT * from users where email = ?', [email], (err, results) => {
      if (err) throw err;
      if (results.length === 0 || !bcrypt.compareSync(password, results[0].password)) {
        res.send({ status: false, msg: 'Invalid Login Credentials' });
      } else {
        const data = { email: results[0].email, name: results[0].name, userId: results[0].user_id };
        const accessToken = jwt.sign(data, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' });
        const refreshToken = jwt.sign(data, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '1d' });
        connection.query('INSERT into tokens SET ?', { token: refreshToken }, (insertErr) => {
          if (insertErr) throw insertErr;
          res.send({ status: true, accessToken, refreshToken });
        });
      }
    });
  } else {
    res.send({ status: false, msg: 'All fields are mandatory' });
  }
});

router.get('/token', (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  connection.query('SELECT * from tokens where token = ?', [refreshToken], (err, results) => {
    if (err) throw err;
    if (results.length === 0) {
      res.sendStatus(403);
    } else {
      jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (jwtErr, user) => {
        if (jwtErr) throw jwtErr;
        const accessToken = jwt.sign({ email: user.email, name: user.name, userId: user.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' });
        res.send({ accessToken });
      });
    }
  });
});

router.get('/', authenticateToken, (req, res) => {
  res.send(res.user);
  console.log(res.user);
});

router.post('/getWord', authenticateToken, (req, res) => {
  const { level } = req.body;
  connection.query('SELECT * from words where level_id = ? ORDER BY RAND() LIMIT 1', level.toUpperCase(), (err, results) => {
    if (err) throw err;
    res.send(results);
  });
});

// add score Data
router.post('/addScore', authenticateToken, (req, res) => {
  const { score } = req.body;
  const { userId } = req.user;
  const data = {
    user_id: userId,
    score,
  };
  connection.query('INSERT into game SET ? ', data, (error) => {
    res.send('Score Added Successfully');
    if (error) throw error;
    //    console.log(results.insertId);
  });
});

// get score Data
router.post('/getScore', authenticateToken, (req, res) => {
  const { userId } = req.user;
  connection.query('SELECT * from game where user_id = ? and is_disabled = 0', [userId], (error) => {
    res.send('Score List');
    if (error) throw error;
    // console.log(results.insertId);
  });
});

// disable game score
router.post('/quitGame', authenticateToken, (req, res) => {
  const { userId } = req.user;
  connection.query('Update game SET is_disabled = 1 where user_id = ? ', [userId], (error) => {
    res.send('Score List');
    if (error) throw error;
    // console.log(results.insertId);
  });
});

router.get('/sendWordsToDatabase', (req, res) => {
  const { level } = req.query;
  let min = 0;
  let max = 0;
  let levelId = 0;
  if (level.toUpperCase() === 'EASY') {
    max = 5;
    levelId = 1;
  }
  if (level.toUpperCase() === 'MEDIUM') {
    min = 4;
    max = 9;
    levelId = 2;
  }
  if (level.toUpperCase() === 'HARD') {
    min = 9;
    max = 50;
    levelId = 3;
  }

  const rstream = fs.createReadStream('dictionary.json');
  rstream.on('data', (chunkData) => {
    const filteredData = (chunkData.toString()).split(',').map((value) => {
      const processedVal = value.replace(new RegExp('\r?\n?"', 'g'), '').trim();
      if (processedVal.length > min && processedVal.length < max) {
        return [processedVal, levelId];
      }
      return null;
    })
      .filter((value) => value);
    connection.query('INSERT into words (word, level_id) VALUES ? ', [filteredData], (err) => {
      if (err) throw err;
    });
  });
  rstream.on('end', () => {
    res.end();
  });
  rstream.on('error', (err) => {
    if (err) throw err;
    res.end('file not found');
  });
});

export default router;
