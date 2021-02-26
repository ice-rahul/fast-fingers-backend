import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import userRoute from './routes/api.js';

const app = express();
const allowedOrigins = ['http://localhost:3000', 'https://rahul-fastfingers.netlify.app'];
app.use(cors({
  origin(origin, callback) {
    // allow requests with no origin
    // (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not '
                  + 'allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
}));
const port = process.env.PORT || 3000;

app.use(bodyParser.json());

app.use('/api', userRoute);

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.listen(port, () => {
//  console.log(`App listening at http://localhost:${port}`);
});
