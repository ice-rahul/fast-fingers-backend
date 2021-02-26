import express from 'express';
import bodyParser from 'body-parser';
import userRoute from './routes/api.js';

const app = express();
const port = 3000;

app.use(bodyParser.json());

app.use('/api', userRoute);

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.listen(port, () => {
//  console.log(`App listening at http://localhost:${port}`);
});
