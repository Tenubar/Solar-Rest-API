import express from 'express';
import {PORT} from './config.js'
import userRoutes from './routes/users.routes.js'
import cors from 'cors';

const app = express();
app.use(cors());

app.use(express.json());
app.use(express.urlencoded({extended:false}));
app.use(userRoutes);

app.listen(PORT);
console.log('server on port', PORT);
