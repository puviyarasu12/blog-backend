import express from 'express';
import dotenv from 'dotenv';
import AuthRoutes from './routes/Auth.js';
import DBCon from './libs/db.js';
import cors from 'cors';
import BlogRoutes from './routes/Blogs.js';
import DashboardRoutes from './routes/Dashboard.js';
import CommentRoutes from './routes/Comments.js';
import PublicRoutes from './routes/Public.js';

dotenv.config();

const PORT = process.env.PORT || 4000;
const app = express();
DBCon();

app.use(express.json());
app.use(express.static('public'));

const corsOptions = {
    origin: true,
    credentials: true
};
app.use(cors(corsOptions));

app.get('/', (req, res) => {
    res.send('Hello from server');
});

app.use('/auth', AuthRoutes);
app.use('/blog', BlogRoutes);
app.use('/dashboard', DashboardRoutes);
app.use('/comment', CommentRoutes);
app.use('/public', PublicRoutes);

app.listen(PORT, () => {
    console.log(`App is running on Port ${PORT}`);
});
