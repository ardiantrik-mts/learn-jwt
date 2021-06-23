require('dotenv').config();
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');

app.use(express.json());

app.post('/token', (req, res) => {
    const refreshToken = req.body.token;
})

app.post('/login', (req, res) => {
    const username = req.body.username;
    const user = { name: username };

    // const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
    res.json({ accessToken: accessToken, refreshToken: refreshToken });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];//BEARER TOKEN

    if (token ==null) {
        return res.sendStatus(401);
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }

        req.user = user
        next();
    })
}

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' })
}

app.listen(4000);