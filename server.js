const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;
const secretKey = 'cofggcvf'; // Troque por uma chave segura

app.use(bodyParser.json());

// Conexão com o Banco de Dados
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'cofggcvf',
    database: 'mentoring',
});

db.connect(err => {
    if (err) {
        console.error('Erro ao conectar ao MySQL:', err);
    } else {
        console.log('Conectado ao MySQL!');
    }
});

// Registro de Usuário
app.post('/register', async (req, res) => {
    const { first_name, last_name, email, password, user_type } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            'INSERT INTO users (first_name, last_name, email, password, user_type) VALUES (?, ?, ?, ?, ?)',
            [first_name, last_name, email, hashedPassword, user_type],
            (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        res.status(400).send('Email já cadastrado.');
                    } else {
                        res.status(500).send('Erro ao registrar o usuário.');
                    }
                } else {
                    res.status(201).send('Usuário registrado com sucesso!');
                }
            }
        );
    } catch (error) {
        res.status(500).send('Erro no servidor.');
    }
});

// Login de Usuário
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            res.status(500).send('Erro no servidor.');
        } else if (results.length === 0) {
            res.status(401).send('Usuário não encontrado.');
        } else {
            const user = results[0];
            const isValidPassword = await bcrypt.compare(password, user.password);

            if (!isValidPassword) {
                res.status(401).send('Senha incorreta.');
            } else {
                const token = jwt.sign({ id: user.id, user_type: user.user_type }, secretKey, {
                    expiresIn: '1h',
                });
                res.json({ message: 'Login bem-sucedido!', token });
            }
        }
    });
});

// Atualizar Configurações de Perfil
app.put('/profile', (req, res) => {
    const { id, first_name, last_name, user_type } = req.body;

    db.query(
        'UPDATE users SET first_name = ?, last_name = ?, user_type = ? WHERE id = ?',
        [first_name, last_name, user_type, id],
        (err, result) => {
            if (err) {
                res.status(500).send('Erro ao atualizar o perfil.');
            } else {
                res.send('Perfil atualizado com sucesso!');
            }
        }
    );
});

// Iniciar o Servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
