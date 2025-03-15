require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Models 
const User = require('./models/User');

// Middleware para verificar token
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado' });
    }

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);
        next();
    } catch (err) {
        return res.status(400).json({ msg: 'Token inválido' });
    }
}

// Rota pública
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo à nossa API' });
});

// Rota privada para buscar usuário por ID
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ msg: 'ID inválido' });
    }

    const user = await User.findById(id, '-password');
    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado' });
    }

    res.status(200).json({ user });
});

// Registro de usuário (Necessita de aprovação)
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body;

    if (!name) return res.status(422).json({ msg: 'O nome é obrigatório!' });
    if (!email) return res.status(422).json({ msg: 'O e-mail é obrigatório!' });
    if (!password) return res.status(422).json({ msg: 'A senha é obrigatória!' });
    if (password !== confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não conferem!' });
    }

    const userExist = await User.findOne({ email });
    if (userExist) {
        return res.status(422).json({ msg: 'Por favor, utilize outro e-mail!' });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({ name, email, password: passwordHash, approved: false });

    try {
        await user.save();
        res.status(201).json({ msg: 'Usuário cadastrado! Aguarde aprovação do administrador.' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: 'Erro no servidor, tente novamente mais tarde!' });
    }
});

// Login de usuário
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email) return res.status(422).json({ msg: 'O email é obrigatório!' });
    if (!password) return res.status(422).json({ msg: 'A senha é obrigatória!' });

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado' });
    }

    if (!user.approved) {
        return res.status(403).json({ msg: 'Usuário ainda não aprovado pelo administrador' });
    }

    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida' });
    }

    try {
        const secret = process.env.SECRET;
        const token = jwt.sign({ id: user._id }, secret, { expiresIn: '1h' });

        res.status(200).json({ msg: 'Autenticação realizada com sucesso!', token });
    } catch (err) {
        console.log(err);
        res.status(500).json({ msg: 'Erro no servidor, tente novamente mais tarde!' });
    }
});

// Rota para aprovar usuários (Apenas admin)
app.put('/auth/approve/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ msg: 'ID inválido' });
    }

    const user = await User.findById(id);
    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado' });
    }

    user.approved = true;
    await user.save();

    res.status(200).json({ msg: 'Usuário aprovado com sucesso!' });
});

// Conexão com o MongoDB
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPassword}@macademy.f8wlz.mongodb.net/?retryWrites=true&w=majority&appName=Macademy`)
    .then(() => {
        app.listen(3000, () => {
            console.log("Servidor rodando na porta 3000 🚀");
        });
    })
    .catch((err) => console.log(err));