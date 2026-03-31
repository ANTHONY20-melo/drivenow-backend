const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = 3000;
const SECRET_KEY = 'sua_chave_secreta_super_segura_aqui'; // Em produção, use variáveis de ambiente (.env)

// Middlewares
app.use(cors()); // Permite que o front-end se comunique com este back-end
app.use(express.json()); // Permite receber dados no formato JSON
app.use(express.static('../frontend')); // Serve arquivos estáticos da pasta frontend

// Rota para servir admin.html
app.get('/admin.html', (req, res) => {
    res.sendFile(__dirname + '/../frontend/admin.html');
});

// Rota para servir index.html
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/../frontend/index.html');
});

// Rota para servir login.html
app.get('/login.html', (req, res) => {
    res.sendFile(__dirname + '/../frontend/login.html');
});

// Configuração do Banco de Dados SQLite
const db = new sqlite3.Database('./drivenow.db', (err) => {
    if (err) console.error('Erro ao conectar ao banco:', err.message);
    else console.log('Conectado ao banco de dados SQLite.');
});

// Cria a tabela de usuários se ela não existir E cria o usuário admin padrão
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT
)`, async () => {
    // === SCRIPT PARA CRIAR O USUÁRIO ADMIN AUTOMATICAMENTE ===
    db.get("SELECT * FROM users WHERE email = 'admin'", async (err, row) => {
        if (!row) { // Se o usuário 'admin' não existir, nós criamos
            try {
                // Criptografa a senha '123' para que o login consiga ler depois
                const hashedAdminPassword = await bcrypt.hash('123', 10);
                
                db.run("INSERT INTO users (email, password) VALUES (?, ?)", ['admin', hashedAdminPassword], (err) => {
                    if (!err) {
                        console.log("✅ Usuário padrão criado -> Email: admin | Senha: 123");
                    } else {
                         console.error("Erro ao inserir admin no banco:", err.message);
                    }
                });
            } catch (error) {
                console.error("Erro ao criar hash da senha admin:", error);
            }
        }
    });
});

// Cria a tabela de carros se ela não existir
db.run(`CREATE TABLE IF NOT EXISTS cars (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    seats INTEGER,
    luggage INTEGER,
    transmission TEXT,
    ac BOOLEAN,
    image_url TEXT
)`, () => {
    // Inserindo dados de exemplo (Seed) apenas se a tabela estiver vazia
    db.get("SELECT COUNT(*) AS count FROM cars", (err, row) => {
        if (row.count === 0) {
            const stmt = db.prepare("INSERT INTO cars (name, price, seats, luggage, transmission, ac, image_url) VALUES (?, ?, ?, ?, ?, ?, ?)");
            
            stmt.run("Audi RS7", 450.00, 4, 2, "Automático", true, "https://images.unsplash.com/photo-1550355291-bbee04a92027?auto=format&fit=crop&q=80&w=600");
            stmt.run("Range Rover Velar", 520.00, 5, 4, "Automático", true, "https://images.unsplash.com/photo-1533473359331-0135ef1b58bf?auto=format&fit=crop&q=80&w=600");
            stmt.run("Volkswagen Polo", 120.00, 5, 2, "Manual", true, "https://images.unsplash.com/photo-1549317661-bd32c8ce0db2?auto=format&fit=crop&q=80&w=600");
            
            stmt.finalize();
            console.log("Carros de exemplo inseridos no banco de dados.");
        }
    });
});

// Cria a tabela de reservas
db.run(`CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    car_id INTEGER,
    status TEXT DEFAULT 'Ativa',
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(car_id) REFERENCES cars(id)
)`);

// ==========================================
// MIDDLEWARE: VERIFICADOR DE LOGIN
// ==========================================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Acesso negado. Faça login primeiro.' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
        req.user = user; 
        next(); 
    });
}

// ==========================================
// ROTA 1: CADASTRAR USUÁRIO 
// ==========================================
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(`INSERT INTO users (email, password) VALUES (?, ?)`, [email, hashedPassword], function(err) {
            if (err) {
                return res.status(400).json({ error: 'Este e-mail já está cadastrado.' });
            }
            res.status(201).json({ message: 'Usuário cadastrado com sucesso!', id: this.lastID });
        });
    } catch (error) {
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

// ==========================================
// ROTA 2: FAZER LOGIN 
// ==========================================
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Erro no banco de dados.' });
        if (!user) return res.status(401).json({ error: 'Usuário não encontrado.' });

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).json({ error: 'Senha incorreta.' });

        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '2h' });
        res.json({ message: 'Login bem-sucedido!', token, user: { email: user.email } });
    });
});

// ==========================================
// ROTA 3: LISTAR TODOS OS CARROS DA FROTA
// ==========================================
app.get('/api/cars', (req, res) => {
    db.all("SELECT * FROM cars", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao buscar a frota no banco de dados.' });
        }
        res.json(rows); 
    });
});

// ==========================================
// ROTA 4: CRIAR UMA RESERVA (Protegida)
// ==========================================
app.post('/api/reserve', authenticateToken, (req, res) => {
    const { carId } = req.body;
    const userId = req.user.id; 

    if (!carId) {
        return res.status(400).json({ error: 'ID do carro é obrigatório.' });
    }

    db.run(`INSERT INTO reservations (user_id, car_id) VALUES (?, ?)`, [userId, carId], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Erro ao criar reserva.' });
        }
        res.status(201).json({ message: 'Reserva confirmada com sucesso!', reservationId: this.lastID });
    });
});

// Inicia o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});