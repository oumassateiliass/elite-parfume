// server.js - Backend API avec Express et MySQL
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'votre_secret_key_changez_moi_en_production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuration de la connexion MySQL
const dbConfig = {
  host: 'mysql.railway.internal',
  user: 'root',           // Changez avec votre utilisateur MySQL
  password: 'dnspIVDyoBXpXaHjxwnompTmElGKiLyy',           // Changez avec votre mot de passe MySQL
  database: 'elite_parfums',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Pool de connexions MySQL
let pool;

// Initialisation de la base de données
async function initDatabase() {
  try {
    // Connexion initiale sans base de données pour la créer
    const tempConnection = await mysql.createConnection({
      host: dbConfig.host,
      user: dbConfig.user,
      password: dbConfig.password
    });

    // Créer la base de données si elle n'existe pas
    await tempConnection.query(`CREATE DATABASE IF NOT EXISTS ${dbConfig.database}`);
    await tempConnection.end();

    // Créer le pool avec la base de données
    pool = mysql.createPool(dbConfig);

    console.log('✅ Connecté à MySQL');

    // Créer les tables
    await createTables();
    await insertDefaultData();

  } catch (error) {
    console.error('❌ Erreur connexion MySQL:', error.message);
    console.log('\n📌 VÉRIFIEZ:');
    console.log('1. MySQL est démarré');
    console.log('2. Utilisateur et mot de passe corrects dans dbConfig');
    console.log('3. Installez mysql2: npm install mysql2');
    process.exit(1);
  }
}

// Créer les tables
async function createTables() {
  const connection = await pool.getConnection();
  
  try {
    // Table des utilisateurs admin
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Table des produits
    await connection.query(`
      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(200) NOT NULL,
        brand VARCHAR(100) NOT NULL,
        category VARCHAR(50) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        old_price DECIMAL(10, 2) NOT NULL,
        emoji VARCHAR(10),
        description TEXT,
        stock INT DEFAULT 100,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Table des commandes
    await connection.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        customer_name VARCHAR(200) NOT NULL,
        customer_email VARCHAR(100) NOT NULL,
        customer_phone VARCHAR(20),
        customer_address TEXT,
        total_amount DECIMAL(10, 2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Table des items de commande
    await connection.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        product_id INT NOT NULL,
        product_name VARCHAR(200) NOT NULL,
        quantity INT NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
      )
    `);

    console.log('✅ Tables créées');
  } catch (error) {
    console.error('❌ Erreur création tables:', error.message);
  } finally {
    connection.release();
  }
}

// Insérer les données par défaut
async function insertDefaultData() {
  const connection = await pool.getConnection();
  
  try {
    // Vérifier si admin existe
    const [users] = await connection.query('SELECT COUNT(*) as count FROM users');
    
    if (users[0].count === 0) {
      const defaultPassword = await bcrypt.hash('admin123', 10);
      await connection.query(
        'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
        ['admin', defaultPassword, 'admin@eliteparfums.com']
      );
      console.log('✅ Utilisateur admin créé');
    }

    // Vérifier si produits existent
    const [products] = await connection.query('SELECT COUNT(*) as count FROM products');
    
    if (products[0].count === 0) {
      const defaultProducts = [
        ['Noir Élégance', 'ÉLITE', 'homme', 79.90, 119.90, '🖤', 'Parfum masculin intense et sophistiqué', 100],
        ['Rose Mystique', 'ÉLITE', 'femme', 89.90, 129.90, '🌹', 'Fragrance florale élégante', 100],
        ['Oud Intense', 'PRESTIGE', 'homme', 99.90, 149.90, '🪵', 'Notes boisées orientales', 100],
        ['Jasmin Royal', 'ÉLITE', 'femme', 74.90, 109.90, '🌸', 'Douceur florale raffinée', 100],
        ['Cuir Sauvage', 'PRESTIGE', 'homme', 84.90, 124.90, '🦁', 'Caractère puissant et audacieux', 100],
        ['Vanille Dorée', 'ÉLITE', 'femme', 69.90, 99.90, '✨', 'Gourmand et envoûtant', 100],
        ['Ambre Nuit', 'PRESTIGE', 'homme', 94.90, 139.90, '🌙', 'Mystérieux et envoûtant', 100],
        ['Fleur de Lys', 'ÉLITE', 'femme', 79.90, 114.90, '💐', 'Élégance florale française', 100]
      ];

      for (const product of defaultProducts) {
        await connection.query(
          'INSERT INTO products (name, brand, category, price, old_price, emoji, description, stock) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          product
        );
      }
      console.log('✅ Produits par défaut ajoutés');
    }
  } catch (error) {
    console.error('❌ Erreur insertion données:', error.message);
  } finally {
    connection.release();
  }
}

// Middleware d'authentification
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token manquant' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalide' });
    }
    req.user = user;
    next();
  });
}

// ==================== ROUTES AUTHENTIFICATION ====================

// Login admin
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const [users] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      SECRET_KEY,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });
  } catch (error) {
    console.error('Erreur login:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== ROUTES PRODUITS ====================

// GET - Récupérer tous les produits (PUBLIC)
app.get('/api/products', async (req, res) => {
  try {
    const [products] = await pool.query('SELECT * FROM products ORDER BY created_at DESC');
    res.json(products);
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET - Récupérer un produit par ID
app.get('/api/products/:id', async (req, res) => {
  try {
    const [products] = await pool.query('SELECT * FROM products WHERE id = ?', [req.params.id]);
    
    if (products.length === 0) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }
    
    res.json(products[0]);
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST - Ajouter un produit (ADMIN)
app.post('/api/products', authenticateToken, async (req, res) => {
  const { name, brand, category, price, old_price, emoji, description, stock } = req.body;

  try {
    const [result] = await pool.query(
      'INSERT INTO products (name, brand, category, price, old_price, emoji, description, stock) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [name, brand, category, price, old_price, emoji || '💎', description || '', stock || 100]
    );

    res.json({ id: result.insertId, message: 'Produit ajouté avec succès' });
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur lors de l\'ajout' });
  }
});

// PUT - Modifier un produit (ADMIN)
app.put('/api/products/:id', authenticateToken, async (req, res) => {
  const { name, brand, category, price, old_price, emoji, description, stock } = req.body;

  try {
    const [result] = await pool.query(
      'UPDATE products SET name=?, brand=?, category=?, price=?, old_price=?, emoji=?, description=?, stock=? WHERE id=?',
      [name, brand, category, price, old_price, emoji, description, stock, req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }

    res.json({ message: 'Produit modifié avec succès' });
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur lors de la modification' });
  }
});

// DELETE - Supprimer un produit (ADMIN)
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM products WHERE id = ?', [req.params.id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Produit non trouvé' });
    }

    res.json({ message: 'Produit supprimé avec succès' });
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur lors de la suppression' });
  }
});

// ==================== ROUTES COMMANDES ====================

// POST - Créer une commande (PUBLIC)
app.post('/api/orders', async (req, res) => {
  const { customer_name, customer_email, customer_phone, customer_address, items, total_amount } = req.body;

  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();

    // Insérer la commande
    const [orderResult] = await connection.query(
      'INSERT INTO orders (customer_name, customer_email, customer_phone, customer_address, total_amount) VALUES (?, ?, ?, ?, ?)',
      [customer_name, customer_email, customer_phone, customer_address, total_amount]
    );

    const orderId = orderResult.insertId;

    // Insérer les items
    for (const item of items) {
      await connection.query(
        'INSERT INTO order_items (order_id, product_id, product_name, quantity, price) VALUES (?, ?, ?, ?, ?)',
        [orderId, item.product_id, item.name, item.quantity, item.price]
      );
    }

    await connection.commit();

    res.json({ 
      orderId, 
      message: 'Commande créée avec succès',
      order_number: orderId
    });
  } catch (error) {
    await connection.rollback();
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur lors de la création de la commande' });
  } finally {
    connection.release();
  }
});

// GET - Récupérer toutes les commandes (ADMIN)
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
    res.json(orders);
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET - Récupérer une commande avec ses items (ADMIN)
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const [orders] = await pool.query('SELECT * FROM orders WHERE id = ?', [req.params.id]);
    
    if (orders.length === 0) {
      return res.status(404).json({ error: 'Commande non trouvée' });
    }

    const [items] = await pool.query('SELECT * FROM order_items WHERE order_id = ?', [req.params.id]);

    res.json({ ...orders[0], items });
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// PUT - Mettre à jour le statut d'une commande (ADMIN)
app.put('/api/orders/:id/status', authenticateToken, async (req, res) => {
  const { status } = req.body;

  try {
    const [result] = await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Commande non trouvée' });
    }

    res.json({ message: 'Statut mis à jour' });
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur lors de la mise à jour' });
  }
});

// ==================== STATISTIQUES (ADMIN) ====================

app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const [productStats] = await pool.query('SELECT COUNT(*) as count, SUM(price * stock) as value FROM products');
    const [orderStats] = await pool.query('SELECT COUNT(*) as count, SUM(total_amount) as revenue FROM orders');
    const [pendingStats] = await pool.query('SELECT COUNT(*) as count FROM orders WHERE status = "pending"');

    res.json({
      totalProducts: productStats[0].count,
      stockValue: productStats[0].value || 0,
      totalOrders: orderStats[0].count,
      totalRevenue: orderStats[0].revenue || 0,
      pendingOrders: pendingStats[0].count
    });
  } catch (error) {
    console.error('Erreur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Démarrage du serveur
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
    console.log(`📦 API disponible sur http://localhost:${PORT}/api`);
    console.log(`🛍️ Boutique: http://localhost:${PORT}/index.html`);
    console.log(`🔐 Admin: http://localhost:${PORT}/admin.html`);
    console.log(`👤 Login: username=admin, password=admin123`);
  });
});

// Gestion de la fermeture propre
process.on('SIGINT', async () => {
  await pool.end();
  console.log('🔴 Pool MySQL fermé');
  process.exit(0);
});
