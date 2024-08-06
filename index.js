const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { generateToken, authenticateToken } = require('./auth');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();
const PORT = 8000;

app.use(bodyParser.json());

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
      },
    });
    res.status(201).send('User registered');
  } catch (error) {
    res.status(400).send('User already exists');
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await prisma.user.findUnique({
    where: { username },
  });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).send('Invalid credentials');
  }
  const token = generateToken(user);
  res.json({ token });
});

// Add password endpoint
app.post('/passwords', authenticateToken, async (req, res) => {
  const { site, password } = req.body;
  const userId = req.user.id;
  await prisma.password.create({
    data: {
      site,
      password,
      userId,
    },
  });
  res.status(201).send('Password added');
});

// Get passwords endpoint
app.get('/passwords', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const userPasswords = await prisma.password.findMany({
    where: { userId },
  });
  res.json(userPasswords);
});

// Update password endpoint
app.put('/passwords/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { site, password } = req.body;
  const userId = req.user.id;

  try {
    // Check if the password entry exists and belongs to the authenticated user
    const existingPassword = await prisma.password.findUnique({
      where: { id: parseInt(id) },
    });

    if (!existingPassword || existingPassword.userId !== userId) {
      return res.status(403).send('Not authorized to update this password');
    }

    // Update the password entry
    const updatedPassword = await prisma.password.update({
      where: { id: parseInt(id) },
      data: {
        site: site || existingPassword.site,
        password: password || existingPassword.password,
      },
    });

    res.json(updatedPassword);
  } catch (error) {
    res.status(400).send('Error updating password');
  }
});

// Delete password endpoint
app.delete('/passwords/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    // Check if the password entry exists and belongs to the authenticated user
    const existingPassword = await prisma.password.findUnique({
      where: { id: parseInt(id) },
    });

    if (!existingPassword || existingPassword.userId !== userId) {
      return res.status(403).send('Not authorized to delete this password');
    }

    // Delete the password entry
    await prisma.password.delete({
      where: { id: parseInt(id) },
    });

    res.status(204).send();
  } catch (error) {
    res.status(400).send('Error deleting password');
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
