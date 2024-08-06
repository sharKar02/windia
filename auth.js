const jwt = require('jsonwebtoken');
const secretKey = 'your_secret_key';

function generateToken(user) {
  return jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {

  const token = req.headers.authorization;
//   const token = req.headers;
  console.log({token});

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {


    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

module.exports = { generateToken, authenticateToken };
