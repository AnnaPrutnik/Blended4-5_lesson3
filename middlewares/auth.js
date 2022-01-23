const jwt = require('jsonwebtoken');

const verifyToken = async (req, res, next) => {
  const [Bearer, token] = req.headers.authorization?.split(' ');
  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY_JWT);
    // req.locals.user = decoded; - правильно ложить сюда!!!
    req.user = decoded; // но все делают вот так
  } catch (err) {
    return res.status(401).json({code: 401, message: err.message});
  }

  return next();
};

module.exports = verifyToken;
