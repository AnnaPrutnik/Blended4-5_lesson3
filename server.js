//Регистрация: сохранение пользователя в базу данных
//Аутентификация: проверка логина, пароля, токена и др. с базой данных. Тот ли пришел пользователь
//Авторизация: проверка прав доступа к определенным ресурсам сайта либо к выполнению каких-либо действий
// Валидные токен: 1. Срок действия не истек 2. Проходит верификацию

const express = require('express');
const {colors} = require('./helpers');
const connectDB = require('./config/db');
const booksRourer = require('./routes/booksRouter');
require('dotenv').config({path: './config/.env'});
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
// const verifyToken = require('./middlewares/auth');
const app = express();

// Мидлвара авторизации
// Токен может придти из req.body, headers или req.query
// const token = req.body.token || req.query.token || tokenFromHeaders;

const verifyToken = async (req, res, next) => {
  let tokenFromHeaders = null;
  if (req.headers.authorization) {
    const [Bearer, token] = req.headers.authorization.split(' ');
    tokenFromHeaders = token;
  }

  const token = tokenFromHeaders;

  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY_JWT);
    // req.locals.user = decoded; - правильно ложить сюда!!!
    req.user = decoded; // но все делают вот так
  } catch (err) {
    return res.status(401).json({code: 401, message: err.message});
  }

  return next();
};

//body parser
app.use(express.json());

//add routes
app.use('/api/v1/books', booksRourer);

app.post('/register', async (req, res) => {
  //1. Получить данные пользователя (могут прийти из боди, из файла и др.)
  const {email, password, phone, firstName, lastName} = req.body;

  //2. Делаем валидацию полей, которые получили
  if (!email || !password || !phone) {
    return res
      .status(400)
      .json({code: 400, message: 'add all requered fields'});
  }

  //3. Проверяем есть ли пользователь в базе
  const user = await User.findOne({email, phone});

  //4. Есть пользователь есть, сообщить что пользователь уже зарегистрирован любым способом: отправка письма, джсон и др
  if (user) {
    return res.status(409).json({code: 409, message: 'user already exists'});
  }
  //5. Есть такого нет, хешируем пароль
  const saltPass = await bcrypt.hash(password, 8);
  //6. Создаем пользователя
  const candidate = await User.create({
    email,
    phone,
    password: saltPass,
    firstName,
    lastName,
  });
  //7. Возможны два варианта: или сразу сгенерить токен или генерить после логинизации.
  //7а Генерим токен
  const token = jwt.sign(
    {
      user_id: candidate._id,
    },
    process.env.SECRET_KEY_JWT,
    {expiresIn: '8h'}
  );

  //8. Присваиваем токен пользователю
  candidate.token = token;
  //9. Сохраняем в базе пользователя (с хешированным паролем, токеном)
  await candidate.save();
  //10. Должны ответить: успешно зарегистрирован.
  return res.status(201).json({code: 201, message: 'registration successfull'});
});

app.post('/login', async (req, res) => {
  //1. Получить данные пользователя (могут прийти из боди, из файла и др.)
  const {email, password, phone, firstName, lastName} = req.body;

  //2. Делаем валидацию полей, которые получили
  if (!email || !password || !phone) {
    return res
      .status(400)
      .json({code: 400, message: 'add all requered fields'});
  }

  //3. Проверяем есть ли пользователь в базе
  const user = await User.findOne({email, phone});

  //5. Есть такого нет, сообщаем, что нужно зарегистрироваться
  if (!user) {
    return res.status(400).json({code: 400, message: 'please, register!'});
  }

  // 6. Если есть, проверяем логин и пароль на валидность
  const correctPassword = await bcrypt.compare(password, user.password);
  //7. Если данные не валидные - пишем "не верный логин и пароль"
  if (!correctPassword) {
    return res
      .status(400)
      .json({code: 400, message: 'wrong login or password'});
  }
  //8. Если валидные логин и пароль: проверяем токен на валидность

  try {
    let tokenFromHeaders = null;
    if (req.headers.authorization) {
      const [Bearer, token] = req.headers.authorization.split(' ');
      tokenFromHeaders = token;
    }

    // // Токен может придти из req.body, headers или req.query
    const token = tokenFromHeaders || user.token;

    jwt.verify(token, process.env.SECRET_KEY_JWT);
    //9. Токен валидные: пишем сообщение что юзер успешно залогинился
  } catch (err) {
    const token = jwt.sign(
      {
        user_id: user._id,
      },
      process.env.SECRET_KEY_JWT,
      {expiresIn: '8h'}
    );
    user.token = token;
    await user.save();
  }

  //10. Токен не валидный: выдать новый токен, сообщить, что юзер успешно залогинился
  return res.status(200).json({code: 200, message: 'login success'});
});

app.get('/logout', verifyToken, async (req, res) => {
  //1. Получить токен

  //2. Расшифровываем токен
  const authorization = req.user.user_id;
  //3. Если в токене есть payload.id, в базе присваиваем токен=null
  if (authorization) {
    await User.findByIdAndUpdate(authorization, {token: null});
    //4. И отправляем ответ, что разлогинился.
    return res.status(200).json({code: 200, message: 'logout success'});
  }
  // Если не правильный токен, пишем, что не авторизирован
  return res.status(401).json({code: 401, message: 'Unauthorized '});
});

const {PORT} = process.env;

//connect to DB
connectDB();

const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`.cyan);
});

process.on('unhandledRejection', (err, _) => {
  if (err) {
    console.log(`Error: ${err.message}`.red);
    // server.close(() => process.exit(1));
    process.exit(1);
  }
});
