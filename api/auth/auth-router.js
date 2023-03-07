const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const UserModel = require("../users/users-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

router.post("/register", rolAdiGecerlimi, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try {
    const { role_name } = req;
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 8);
    const newUser = await UserModel.ekle({
      username,
      role_name,
      password: hash,
    });
    res.status(201).json(newUser);
  } catch (error) {
    next(error);
  }
});

router.post("/login", usernameVarmi, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */
  const { username, password } = req.body;
  const passwordExist = bcrypt.compareSync(password, req.user.password);
  UserModel.goreBul({ username })
    .then(([user]) => {
      if (user && passwordExist) {
        const token = generateToken(user);
        res
          .status(200)
          .json({ message: `${user.username} geri geldi!`, token });
      } else {
        next({
          status: 401,
          message: "Geçersiz kriter",
        });
      }
    })
    .catch(next);
});

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: "1d",
  };
  const token = jwt.sign(payload, JWT_SECRET, options);
  return token;
}

module.exports = router;
