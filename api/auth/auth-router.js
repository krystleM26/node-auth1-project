// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router()
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const {checkUsernameFree, checkUsernameExists, checkPasswordLength} = require('./auth-middleware')


router.post('/register', checkUsernameFree, checkUsernameExists, checkPasswordLength, async (req,res, next)=> {

  console.log('register')
try {
  const hash = bcrypt.hashSync(req.user.password, 8);
  const user = await Users.add({ username: req.user.username, password:hash })
  res.status(201).json('add new user ${user.username')
} catch (err) {
  next({ message: err.message})
}


  }) 
  


/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/login', checkUsernameExists, (req,res, next) => {

})
/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
  router.get('/logout', (req,res, next) => {

  })


// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router