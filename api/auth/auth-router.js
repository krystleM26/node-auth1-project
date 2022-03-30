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
   if(bcrypt.compareSync(req.user.password, req.user.hash)) {
     req.session.user = {
        username: req.user.username,
        password: req.user.hash,
     }
     res.status(200).json(` Welcome ${req.user.username}!`)
   } else {
     next({status: 401, message: 'Invalid Credentials' })
   }
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

  router.get('/logout', (req,res, next) => {
    if(req.session.user) {
      const {username} = req.session.user
      req.session.destroy(err => {
        if(err) {
         res.status(200).json({ message: 'logged out'})
        } else {
          res.json({ message: ' nosession'})
        } 
    })
  }
})


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
  


// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router