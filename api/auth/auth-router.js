// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router()
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const db = require('../../data/db-config')
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
} = require('./auth-middleware')

router.post(
  '/register',
  checkUsernameFree, 
  (req, res, next) => {

    const {username, password} = req.body;
    const hash = bcrypt.hashSync(req.body.password, 8)
    Users.add({username, password: hash})
    .then(user => {
      res.status(201).json(user)
    })
    .catch(err => {
      next({ message: err.message })
    })
    // try {
    //   const hash = bcrypt.hashSync(req.body.password, 8)
    //   const user = await Users.add({
    //     username: req.body.username,
    //     password: hash,
    //   })
    //   console.log(user)
    //   res.status(201).json(`add new user ${user}`)
    //   console.log('try')
    // } catch (err) {
    //   next({ message: err.message })
    //   console.log('catch')
    // }
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

router.post('/login', checkUsernameExists, (req, res, next) => {
  if (bcrypt.compareSync(req.body.password, req.body.hash)) {
    req.session.user = {
      username: req.body.username,
      password: req.body.hash,
    }
    res.status(200).json(` Welcome ${req.body.username}!`)
  } else {
    next({ status: 401, message: 'Invalid Credentials' })
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

router.get('/logout', (req, res, next) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        res.status(200).json({ message: 'logged out' })
      } else {
        res.json({ message: ' no session' })
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
