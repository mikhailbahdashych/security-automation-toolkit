const router = require('express').Router();

const asyncMiddleware = require('./middlewares/async')
const accountController = require('./controllers/accountController')

router.post('/login', asyncMiddleware(accountController.login))
router.post('/register', asyncMiddleware(accountController.register))

export default router;
