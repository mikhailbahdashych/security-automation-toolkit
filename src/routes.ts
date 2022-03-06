const router = require('express').Router();

const accountController = require('./controllers/accountController')
const emailController = require('./controllers/emailController')

// @TODO validator(['email', 'phone']) Something with validators
import validator from "./middlewares/validator";
import jwt from "./middlewares/jwt";

// Basic functions
router.post('/login', accountController.login)
router.post('/register', accountController.register)
router.post('/confirm-registration', accountController.confirmRegistration)
router.post('/close-account', accountController.closeAccount)

// 2FA
router.post('/set-2fa', accountController.set2fa)
router.post('/disable-2fa', accountController.disable2fa)
router.post('/verify-2fa', accountController.verify2fa)

// Password
router.post('/reset-password', accountController.resetPassword) // To implement
router.post('/change-password', accountController.changePassword)

// Email
router.post('/change-email', accountController.changeEmail)
router.post('/send-email', emailController.sendEmail)

// Token
router.post('/verify-token', accountController.verifyToken)

// Other
router.post('/verification-code', accountController.sendVerificationCode)

export default router;
