const router = require('express').Router();

const accountController = require('./controllers/accountController')
const emailController = require('./controllers/emailController')

// import jwt from "./middlewares/jwt";
import validator from "./middlewares/validator";

router.post('/login', validator(['email']), accountController.login)
router.post('/register', accountController.register)
router.post('/confirm-registration', accountController.confirmRegistration)

router.post('/reset-password', accountController.resetPassword)
router.post('/verification-code', accountController.sendVerificationCode)
router.post('/verify-token', accountController.verifyToken)
router.post('/set-2fa', accountController.set2fa)
router.post('/verify-2fa', accountController.verify2fa)
router.post('/change-password', accountController.changePassword)
router.post('/close-account', accountController.closeAccount)
router.post('/change-email', accountController.changeEmail)

router.post('/send-email', emailController.sendEmail)

export default router;
