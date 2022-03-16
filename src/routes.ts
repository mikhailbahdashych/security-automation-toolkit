const router = require('express').Router();

const accountController = require('./controllers/accountController')
const emailController = require('./controllers/emailController')

// @TODO validator(['email', 'phone']) Something with validators
import validator from "./middlewares/validator";

// Basic functions
router.post('/login', accountController.login)
router.post('/register', accountController.register)
router.post('/confirm-registration', accountController.confirmRegistration)
router.post('/close-account', accountController.closeAccount)
router.post('/freeze-account', accountController.freezeAccount)

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
router.post('/client-by-token', accountController.clientByToken)

// Other
router.post('/verification-code', accountController.sendVerificationCode)
router.post('/generate-referral-link', accountController.generateReferralLink)

export default router;
