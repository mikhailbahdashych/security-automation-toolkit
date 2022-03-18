const router = require('express').Router();

const accountController = require('./controllers/accountController')
const emailController = require('./controllers/emailController')
const reflinkController = require('./controllers/reflinkController')

// @TODO validator(['email', 'phone']) Something with validators
import validator from "./middlewares/validator";
import auth from "./middlewares/auth";

// Basic functions
router.post('/login', accountController.login)
router.post('/register', accountController.register)
router.post('/confirm-registration', accountController.confirmRegistration)
router.post('/close-account', auth, accountController.closeAccount)
router.post('/freeze-account', auth, accountController.freezeAccount)

// 2FA
router.post('/set-2fa', auth, accountController.set2fa)
router.post('/disable-2fa', auth, accountController.disable2fa)
router.post('/verify-2fa', auth, accountController.verify2fa)

// Password
router.post('/reset-password', accountController.resetPassword)
router.post('/change-password', auth, accountController.changePassword)

// Email
router.post('/change-email', auth, accountController.changeEmail)
router.post('/send-email', emailController.sendEmail) // ?

// Token
router.post('/client-by-token', accountController.clientByToken) // ?

// Other
router.post('/verification-code', accountController.sendVerificationCode) // ?

// Referral links
router.post('/generate-referral-link', auth, reflinkController.generateReferralLink)
router.post('/get-referral-link', auth, reflinkController.getReferralLink)
router.get('/get-clients-by-referral-link/:reflink', auth, reflinkController.getClientsByReferralLink)

export default router;
