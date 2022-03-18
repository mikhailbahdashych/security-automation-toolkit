import {generateReferralLink, getClientsByReferralLink} from "./controllers/reflinkController";

const router = require('express').Router();

const accountController = require('./controllers/accountController')
const emailController = require('./controllers/emailController')
const reflinkController = require('./controllers/reflinkController')

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
router.post('/reset-password', accountController.resetPassword)
router.post('/change-password', accountController.changePassword)

// Email
router.post('/change-email', accountController.changeEmail)
router.post('/send-email', emailController.sendEmail)

// Token
router.post('/client-by-token', accountController.clientByToken)

// Other
router.post('/verification-code', accountController.sendVerificationCode)

// Referral links
router.post('/generate-referral-link', reflinkController.generateReferralLink)
router.post('/get-referral-link', reflinkController.getReferralLink)
router.get('/get-clients-by-referral-link/:reflink', reflinkController.getClientsByReferralLink)

export default router;
