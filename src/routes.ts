const router = require('express').Router();

const clientController = require('./controllers/clientController')
const emailController = require('./controllers/emailController')
const reflinkController = require('./controllers/reflinkController')
const walletController = require('./controllers/walletController')

import validator from "./middlewares/validator";

// Basic functions
router.post('/login', clientController.login)
router.post('/register', clientController.register)
router.post('/confirm-registration', clientController.confirmRegistration)
router.post('/freeze-or-close-account', clientController.freezeOrCloseAccount)

// 2FA
router.post('/set-2fa', clientController.set2fa)
router.post('/disable-2fa', clientController.disable2fa)
router.post('/verify-2fa', clientController.checkFor2fa)

// Password
router.post('/change-password', clientController.changePassword)

// Email
router.post('/change-email', clientController.changeEmail)
router.post('/send-email', emailController.sendEmail)

// Token
router.post('/client-by-token', clientController.clientByToken)

// Referral links
router.post('/generate-referral-link', reflinkController.generateReferralLink)
router.post('/get-referral-link', reflinkController.getReferralLink)
router.get('/registration-from-reflink/:reflink', reflinkController.findReferralLink)

// Wallet
router.post('/check-wallets', walletController.checkWallets)

export default router;
