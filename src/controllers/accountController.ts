import { Request, Response } from 'express';
import loggerConfig from '../common/logger'

const twoFactorService = require('node-2fa')

const accountService = require('../services/accountService')
const jwtService = require('../services/jwtService')
const cryptoService = require('../services/cryptoService')
const logger = loggerConfig({ label: 'account-controller', path: 'account' })

export const register = async (req: Request, res: Response) => {
  try {
    let { email, password } = req.body
    const user = await accountService.getUserByEmail(email)
    logger.info(`Registration user with email: ${email}`)

    if (!user) {
      password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT)
      await accountService.createUser({ email, password })
      res.status(200).json({ status: 1 })
    } else {
      logger.info(`User with email ${email} already exists`)
      res.status(500).json({ message: "Something went wrong" })
    }

  } catch (e) {
    logger.info(`Error while register => ${e}`)
    res.status(500).json({ message: 'Something went wrong' })
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    let { email, password } = req.body

    password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT)
    const result = await accountService.getUserToLogin(email, password)
    logger.info(`Login user with email: ${email}`)

    if (result) {
      const userId = cryptoService.encrypt(result.id, process.env.CRYPTO_KEY, process.env.CRYPTO_IV)
      const token = await jwtService.sign({
        uxd: userId,
      });
      res.status(200).json(token)
    } else {
      logger.info(`Wrong login data for user with email: ${email}`)
      res.status(500).json({ message: 'User already exists' })
    }

  } catch (e) {
    res.status(500).json({ message: 'Something went wrong' })
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    res.status(500).json({ message: 'Something went wrong' })
  }
};

export const sendVerificationCode = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    res.status(500).json({ message: 'Something went wrong' })
  }
}

export const verifyToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const result = await jwtService.getUser(token)
    res.status(200).json(result)
  } catch (e) {
    res.json({
      error: 'Corrupted token'
    })
  }
}

export const set2fa = async (req: Request, res: Response) => {
  try {
    const { jwt, code, token } = req.body
    console.log(req.body)
    const user = await jwtService.getUser(jwt)
    const userId = cryptoService.decrypt(user.uxd, process.env.CRYPTO_KEY, process.env.CRYPTO_IV)
    console.log('userId', userId)
    const result2F = twoFactorService.verifyToken(token, code);

    if (result2F) {
      // await accountService.set2fa({token, clientId: id})
    }
  } catch (e) {
    res.status(500).json({ message: 'Something went wrong' })
  }
}
