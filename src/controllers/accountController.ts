import { Request, Response } from 'express';
import loggerConfig from '../common/logger'

const accountService = require('../services/accountService')
const jwtService = require('../services/jwtService')
const cryptoService = require('../services/cryptoService')
const logger = loggerConfig({ label: 'account-controller', path: 'account' })

export const register = async (req: Request, res: Response) => {
  try {
    let { email, password } = req.body
    const user = await accountService.getUserByEmail(email)
    logger.info(`Registration user with email: ${email}`)

    // @TODO DO SOMETHING WITH STATUSES
    if (!user) {
      password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT)
      await accountService.createUser({ email, password })
      res.status(200).json({ status: 1 })
    } else {
      logger.info(`User with email ${email} already exists`)
      res.status(500).json({message: 'Something went wrong'})
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

    if (result) {
      const userId = cryptoService.encrypt(result.id, process.env.CRYPTO_KEY)
      const token = await jwtService.sign({
        uxd: userId,
      });
      res.status(200).json(token)
    } else {
      //
    }

  } catch (e) {
    console.log(e)
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    console.log(e)
  }
};

export const verifyToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const result = await jwtService.getUser(token)
    res.json(result)
  } catch (e) {
    console.log(e)
  }
};

export const sendVerificationCode = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    console.log(e)
  }
}
