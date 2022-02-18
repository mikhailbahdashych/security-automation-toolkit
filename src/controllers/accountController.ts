import { Request, Response } from 'express';
const accountService = require('../services/accountService')
const jwtService = require('../services/jwtService')
const cryptoService = require('../services/cryptoService')

export const register = async (req: Request, res: Response) => {
  try {
    let { email, password } = req.body
    const user = await accountService.getUserByEmail(email)

    if (!user) {
      password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT)
      await accountService.createUser({ email, password })
      res.status(200).json({ status: 1 })
    }

  } catch (e) {
    res.status(500).json({ message: 'Something went wrong' })
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body
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
}
