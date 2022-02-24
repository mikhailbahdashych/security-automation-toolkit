import { Request, Response } from 'express';
import loggerConfig from '../common/logger'

const twoFactorService = require('node-2fa')

import * as accountService from '../services/accountService'
import * as jwtService from '../services/jwtService';
import * as cryptoService from '../services/cryptoService';
import * as dotenv from 'dotenv';
dotenv.config();

import { CommonResponse } from "../responses/response";

const logger = loggerConfig({ label: 'account-controller', path: 'account' })

const getUserByJwtToken = async (jwt: string) => {
  const user = await jwtService.getUser(jwt)
  return cryptoService.decrypt(user.uxd, process.env.CRYPTO_KEY.toString(), process.env.CRYPTO_IV.toString())
}

export const register = async (req: Request, res: Response) => {
  try {
    let { email, password } = req.body
    const user = await accountService.getUserByEmail(email)
    logger.info(`Registration user with email: ${email}`)

    if (!user) {
      password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT.toString())
      await accountService.createUser({ email, password })
      logger.info(`User with email ${email} was created`)
      res.status(200).json({ status: 1 })
    } else {
      logger.info(`User with email ${email} already exists`)
      res.status(500).json({ message: "Something went wrong" })
    }

  } catch (e) {
    logger.info(`Error while register => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    let { email, password } = req.body

    password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT.toString())
    const result = await accountService.getUserToLogin(email, password)
    logger.info(`Login user with email: ${email}`)

    if (result) {
      const userId = cryptoService.encrypt(result.id, process.env.CRYPTO_KEY.toString(), process.env.CRYPTO_IV.toString())
      const token = jwtService.sign({
        uxd: userId,
      });
      res.status(200).json(token)
    } else {
      logger.info(`Wrong login data for user with email: ${email}`)
      res.status(500).json({ message: 'User already exists' })
    }

  } catch (e) {
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const verifyToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const result = await jwtService.getUser(token)
    if (!result) {
      res.status(200).json({error: true})
    } else {
      res.status(200).json(result)
    }
  } catch (e) {
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const set2fa = async (req: Request, res: Response) => {
  try {
    const { jwt, code, token } = req.body
    const userId = await getUserByJwtToken(jwt)

    const result2F = twoFactorService.verifyToken(token.secret, code);
    logger.info(`Setting 2FA for user with id: ${userId}`)

    if (result2F.delta === 0) {
      await accountService.set2fa({secret: token.secret, clientId: userId})
      logger.info(`2FA was successfully created for user with id: ${userId}`)
    }
  } catch (e) {
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const verify2fa = async (req: Request, res: Response) => {
  try {
    const { jwt, code } = req.body
    const userId = await getUserByJwtToken(jwt)
    const two2fa = await accountService.get2fa(userId)
    if (two2fa) {}
  } catch (e) {
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const resetPassword = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const sendVerificationCode = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    return CommonResponse.common.somethingWentWrong({ res })
  }
}
