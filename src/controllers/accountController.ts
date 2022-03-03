import { Request, Response } from 'express';
import loggerConfig from '../common/logger'

const twoFactorService = require('node-2fa')

import * as accountService from '../services/accountService';
import * as jwtService from '../services/jwtService';
import * as cryptoService from '../services/cryptoService';
import * as dotenv from 'dotenv';
dotenv.config();

import { CommonResponse } from "../responses/response";

const logger = loggerConfig({ label: 'account-controller', path: 'account' })

const getClientByJwtToken = async (jwt: string) => {
  const userJwt = await jwtService.getClient(jwt)
  const userId = cryptoService.decrypt(userJwt.uxd, process.env.CRYPTO_KEY.toString(), process.env.CRYPTO_IV.toString())
  return await accountService.getClientById(userId)
}

export const register = async (req: Request, res: Response) => {
  try {
    let { email, password } = req.body

    if (!email || !password) return res.status(500).json({ status: -1 })

    const user = await accountService.getClientByEmail(email)
    logger.info(`Registration user with email: ${email}`)

    if (user) {
      logger.info(`User with email ${email} already exists`)
      return res.status(500).json({ status: -1 })
    }

    password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT.toString())
    await accountService.createClient({ email, password })
    logger.info(`User with email ${email} was created`)
    return res.status(200).json({ status: 1 })

  } catch (e) {
    logger.info(`Error while register => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const confirmRegistration = async (req: Request, res: Response) => {
  try {
    const { confirmToken } = req.body

    if (!confirmToken) return res.status(500).json({ status: -1 })

    const decryptedHash = cryptoService.decryptHex(confirmToken, `${process.env.CRYPTO_KEY_SHORT}`, null)
    const user = await accountService.getClientByEmail(decryptedHash)

    // @TODO ?
    if (!user && user.confirmemail) return res.status(500).json({ status: -1 })

    await accountService.confirmEmailRegistration(user.id)
    return res.status(200).json({ status: 1 })

  } catch (e) {
    logger.info(`Error while registration conformation => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const login = async (req: Request, res: Response) => {
  try {
    let { email, password, phone } = req.body

    if (!email || !password) res.status(500).json({ status: -1 })

    password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT.toString())
    const result = await accountService.getClientToLogin(email, password)
    logger.info(`Login user with email: ${email}`)

    if (!result) {
      logger.info(`Wrong login data for user with email: ${email}`)
      return res.status(500).json({ status: -1 })
    }

    const userId = cryptoService.encrypt(result.id, process.env.CRYPTO_KEY.toString(), process.env.CRYPTO_IV.toString())
    const token = jwtService.sign({
      uxd: userId,
    });
    return res.status(200).json(token)

  } catch (e) {
    logger.info(`Error while login => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const verifyToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.body

    if (!token) return res.status(200).json({error: true})

    const result = await jwtService.getClient(token)

    if (!result) {
      logger.info(`Expired token: ${token}`)
      return res.status(200).json({status: -1})
    }

    return res.status(200).json(result)
  } catch (e) {
    logger.info(`Error while verify token => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const set2fa = async (req: Request, res: Response) => {
  try {
    const { jwt, code, token } = req.body

    if (!jwt || !code || !token) return res.status(500).json({status: -1})

    const user = await getClientByJwtToken(jwt)

    const result2F = twoFactorService.verifyToken(token.secret, code);
    logger.info(`Setting 2FA for user with id: ${user.id}`)

    if (result2F && result2F.delta === 0) {
      await accountService.set2fa({secret: token.secret, clientId: user.id})
      logger.info(`2FA was successfully created for user with id: ${user.id}`)
      res.status(200).json({ status: 1 })
    } else {
      res.status(500).json({status: -1})
    }

  } catch (e) {
    logger.info(`Error while setting 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const verify2fa = async (req: Request, res: Response) => {
  try {
    const { token } = req.body

    if (!token) return res.status(200).json({ status: -1 })

    const user = await getClientByJwtToken(token)
    const two2fa = await accountService.get2fa(user.id)

    if (!two2fa.two2fa) return res.status(200).json({ status: -1 })

    res.status(200).json({ status: 1 })

  } catch (e) {
    logger.info(`Error verifying setting 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const changePassword = async (req: Request, res: Response) => {
  try {
    const { currentPassword, newPassword, newPasswordRepeat, token } = req.body

    if (
      (!currentPassword || !newPassword || !newPasswordRepeat || !token) ||
      (newPassword !== newPasswordRepeat)
    ) return res.status(500).json({ status: -1 })

    const user = await getClientByJwtToken(token)
    if (user.password !== cryptoService.hashPassword(currentPassword, process.env.CRYPTO_SALT.toString())) return res.status(500).json({ status: -1 })

    await accountService.changePassword(user.id, cryptoService.hashPassword(newPassword, process.env.CRYPTO_SALT.toString()))
    res.status(200).json({ status: 1 })

  } catch (e) {
    logger.info(`Error while changing password => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const changeEmail = async (req: Request, res: Response) => {
  try {
    const { currentEmail, newEmail, newEmailRepeat, token } = req.body

    if (
      (!currentEmail || !newEmail || !newEmailRepeat || !token) ||
      (newEmail !== newEmailRepeat)
    ) return res.status(500).json({ status: -1 })

    const user = await getClientByJwtToken(token)
    const checkIfEmailUsed = await accountService.getClientByEmail(newEmail)

    if (checkIfEmailUsed || user.email !== currentEmail) return res.status(500).json({ status: -1 })

    await accountService.changeEmail(user.id, newEmail)
    res.status(200).json({ status: 1 })

  } catch (e) {
    logger.info(`Error while changing email => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const closeAccount = async (req: Request, res: Response) => {
  try {
    const { token } = req.body

    if (!token) return res.status(200).json({ status: -1 })

    const user = await getClientByJwtToken(token)

    if (!user) return res.status(200).json({ status: -1 })

    await accountService.closeAccount(user)
    res.status(200).json({ status: 1 })

  } catch (e) {
    logger.info(`Error while closing account => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const resetPassword = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    logger.info(`Error while reset password => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const sendVerificationCode = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    logger.info(`Error while sending verification code => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

