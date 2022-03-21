import { Request, Response } from 'express';
import moment from 'moment';
import loggerConfig from '../common/logger'

const twoFactorService = require('node-2fa')

import * as accountService from '../services/accountService';
import * as jwtService from '../services/jwtService';
import * as cryptoService from '../services/cryptoService';
import * as reflinkService from '../services/reflinkService';
import * as dotenv from 'dotenv';
import seedrandom from 'seedrandom';
import { getClientByJwtToken } from "../common/getClientByJwtToken";
import { hideEmail } from "../common/hideEmail";
dotenv.config();

import { CommonResponse } from "../responses/response";

const logger = loggerConfig({ label: 'account-controller', path: 'account' })

export const register = async (req: Request, res: Response) => {
  try {
    let { email, password, reflink } = req.body

    if (!email || !password) return res.status(400).json({ status: -1 })

    const client = await accountService.getClientByEmail(email)
    logger.info(`Registration client with email: ${email}`)

    if (client) {
      logger.info(`Client with email ${email} already exists`)
      return res.status(403).json({ status: -1 })
    }

    password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT.toString())
    const personaluuid = (seedrandom(email).quick() * 1e10).toFixed(0)
    const createdClient = await accountService.createClient({ email, password, personaluuid })
    logger.info(`Client with email ${email} was created`)

    if (reflink) {
      const existingReflink = await reflinkService.findReflinkByName(reflink)
      if (!existingReflink) return res.status(400).json({ status: -2 })

      await reflinkService.addClientToReferralProgram(createdClient[0].id, reflink)
    }

    return res.status(200).json({ status: 1 })

  } catch (e) {
    logger.error(`Error while register => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const confirmRegistration = async (req: Request, res: Response) => {
  try {
    const { confirmToken } = req.body

    if (!confirmToken) return res.status(400).json({ status: -1 })

    const decryptedHash = cryptoService.decryptHex(confirmToken, `${process.env.CRYPTO_KEY_SHORT}`, null)
    const client = await accountService.getClientByEmail(decryptedHash)

    if (!client && client.confirmemail) return res.status(403).json({ status: -1 })

    if (
      moment().subtract(1, 'day').format('YYYY-MM-DD HH:mm:ss') >=
      moment(client.createdat).format('YYYY-MM-DD HH:mm:ss')
    ) return res.status(403).json({ status: -2 })

    await accountService.confirmEmailRegistration(client.id)
    return res.status(200).json({ status: 1 })

  } catch (e) {
    logger.error(`Error while registration confirmation => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const login = async (req: Request, res: Response) => {
  try {
    let { email, password, phone } = req.body

    if (!email || !password) res.status(400).json({ status: -1 })

    password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT.toString())
    const result = await accountService.getClientToLogin(email, password)
    logger.info(`Login client with email: ${email}`)

    if (!result) {
      logger.info(`Wrong login data for client with email: ${email}`)
      return res.status(403).json({ status: -1 })
    }

    if (!result.confirmemail) {
      logger.info(`Email wasn't confirmed for client: ${email}`)
      return res.status(403).json({ status: -1 })
    }

    const clientId = cryptoService.encrypt(result.id, process.env.CRYPTO_KEY.toString(), process.env.CRYPTO_IV.toString())
    const token = jwtService.sign({
      uxd: clientId,
    });
    return res.status(200).json(token)

  } catch (e) {
    logger.error(`Error while login => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const clientByToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const result = await getClientByJwtToken(token)
    if (!result) return res.status(403).json({ status: -1 })
    result.email = hideEmail(result.email)

    return res.status(200).json(result)
  } catch (e) {
    logger.error(`Error while getting client by token => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const set2fa = async (req: Request, res: Response) => {
  try {
    const { jwt, code, token } = req.body

    if (!jwt || !code || !token) return res.status(400).json({ status: -1 })

    const client = await getClientByJwtToken(jwt)
    if (!client) return res.status(403).json({ status: -1 })

    const result2Fa = twoFactorService.verifyToken(token, code);
    logger.info(`Setting 2FA for client with id: ${client.id}`)

    if (!result2Fa || result2Fa.delta !== 0) return res.status(403).json({ status: -1 })

    await accountService.set2fa({ secret: token, clientId: client.id })
    logger.info(`2FA was successfully created for client with id: ${ client.id }`)
    res.status(200).json({ status: 1 })

  } catch (e) {
    logger.error(`Error while setting 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const disable2fa = async (req: Request, res: Response) => {
  try {
    const { code, jwt } = req.body

    const client = await getClientByJwtToken(jwt)
    if (!client) return res.status(403).json({ status: -1 })

    if (!code) return res.status(400).json({ status: -1 })

    const twofa = await accountService.get2fa(client.id)

    if (!twofa.twofa) return res.status(403).json({ status: -1 })

    const result2Fa = twoFactorService.verifyToken(client.twofa, code)

    if (!result2Fa) return res.status(403).json({ status: -4 })
    if (result2Fa.delta !== 0) return res.status(403).json({ status: -4 })

    await accountService.remove2fa(client.id)
    logger.info(`2FA was successfully disabled for client with id: ${client.id}`)
    res.status(200).json({ status: -3 })

  } catch (e) {
    logger.error(`Error while disabling 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const verify2fa = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const client = await getClientByJwtToken(token)
    if (!client) return res.status(403).json({ status: -1 })

    const twofa = await accountService.get2fa(client.id)

    if (!twofa.twofa) return res.status(200).json({ status: -2 })

    res.status(200).json({ status: 1 })

  } catch (e) {
    logger.error(`Error verifying setting 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const changePassword = async (req: Request, res: Response) => {
  try {
    const { currentPassword, newPassword, newPasswordRepeat, token } = req.body

    if (
      (!currentPassword || !newPassword || !newPasswordRepeat || !token) ||
      (newPassword !== newPasswordRepeat)
    ) return res.status(400).json({ status: -1 })

    const client = await getClientByJwtToken(token)
    if (!client) return res.status(403).json({ status: -1 })

    if (client.password !== cryptoService.hashPassword(currentPassword, process.env.CRYPTO_SALT.toString())) return res.status(403).json({ status: -1 })

    await accountService.changePassword(client.id, cryptoService.hashPassword(newPassword, process.env.CRYPTO_SALT.toString()))
    res.status(200).json({ status: 1 })

  } catch (e) {
    logger.error(`Error while changing password => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const changeEmail = async (req: Request, res: Response) => {
  try {
    const { currentEmail, newEmail, newEmailRepeat, token } = req.body

    if (
      (!currentEmail || !newEmail || !newEmailRepeat || !token) ||
      (newEmail !== newEmailRepeat)
    ) return res.status(400).json({ status: -1 })

    const client = await getClientByJwtToken(token)
    if (!client) return res.status(403).json({ status: -1 })

    const checkIfEmailUsed = await accountService.getClientByEmail(newEmail)

    if (checkIfEmailUsed || client.email !== currentEmail) return res.status(400).json({ status: -1 })

    await accountService.changeEmail(client.id, newEmail)
    res.status(200).json({ status: 1 })

  } catch (e) {
    logger.error(`Error while changing email => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const closeAccount = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const client = await getClientByJwtToken(token)
    if (!client) return res.status(403).json({ status: -1 })

    await accountService.closeAccount(client)
    res.status(200).json({ status: 1 })
  } catch (e) {
    logger.error(`Error while closing account => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const freezeAccount = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    logger.error(`Error while freezing account => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const resetPassword = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    logger.error(`Error while reset password => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
};
