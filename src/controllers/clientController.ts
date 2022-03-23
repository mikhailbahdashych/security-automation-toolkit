import { Request, Response } from 'express';
import moment from 'moment';
import loggerConfig from '../common/logger'

const twoFactorService = require('node-2fa')

import * as clientService from '../services/clientService';
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

    if (!email || !password) return CommonResponse.common.badRequest({ res })

    const client = await clientService.getClientByEmail(email)
    logger.info(`Registration client with email: ${email}`)

    if (client) {
      logger.info(`Client with email ${email} already exists`)
      return CommonResponse.common.accessForbidden({ res })
    }

    password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT.toString())
    const personaluuid = (seedrandom(email).quick() * 1e10).toFixed(0)
    const createdClient = await clientService.createClient({ email, password, personaluuid })
    logger.info(`Client with email ${email} was created`)

    if (reflink) {
      const existingReflink = await reflinkService.findReflinkByName(reflink)
      if (!existingReflink) return CommonResponse.common.badRequest({ res })

      await reflinkService.addClientToReferralProgram(createdClient[0].id, reflink)
    }

    return CommonResponse.common.success({ res })

  } catch (e) {
    logger.error(`Error while register => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const confirmRegistration = async (req: Request, res: Response) => {
  try {
    const { confirmToken } = req.body

    if (!confirmToken) return CommonResponse.common.badRequest({ res })

    const decryptedHash = cryptoService.decryptHex(confirmToken, `${process.env.CRYPTO_KEY_SHORT}`, null)
    const client = await clientService.getClientByEmail(decryptedHash)

    if (!client && client.confirmemail) return CommonResponse.common.accessForbidden({ res })

    if (
      moment().subtract(1, 'day').format('YYYY-MM-DD HH:mm:ss') >=
      moment(client.createdat).format('YYYY-MM-DD HH:mm:ss')
    ) return CommonResponse.common.accessForbidden({ res }, -2)

    await clientService.confirmEmailRegistration(client.id)
    return CommonResponse.common.success({ res })

  } catch (e) {
    logger.error(`Error while registration confirmation => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const login = async (req: Request, res: Response) => {
  try {
    let { email, password } = req.body

    if (!email || !password) return CommonResponse.common.badRequest({ res })

    password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT.toString())
    const client = await clientService.getClientToLogin(email, password)
    logger.info(`Login client with email: ${email}`)

    if (!client) {
      logger.info(`Wrong login data for client with email: ${email}`)
      return CommonResponse.common.accessForbidden({ res })
    }

    if (!client.confirmemail) {
      logger.info(`Email wasn't confirmed for client: ${email}`)
      return CommonResponse.common.accessForbidden({ res })
    }

    if (client.twofa) {
      return res.status(200).json({ twofa: true })
    }

    if (client.phone) {
      return res.status(200).json({ phone: true })
    }

    const clientId = cryptoService.encrypt(client.id, process.env.CRYPTO_KEY.toString(), process.env.CRYPTO_IV.toString())
    const token = jwtService.sign({
      uxd: clientId,
    });
    return res.status(200).json(token)
  } catch (e) {
    logger.error(`Error while login => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
};

export const set2fa = async (req: Request, res: Response) => {
  try {
    const { jwt, code, token } = req.body

    if (!jwt || !code || !token) return CommonResponse.common.badRequest({ res })

    const client = await getClientByJwtToken(jwt)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    const result2Fa = twoFactorService.verifyToken(token, code);
    logger.info(`Setting 2FA for client with id: ${client.id}`)

    if (!result2Fa || result2Fa.delta !== 0) return CommonResponse.common.accessForbidden({ res })

    await clientService.set2fa(token, client.id)
    logger.info(`2FA was successfully created for client with id: ${ client.id }`)
    return CommonResponse.common.success({ res })

  } catch (e) {
    logger.error(`Error while setting 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const disable2fa = async (req: Request, res: Response) => {
  try {
    const { code, jwt } = req.body

    if (!code) return CommonResponse.common.badRequest({ res })

    const client = await getClientByJwtToken(jwt)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    const { twofa } = await clientService.getClientById(client.id)

    if (!twofa) return CommonResponse.common.accessForbidden({ res })

    const result2Fa = twoFactorService.verifyToken(twofa, code)

    if (!result2Fa) return CommonResponse.common.accessForbidden({ res }, -4)
    if (result2Fa.delta !== 0) return CommonResponse.common.accessForbidden({ res }, -4)

    await clientService.remove2fa(client.id)
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
    if (!client) return CommonResponse.common.accessForbidden({ res })

    const { twofa } = await clientService.getClientById(client.id)

    if (!twofa) return res.status(200).json({ status: -2 })

    return CommonResponse.common.success({ res })

  } catch (e) {
    logger.error(`Error verifying setting 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const loginWith2fa = async (req: Request, res: Response) => {
  try {
    const { email, twoFaCode } = req.body

    if (!twoFaCode) return CommonResponse.common.accessForbidden({ res })

    const client = await clientService.getClientByEmail(email)

    if (!client) return CommonResponse.common.accessForbidden({ res })

    const { twofa } = await clientService.getClientById(client.id)

    if (!twofa) return CommonResponse.common.accessForbidden({ res })

    const result2Fa = twoFactorService.verifyToken(twofa, twoFaCode)

    if (!result2Fa) return CommonResponse.common.accessForbidden({ res }, -4)
    if (result2Fa.delta !== 0) return CommonResponse.common.accessForbidden({ res }, -4)

    const clientId = cryptoService.encrypt(client.id, process.env.CRYPTO_KEY.toString(), process.env.CRYPTO_IV.toString())
    const token = jwtService.sign({
      uxd: clientId,
    });

    res.status(200).json({ status: 1, token })
  } catch (e) {
    logger.error(`Error while checking 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const clientByToken = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const client = await getClientByJwtToken(token)
    if (!client) return CommonResponse.common.accessForbidden({ res })
    client.email = hideEmail(client.email)

    return res.status(200).json(client)
  } catch (e) {
    logger.error(`Error while getting client by token => ${e}`)
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

    await clientService.changePassword(client.id, cryptoService.hashPassword(newPassword, process.env.CRYPTO_SALT.toString()))
    return CommonResponse.common.success({ res })

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
    ) return CommonResponse.common.badRequest({ res })

    const client = await getClientByJwtToken(token)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    const checkIfEmailUsed = await clientService.getClientByEmail(newEmail)

    if (checkIfEmailUsed || client.email !== currentEmail) return CommonResponse.common.badRequest({ res })

    await clientService.changeEmail(client.id, newEmail)
    return CommonResponse.common.success({ res })

  } catch (e) {
    logger.error(`Error while changing email => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const closeAccount = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const client = await getClientByJwtToken(token)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    await clientService.closeAccount(client.id, client.email)
    return CommonResponse.common.success({ res })
  } catch (e) {
    logger.error(`Error while closing account => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const freezeAccount = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const client = await getClientByJwtToken(token)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    await clientService.freezeAccount(client.id)
    return CommonResponse.common.success({ res })
  } catch (e) {
    logger.error(`Error while freezing account => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}
