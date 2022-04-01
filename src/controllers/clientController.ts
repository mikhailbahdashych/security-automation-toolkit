import { Request, Response } from 'express';
import moment from 'moment';
import loggerConfig from '../common/logger'

const twoFactorService = require('node-2fa')

import * as clientService from '../services/clientService';
import * as jwtService from '../services/jwtService';
import * as cryptoService from '../services/cryptoService';
import * as reflinkService from '../services/reflinkService';
import seedrandom from 'seedrandom';
import { getClientByJwtToken } from "../common/getClientByJwtToken";
import { hideEmail, hidePhone } from "../common/hiders";
import { verifyTwoFa } from "../common/verify2fa";

import { CommonResponse } from "../responses/response";

const logger = loggerConfig({ label: 'client-controller', path: 'client' })

export const register = async (req: Request, res: Response) => {
  try {
    let { email, password, reflink } = req.body

    if (!email || !password) return CommonResponse.common.badRequest({ res })

    const client = await clientService.getClientByEmailOrId({ email })
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
    const client = await clientService.getClientByEmailOrId({ id: decryptedHash })

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
    let { email, password, twofa } = req.body

    if (!email || !password) return CommonResponse.common.badRequest({ res })

    password = cryptoService.hashPassword(password, process.env.CRYPTO_SALT.toString())
    const client = await clientService.getClientToLogin(email, password)
    logger.info(`Login client with email: ${email}`)

    if (!client) {
      logger.info(`Wrong login data for client with email: ${email}`)
      return CommonResponse.common.unauthorized({ res })
    }

    if (!client.confirmemail) {
      logger.info(`Email wasn't confirmed for client: ${email}`)
      return CommonResponse.common.accessForbidden({ res })
    }

    const checkIfAccountFrozen = await clientService.getFrozenAccount(client.id)
    logger.info(`Check if account was frozen for client with email: ${email}`)

    if (checkIfAccountFrozen) {
      await clientService.unfreezeAccount(client.id)
      logger.info(`Account was frozen, let's unfreeze it for client with email: ${email}`)
    }

    if (client.twofa) {
      if (!twofa) return res.status(200).json({ twofa: true })

      const result2Fa = twoFactorService.verifyToken(client.twofa, twofa)
      if (!result2Fa) return CommonResponse.common.accessForbidden({ res }, -4)
      if (result2Fa.delta !== 0) return CommonResponse.common.accessForbidden({ res }, -4)
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
    const { token, twofa, tokenTwofa } = req.body

    if (!token || !twofa || !tokenTwofa) return CommonResponse.common.badRequest({ res })

    const client = await getClientByJwtToken(token)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    const result2Fa = twoFactorService.verifyToken(tokenTwofa, twofa);
    logger.info(`Setting 2FA for client with id: ${client.id}`)

    if (!result2Fa) return CommonResponse.common.accessForbidden({ res })
    if (result2Fa.delta !== 0) return CommonResponse.common.accessForbidden({ res })

    await clientService.set2fa(tokenTwofa, client.id)
    logger.info(`2FA was successfully created for client with id: ${ client.id }`)
    return CommonResponse.common.success({ res })

  } catch (e) {
    logger.error(`Error while setting 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const disable2fa = async (req: Request, res: Response) => {
  try {
    const { twofa, token } = req.body

    if (!twofa) return CommonResponse.common.badRequest({ res })

    const client = await verifyTwoFa({ token, twofa })
    if (!client) return CommonResponse.common.unauthorized({ res }, -4)

    await clientService.remove2fa(client.id)
    logger.info(`2FA was successfully disabled for client with id: ${client.id}`)
    return CommonResponse.common.success({ res }, -3 )
  } catch (e) {
    logger.error(`Error while disabling 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const checkFor2fa = async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization.split(' ')[1]
    const client = await getClientByJwtToken(token)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    const { twofa } = await clientService.getClientByEmailOrId({ id: client.id })

    if (!twofa) return CommonResponse.common.success({ res }, -2)

    return CommonResponse.common.success({ res })

  } catch (e) {
    logger.error(`Error verifying setting 2FA => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const clientByToken = async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization.split(' ')[1]
    const client = await getClientByJwtToken(token)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    client.email = hideEmail(client.email)
    client.twofa = !!client.twofa;
    if (client.phone) client.phone = hidePhone(client.phone)

    return res.status(200).json(client)
  } catch (e) {
    logger.error(`Error while getting client by token => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const changePassword = async (req: Request, res: Response) => {
  try {
    const { currentPassword, newPassword, newPasswordRepeat, token, twofa } = req.body

    if (
      (!currentPassword || !newPassword || !newPasswordRepeat || !token || !twofa) ||
      (newPassword !== newPasswordRepeat)
    ) return CommonResponse.common.badRequest({ res })

    const client = await verifyTwoFa({ token, twofa })
    if (!client) return CommonResponse.common.unauthorized({ res })

    if (client.password !== cryptoService.hashPassword(currentPassword, process.env.CRYPTO_SALT.toString())) return CommonResponse.common.accessForbidden({ res })

    await clientService.changePassword(client.id, cryptoService.hashPassword(newPassword, process.env.CRYPTO_SALT.toString()))
    return CommonResponse.common.success({ res })

  } catch (e) {
    logger.error(`Error while changing password => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const changeEmail = async (req: Request, res: Response) => {
  try {
    const { currentEmail, newEmail, newEmailRepeat, token, twofa } = req.body

    if (
      (!currentEmail || !newEmail || !newEmailRepeat || !token || !twofa ) ||
      (newEmail !== newEmailRepeat)
    ) return CommonResponse.common.badRequest({ res })

    const client = await verifyTwoFa({ token, twofa })
    if (!client) return CommonResponse.common.unauthorized({ res })

    const checkIfEmailUsed = await clientService.getClientByEmailOrId({ email: newEmail})

    if (checkIfEmailUsed || client.email !== currentEmail) return CommonResponse.common.badRequest({ res })

    await clientService.changeEmail(client.id, newEmail)
    return CommonResponse.common.success({ res })

  } catch (e) {
    logger.error(`Error while changing email => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const freezeOrCloseAccount = async (req: Request, res: Response) => {
  try {
    const { token, twofa, type } = req.body

    const client = await verifyTwoFa({ token, twofa })
    if (!client) return CommonResponse.common.unauthorized({ res })

    if (type === 'closeaccount') await clientService.closeAccount(client.id, client.email)
    else await clientService.freezeAccount(client.id)

    return CommonResponse.common.success({ res })
  } catch (e) {
    logger.error(`Error while ${req.body.type} account => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })

  }
}
