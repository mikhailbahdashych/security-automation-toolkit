import { Request, Response } from 'express';
import loggerConfig from '../common/logger'

import * as emailService from '../services/emailService';
import * as cryptoService from '../services/cryptoService';
import * as dotenv from 'dotenv';
dotenv.config();

import { CommonResponse } from "../responses/response";

const logger = loggerConfig({ label: 'email-controller', path: 'email' })

export const sendEmail = async (req: Request, res: Response) => {
  try {
    const { type, to } = req.body

    if (to) {

      const hash = cryptoService.encryptHex(to, `${process.env.CRYPTO_KEY_SHORT}`, null)

      if (type === 'reg') {
        await emailService.sendRegistrationEmail(to, hash)
      } else {
        res.status(200).json({ status: -1 })
      }

    } else {
      res.status(200).json({ status: -1 })
    }

  } catch (e) {
    logger.info(`Error while sending email => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}
