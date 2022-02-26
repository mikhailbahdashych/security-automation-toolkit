import { Request, Response } from 'express';
import loggerConfig from '../common/logger'

import * as emailService from '../services/emailService';
import * as dotenv from 'dotenv';
dotenv.config();

import { CommonResponse } from "../responses/response";

const logger = loggerConfig({ label: 'email-controller', path: 'email' })

export const sendEmail = async (req: Request, res: Response) => {
  try {
    const { message } = req.body
    await emailService.sendEmail(message)
    res.status(200).json({ status: 1 })
  } catch (e) {
    logger.info(`Error while sending email => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}
