import { Request, Response } from "express";
import loggerConfig from '../common/logger'

import * as crypto from "crypto";
import * as reflinkService from '../services/reflinkService'

import { CommonResponse } from "../responses/response";
import { getClientByJwtToken } from "../common/getClientByJwtToken";
import {getClientsByReflink} from "../services/reflinkService";

const logger = loggerConfig({ label: 'reflink-controller', path: 'reflink' })

export const generateReferralLink = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const user = await getClientByJwtToken(token)
    if (!user) return res.status(403).json({ status: -1 })

    const reflink = crypto.randomBytes(10).toString('hex');

    await reflinkService.createReflink(user.id, reflink)

    return res.status(200).json({ status: 1 })
  } catch (e) {
    logger.error(`Error while generating referral link => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const getReferralLink = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const user = await getClientByJwtToken(token)
    if (!user) return res.status(403).json({ status: -1 })

    const result = await reflinkService.getReflink(user.id)
    if (!result) return res.status(200).json({ status: -1 })

    return res.status(200).json(result.reflink)
  } catch (e) {
    logger.error(`Error while getting referral link => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const getClientsByReferralLink = async (req: Request, res: Response) => {
  try {
    const { reflink } = req.params
    if (!reflink) return res.status(400).json({ status: -1 })

    const clientsByReflink = await reflinkService.getClientsByReflink()

    return res.status(200).json({ reflink })
  } catch (e) {
    logger.error(`Error while getting clients by referral link => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}
