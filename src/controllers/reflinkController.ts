import { Request, Response } from "express";
import loggerConfig from '../common/logger'

import * as crypto from "crypto";
import * as reflinkService from '../services/reflinkService'
import * as clientService from '../services/clientService'

import { CommonResponse } from "../responses/response";
import { getClientByJwtToken } from "../common/getClientByJwtToken";
import { hideEmail } from "../common/hiders";
import moment from "moment";
import * as QRCode from "qrcode";

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

    const result = await reflinkService.getReflinkByInviteeId(user.id)
    if (!result) return res.status(400).json({ status: -1 })

    const accs: any[] = []
    if (result.invitedclients) {
      await Promise.all(
        Object.entries(result.invitedclients).map(async item => {
          const { email } = await clientService.getClientByEmailOrId({ id: item[0] })
          accs.push({ email, invitedAt: item[1] })
        }))
    }
    accs.forEach(item => {
      item.email = hideEmail(item.email)
      item.invitedAt = moment().format('YYYY-MM-DD HH:mm:ss')
    })
    result.invitedclients = accs

    result['qrcode'] = await QRCode.toDataURL(`localhost:8010/reflink/${result.reflink}`, { margin: 1 })

    return res.status(200).json(result)
  } catch (e) {
    logger.error(`Error while getting referral link => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}

export const findReferralLink = async (req: Request, res: Response) => {
  try {
    const { reflink } = req.params
    const foundedReflink = await reflinkService.findReflinkByName(reflink)
    if (!foundedReflink) return res.status(400).json({ status: -1 })

    return res.status(200).json(foundedReflink.reflink)
  } catch (e) {
    logger.error(`Error while finding referral link => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}
