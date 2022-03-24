import { Request, Response } from 'express';
import loggerConfig from '../common/logger'

import * as walletService from '../services/walletService';
import { getClientByJwtToken } from "../common/getClientByJwtToken";
import { CommonResponse } from "../responses/response";

const logger = loggerConfig({ label: 'wallet-controller', path: 'wallet' })

export const checkWallets = async (req: Request, res: Response) => {
  try {
    const { token } = req.body
    const client = await getClientByJwtToken(token)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    const clientWallets = await walletService.getWalletsByClientId(client.id)

  } catch (e) {
    logger.error(`Error while checking wallets => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}
