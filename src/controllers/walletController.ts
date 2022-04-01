import { Request, Response } from 'express';
import loggerConfig from '../common/logger'

import * as walletService from '../services/walletService';
import { getClientByJwtToken } from "../common/getClientByJwtToken";
import { CommonResponse } from "../responses/response";

const logger = loggerConfig({ label: 'wallet-controller', path: 'wallet' })

export const checkWallets = async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization.split(' ')[1]
    const client = await getClientByJwtToken(token)
    if (!client) return CommonResponse.common.accessForbidden({ res })

    const clientWallets = await walletService.getWalletsByClientId(client.id)

    if (clientWallets.length < 2) {
      await walletService.generateWallets(clientWallets)
    }

    return res.status(200).json(clientWallets)
  } catch (e) {
    logger.error(`Error while checking wallets => ${e}`)
    return CommonResponse.common.somethingWentWrong({ res })
  }
}
