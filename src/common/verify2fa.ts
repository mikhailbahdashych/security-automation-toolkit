import { Response } from 'express';
import { verify2fa } from "../interfaces/interfaces"
import { getClientByJwtToken } from "./getClientByJwtToken";
import { CommonResponse } from "../responses/response";
const twoFactorService = require('node-2fa');

export const verifyTwoFa = async (data: verify2fa, res: Response) => {
  const client = await getClientByJwtToken(data.token)
  if (!client) return CommonResponse.common.accessForbidden({ res })

  const result2Fa = twoFactorService.verifyToken(client.twofa, data.twofa)

  if (!result2Fa) return CommonResponse.common.accessForbidden({ res })
  if (result2Fa.delta !== 0) return CommonResponse.common.accessForbidden({ res })

  return client
}
