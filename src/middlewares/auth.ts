import * as jwtService from './../services/jwtService';
import { Request, Response } from 'express';
import { CommonResponse } from "../responses/response";

export default async (req: Request, res: Response, next: any) => {
  try {
    console.log('req.headers', req.headers)
    if (req.headers.authorization) return CommonResponse.common.unauthorized({ res })
    const user = await jwtService.getClient(req.headers.authorization.split(' ')[1])
    if (!user) return CommonResponse.common.unauthorized({ res })
    next()
  } catch (e) {
    return CommonResponse.common.unauthorized({res});
  }
}
