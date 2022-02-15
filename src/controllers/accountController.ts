import { Request, Response } from 'express';
const accountService = require('../services/accountService')

export const register = async (req: Request, res: Response) => {
  try {
    let { email, password } = req.body
    const user = await accountService.getUserByEmail(email)

    if (!user) {
      await accountService.createUser({
        email, password: '123'
      })
    }
  } catch (e) {
    console.log(e)
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    //
  } catch (e) {
    console.log(e)
  }
};
