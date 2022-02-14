import { Request, Response } from 'express';
const accountService = require('../services/accountService')

export const login = async (req: Request, res: Response) => {
    try {
        const user = await accountService.getUserById(req.body.id)
    } catch (e) {
        console.log(e)
    }
};

export const register = async (req: Request, res: Response) => {
    try {
        //
    } catch (e) {
        console.log(e)
    }
};
