const knex = require('../knex/knex.js')
const tableName = 'clients'
import { getClientByEmailOrIdData } from "../interfaces/interfaces";

export const getClientToLogin = async (email: string, password: string) => {
  return knex(tableName)
    .first()
    .where('email', email)
    .andWhere('password', password)
}

export const getClientByEmailOrId = async (data: getClientByEmailOrIdData) => {
  return knex(tableName)
    .first(
      'id',
      'personaluuid',
      'email',
      'confirmemail',
      'emailchange',
      'twofa',
      'phone'
    ).modify((x: any) => {
      if (data.email) x.where('email', data.email)
      else x.where('id', data.id)
    })
}

export const createClient = async (data: object) => {
  return knex(tableName)
    .insert(data).returning('*')
}

export const set2fa = async (secret: string, clientId: string) => {
  return knex(tableName)
    .update({ twofa: secret })
    .where('id', clientId)
}

export const remove2fa = async (id: string) => {
  return knex(tableName)
    .update({ twofa: null })
    .where('id', id)
}

export const closeAccount = async (id: string, email: string) => {
  return knex(tableName)
    .update({
      email: `${email}_del`
    })
    .where('id', id)
}

export const changePassword = async (id: string, newPassword: string) => {
  return knex(tableName)
    .update({
      password: newPassword
    })
    .where('id', id)
}

export const changeEmail = async (id: string, newEmail: string) => {
  return knex(tableName)
    .update({
      email: newEmail
    })
    .where('id', id)
}

export const confirmEmailRegistration = async (id: string) => {
  return knex(tableName)
    .update({
      confirmemail: true
    })
    .where('id', id)
}

export const getFrozenAccount = async (id: string) => {
  return knex('freezedaccounts')
    .first().where('clientid', id)
}

export const freezeAccount = async (id: string) => {
  return knex('freezedaccounts').insert({ clientid: id })
}

export const unfreezeAccount = async (id: string) => {
  return knex('freezedaccounts')
    .del().where('clientid', id)
}

