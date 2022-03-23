const knex = require('../knex/knex.js')
const tableName = 'clients'

export const getClientToLogin = async (email: string, password: string) => {
  return knex(tableName)
    .first()
    .where('email', email)
    .andWhere('password', password)
}

export const getClientByEmail = async (email: string) => {
  return knex(tableName)
    .first(
      'id',
      'personaluuid',
      'email',
      'confirmemail',
      'emailchange',
      'twofa',
      'phone'
    ).where('email', email)
}

export const getClientById = async (id: string) => {
  return knex(tableName)
    .first(
      'id',
      'personaluuid',
      'email',
      'confirmemail',
      'emailchange',
      'twofa',
      'phone'
    ).where('id', id)
}

export const createClient = async (data: object) => {
  return knex(tableName)
    .insert(data).returning('*')
}

export const set2fa = async (data: { secret: string, clientId: string }) => {
  return knex(tableName)
    .update({ twofa: data.secret })
    .where('id', data.clientId)
}

export const remove2fa = async (id: string) => {
  return knex(tableName)
    .update({ twofa: null })
    .where('id', id)
}

export const closeAccount = async (client: { id: string, email: string }) => {
  return knex(tableName)
    .update({
      email: `${client.email}_del`
    })
    .where('id', client.id)
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

export const freezeAccount = async (id: string) => {

}
