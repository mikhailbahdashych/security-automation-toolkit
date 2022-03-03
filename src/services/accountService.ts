const knex = require('../knex/knex.js')

export const getClientToLogin = async (email: string, password: string) => {
  return knex('users')
    .first()
    .where('email', email)
    .andWhere('password', password)
}

export const getClientByEmail = async (email: string) => {
  return knex('users')
    .first()
    .where('email', email)
}

export const getClientById = async (id: string) => {
  return knex('users')
    .first()
    .where('id', id)
}

export const createClient = async (data: object) => {
  return knex('users')
    .insert(data)
}

export const set2fa = async (data: { secret: string, clientId: string }) => {
  return knex('users')
    .update({twofa: data.secret})
    .where('id', data.clientId)
}

export const get2fa = async (id: string) => {
  return knex('users')
    .first('twofa')
    .where('id', id)
}

export const closeAccount = async (client: { id: string, email: string }) => {
  return knex('users')
    .update({
      email: `${client.email}_del`
    })
    .where('id', client.id)
}

export const changePassword = async (id: string, newPassword: string) => {
  return knex('users')
    .update({
      password: newPassword
    })
    .where('id', id)
}

export const changeEmail = async (id: string, newEmail: string) => {
  return knex('users')
    .update({
      email: newEmail
    })
    .where('id', id)
}

export const confirmEmailRegistration = async (id: string) => {
  return knex('users')
    .update({
      confirmemail: true
    })
    .where('id', id)
}
