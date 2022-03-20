const knex = require('../knex/knex.js')
const uuid = require('uuid')
const moment = require('moment')
const tableName = 'reflinks'

export const createReflink = async (clientId: string, reflink: string) => {
  const generatedUuid = uuid.v4()

  const reflinkid = await knex('clients')
    .update({ reflinkid: generatedUuid })
    .where('id', clientId).returning('reflinkid')

  return knex(tableName).insert({ id: reflinkid[0].reflinkid, reflink })
}

export const getReflinkByInviteeId = async (clientId: string) => {
  return knex(tableName)
    .leftJoin('clients', 'clients.reflinkid', `${tableName}.id`)
    .where('clients.id', clientId)
    .first(`${tableName}.reflink`, `${tableName}.invitedclients`)
}

export const findReflinkByName = async (reflink: string) => {
  return knex(tableName)
    .first('reflink', 'invitedclients')
    .where('reflink', reflink)
}

export const addClientToReferralProgram = async (clientId: string, reflink: string) => {
  return knex(tableName)
    .update({
      invitedclients: JSON.stringify({[clientId]: moment()})
    }).where('reflink', reflink)
}
