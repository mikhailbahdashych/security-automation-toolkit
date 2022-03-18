const knex = require('../knex/knex.js')
const uuid = require('uuid')
const tableName = 'reflinks'

export const createReflink = async (userId: string, reflink: string) => {
  const generatedUuid = uuid.v4()

  const reflinkid = await knex('clients')
    .update({ reflinkid: generatedUuid })
    .where('id', userId).returning('reflinkid')

  return knex(tableName).insert({ id: reflinkid[0].reflinkid, reflink })
}

export const getReflink = async (userId: string) => {
  return knex(tableName)
    .leftJoin('clients', 'clients.reflinkid', `${tableName}.id`)
    .where('clients.id', userId)
    .first(`${tableName}.reflink`)
}

export const getClientsByReflink = async () => {

}
