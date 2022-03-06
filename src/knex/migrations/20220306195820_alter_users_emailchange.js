exports.up = function(knex) {
  return knex.schema.alterTable('users', table => {
    table.boolean('emailchange').notNullable().defaultTo(false)
  })
};

exports.down = function(knex) {
  return knex.schema.alterTable('users', table => {
    table.dropColumn('emailchange')
  })
};
