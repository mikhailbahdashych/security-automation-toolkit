exports.up = function(knex) {
  return knex.schema.alterTable('users', table => {
    table.uuid('reflinkid').nullable().unique()
  })
};

exports.down = function(knex) {
  return knex.schema.alterTable('users', table => {
    table.dropColumn('reflinkid')
  })
};
