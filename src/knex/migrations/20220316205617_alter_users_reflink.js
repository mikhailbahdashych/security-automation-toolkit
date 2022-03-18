exports.up = function(knex) {
  return knex.schema.alterTable('clients', table => {
    table.uuid('reflinkid').nullable().unique()
  })
};

exports.down = function(knex) {
  return knex.schema.alterTable('clients', table => {
    table.dropColumn('reflinkid')
  })
};
