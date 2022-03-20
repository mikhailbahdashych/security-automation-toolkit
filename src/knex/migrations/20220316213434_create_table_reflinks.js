exports.up = function(knex) {
  return knex.schema.createTable('reflinks', table => {
    table.uuid('id').notNullable().defaultTo(knex.raw('gen_random_uuid ()')).primary()

    table
      .foreign('id')
      .references('reflinkid')
      .inTable('clients')

    table.text('reflink').notNullable()
    table.float('amount').nullable().defaultTo(0)
    table.json('invitedclients').nullable()

    table.timestamp("createdat").defaultTo(knex.fn.now())
    table.timestamp("updatedat").defaultTo(knex.fn.now())

  })
};

exports.down = function(knex) {
  return knex.schema.dropTable('reflinks')
};
