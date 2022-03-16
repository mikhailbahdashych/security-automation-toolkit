exports.up = function(knex) {
  return knex.schema.createTable('reflinks', table => {
    table.uuid('id').notNullable().defaultTo(knex.raw('gen_random_uuid ()')).primary()

    table
      .foreign('id')
      .references('reflinkid')
      .inTable('users')


    table.text('reflink').notNullable()
    table.float('amount').nullable()
    table.json('invitedusers').nullable()
    table.uuid('invitedby').nullable()

    table
      .foreign('invitedby')
      .references('id')
      .inTable('users')

    table.timestamp("createdat").defaultTo(knex.fn.now())
    table.timestamp("updatedat").defaultTo(knex.fn.now())

  })
};

exports.down = function(knex) {
  return knex.schema.dropTable('reflinks')
};
