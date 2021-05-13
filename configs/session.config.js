const session = require('express-session');
const MongoDbStore = require('connect-mongo')
module.exports = app => {
  app.use(
    session({
      secret: process.env.SESS_SECRET,
      resave: true,
      saveUninitialized: false,
      cookie: {
        sameSite: true,
        httpOnly: true,
        maxAge: 60000 // 60 * 1000 ms === 1 min
      },
      store: MongoDbStore.create({
        mongoUrl: process.env.MONGODB_URL
        })
    })
  );
};