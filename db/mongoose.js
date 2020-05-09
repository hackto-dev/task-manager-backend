// This file will handle connection logic to the MongoDB database.
const mongoose = require('mongoose');

mongoose.Promise = global.Promise

mongoose.connect("mongodb://localhost:27017/TaskManager", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }).then(() => {
    console.log("Connected to MongoDB successfully!");
  })
  .catch((e) => {
    console.log("Error in connecting to database");
    console.log(e);
  });

// To prevent deprecation warnings (from Mongo native driver)
mongoose.set('useCreateIndex',true);
mongoose.set('useFindAndModify',false);

module.exports = {
    mongoose
};