const {connect} = require('mongoose');

const connectDB = async () => {
    const db = await connect(process.env.MONGODB_URI);
    // console.log(db.connection)
    console.log(`MongoDB are connected PORT: ${db.connection.port}, NAME: ${db.connection.name}, HOST: ${db.connection.host}`.cyan)
//  console.log(db)   
}

module.exports = connectDB;