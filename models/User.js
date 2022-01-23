const {model, Schema} = require('mongoose');

const userSchema = Schema(
  {
    email: {
      type: String,
      required: [true, 'Please add an email'],
      unique: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, 'Please add a password'],
      trim: true,
    },
    firstName: {
      type: String,
      default: 'John',
    },
    lastName: {
      type: String,
      default: 'Doe',
    },
    phone: {
      type: String,
      unique: true,
      required: true,
    },
    token: {
      type: String,
    },
    roles: [
      {
        type: String,
        ref: 'Role',
      },
    ],
  },
  {versionKey: false, timestamps: true}
);

module.exports = model('user', userSchema);
