const {model, Schema} = require('mongoose');

const roleSchema = Schema(
  {
    value: {
      type: String,
      required: true,
      default: 'USER',
      unique: true,
      trim: true,
    },
  },
  {versionKey: false, timestamps: true}
);

module.exports = model('role', roleSchema);
