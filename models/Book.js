const { model, Schema } = require("mongoose");

const bookSchema = Schema(
  {
    author: {
      type: String,
      required: [true, "Please add an author"],
      trim: true,
      maxLength: [20, "Max length 20 signs"],
    },
    title: {
      type: String,
      required: [true, "Please add a title"],
      trim: true,
      maxLength: [50, "Max length 50 signs"],
    },
    language: {
      type: String,
      enum: ["it", "ua", "en"],
    },
    link: {
      type: String,
    },
    year: {
      type: Number,
    },
  },
  { versionKey: false, timestamps: true }
);

module.exports = model("book", bookSchema);
