const Book = require("../../models/Book");

const addBook = async (req, res) => {
  try {
    const book = await Book.create(req.body);
    return res.status(201).json({
      code: 201,
      message: "Book created",
      data: book,
    });
  } catch (error) {
    return res.status(400).json({
      code: 400,
      message: error.message,
    });
  }
};

module.exports = addBook;
