const Book = require("../../models/Book");

const getSingleBook = async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    if (!book) {
      return res.status(400).json({
        code: 400,
        message: `Can't find book with id: ${req.params.id}`,
        data: book,
      });
    }
    return res.status(200).json({
      code: 200,
      message: `You find your book with id: ${req.params.id}`,
      data: book,
    });
  } catch (error) {
    return res.status(400).json({
      code: 400,
      message: error.message,
    });
  }
};

module.exports = getSingleBook;
