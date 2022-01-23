const Book = require("../../models/Book");

const updateBook = async (req, res) => {
   try {
       const book = await Book.findByIdAndUpdate(req.params.id, req.body, {
           new: true,
           runValidators: true
    });
    if (!book) {
      return res.status(400).json({
        code: 400,
        message: `Can't find book with id: ${req.params.id}`,
        data: book,
      });
    }
    return res.status(200).json({
      code: 200,
      message: `Book ${req.params.id} updated`,
      data: book,
    });
  } catch (error) {
    return res.status(400).json({
      code: 400,
      message: error.message,
    });
  }
}

module.exports = updateBook;