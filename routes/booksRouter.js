const express = require('express');
const {books: booksController} = require('../controllers')
const router = express.Router();

const { getBooks, getSingleBook, addBook, deleteBook, updateBook } = booksController;

router.get('/', getBooks);
router.get('/:id', getSingleBook)
router.post('/', addBook)
router.put('/:id', updateBook)
router.delete('/:id', deleteBook)

module.exports = router;