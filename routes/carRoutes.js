const express = require('express');
const multer = require('multer');
const { Car } = require('../models/models');
const router = express.Router();


const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    console.log('Saving to:', 'uploads/');
    cb(null, 'uploads/');
  },
  filename: (_req, file, cb) => {
    console.log('Saving file with name:', Date.now() + '-' + file.originalname);
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage,
  limits: { files: 10 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images are allowed'));
    }
  }
});

router.post('/', upload.array('images', 10), async (req, res) => {
  try {
    // console.log('Uploaded Files:', req.files); 
    const { title, description, tags } = req.body;
    const images = req.files.map(file => `/uploads/${file.filename}`);
    //console.log('Image paths:', images);

    const car = new Car({
      title,
      description,
      images,
      tags: JSON.parse(tags),
      user: req.user._id
    });

    await car.save();
    res.status(201).json(car);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error creating car' });
  }
});


router.get('/', async (req, res) => {
  try {
    const { search } = req.query;
    let query = { user: req.user._id };
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { 'tags.car_type': { $regex: search, $options: 'i' } },
        { 'tags.company': { $regex: search, $options: 'i' } },
        { 'tags.dealer': { $regex: search, $options: 'i' } }
      ];
    }

    const cars = await Car.find(query).sort('-createdAt');
    res.json(cars);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error fetching cars' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    console.log("Getting ")
    const car = await Car.findOne({ _id: req.params.id, user: req.user._id });
    if (!car) {
      return res.status(404).json({ message: 'Car not found' });
    }
    console.log(car);
    res.json(car);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error fetching car' });
  }
});

router.put('/:id', upload.array('images', 10), async (req, res) => {
  try {
    const { title, description, tags } = req.body;
    const car = await Car.findOne({ _id: req.params.id, user: req.user._id });
    
    if (!car) {
      return res.status(404).json({ message: 'Car not found' });
    }

    car.title = title || car.title;
    car.description = description || car.description;
    if (tags) car.tags = JSON.parse(tags);
    
    if (req.files?.length > 0) {
      car.images = req.files.map(file => `/uploads/${file.filename}`);
    }

    await car.save();
    res.json(car);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error updating car' });
  }
});

// Delete car
router.delete('/:id', async (req, res) => {
  try {
    const car = await Car.findOneAndDelete({ _id: req.params.id, user: req.user._id });
    if (!car) {
      return res.status(404).json({ message: 'Car not found' });
    }
    res.json({ message: 'Car deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error deleting car' });
  }
});

module.exports = router;