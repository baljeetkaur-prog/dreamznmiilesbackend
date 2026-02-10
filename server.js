const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt"); // for secure password hashing
require("dotenv").config();
const axios = require("axios");
const nodemailer = require("nodemailer");
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);



const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const multer = require("multer");

const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const path = require("path");

// const fileUpload = require("express-fileupload");



// ===== Cloudinary Config =====
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});


const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    if (file.mimetype === "application/pdf") {
      return {
        folder: "visa_uploads", // same as your preset
        resource_type: "raw"
      };
    } else {
      return {
        folder: "visa_uploads",
        resource_type: "image",
        allowed_formats: ["jpg", "jpeg", "png", "webp"]
      };
    }
  }
});


const upload = multer({ storage });

// const transporter = nodemailer.createTransport({
//   host: process.env.SMTP_HOST,
//   port: Number(process.env.SMTP_PORT),
//   secure: process.env.SMTP_SECURE === "true",
//   auth: {
//     user: process.env.SMTP_USER,
//     pass: process.env.SMTP_PASS,
//   },
// });

// transporter.verify()
//   .then(() => console.log("✅ Google Workspace SMTP is ready"))
//   .catch(err => console.error("❌ SMTP Error:", err));
  

// ===== Express App =====
const app = express();
app.use(cors());
app.use(express.json());
// app.use(fileUpload({
//   useTempFiles: true,      
//   tempFileDir: "/tmp/",     
// }));


// ===== MongoDB Connection =====
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.error("DB Connection Error:", err));

// ===== Admin Schema =====
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const Admin = mongoose.model("Admin", adminSchema);

// Create default admin
(async () => {
  try {
    const existingAdmin = await Admin.findOne({ username: process.env.ADMIN_USERNAME });
    if (!existingAdmin) {
      await Admin.create({
        username: process.env.ADMIN_USERNAME,
        password: process.env.ADMIN_PASSWORD
      });
      console.log("Default admin created");
    }
  } catch (err) {
    console.error("Error creating default admin:", err);
  }
})();

// ===== Admin Login =====
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    if (!admin || admin.password !== password) {
      return res.status(400).json({ error: "Invalid username or password" });
    }
    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post("/api/admin/change-password", async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    // Get the logged-in admin from token (assume you have auth middleware)
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.id);
    if (!admin) return res.status(404).json({ error: "Admin not found" });

    // Check old password
    if (admin.password !== oldPassword) {
      return res.status(400).json({ error: "Old password is incorrect" });
    }

    // Update password
    admin.password = newPassword;
    await admin.save();

    res.json({ message: "Password changed successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== Destination Schema =====
const destinationSchema = new mongoose.Schema({
  title: { type: String, required: true },
  images: [String],
  thumbnail: String,
  price: Number,
  days: String,
  shortDescription: String,
  highlights: [String],
  inclusions: [String],
  exclusions: [String],
  itinerary: [
    { day: String, title: String, description: String }
  ],
  hotels: [
    { city: String, name: String, rating: String, nights: Number }
  ],
  availableDates: [String],
  transportation: [String],
  pricing: {
    adult: Number,
    child: Number,
    singleSupplement: Number
  },
  policies: {
    cancellation: [String],
    payment: [String]
  },
  termsConditions: [String],
  location: {
    country: String,
    city: String,
    coordinates: { lat: Number, lng: Number }
  },
  activities: [
    { name: String, description: String, duration: String, location: String, included: [String], images: [String] }
  ]
}, { timestamps: true });

const Destination = mongoose.model("Destination", destinationSchema);

// ===== Destination Routes =====

// Get all packages
app.get("/api/admin/packages", async (req, res) => {
  try {
    const packages = await Destination.find();
    res.json(packages);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get package by ID
app.get("/api/admin/packages/:id", async (req, res) => {
  try {
    const pkg = await Destination.findById(req.params.id);
    if (!pkg) return res.status(404).json({ message: "Package not found" });
    res.json(pkg);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Add new package
app.post(
  "/api/admin/packages",
  upload.fields([
    { name: "thumbnail", maxCount: 1 },
    { name: "images", maxCount: 10 },
    { name: "activityImages", maxCount: 50 },
  ]),
  async (req, res) => {
    try {
      const data = { ...req.body };

      // Parse JSON fields safely
      const jsonFields = [
        "itinerary",
        "hotels",
        "activities",
        "pricing",
        "policies",
        "location",
        "termsConditions",
        "highlights",
        "inclusions",
        "exclusions",
        "availableDates",
        "transportation",
      ];

      jsonFields.forEach((field) => {
        if (data[field] && typeof data[field] === "string") {
          try {
            data[field] = JSON.parse(data[field]);
          } catch (err) {
            console.warn(`Failed to parse field ${field}:`, err.message);
            data[field] = Array.isArray(data[field]) ? data[field] : [];
          }
        }
      });

      // Generate a unique ID
      data.id = uuidv4();

      // Handle thumbnail
      if (req.files.thumbnail?.length) {
        data.thumbnail = req.files.thumbnail[0].path;
      }

      // Handle package images
      if (req.files.images?.length) {
        data.images = req.files.images.map((f) => f.path);
      }

      // Handle activity images
      if (data.activities && req.files.activityImages?.length) {
        let imgIdx = 0;
        data.activities.forEach((act) => {
          const count = act.imageCount || 1; // optional: can be sent from frontend
          act.images = req.files.activityImages
            .slice(imgIdx, imgIdx + count)
            .map((f) => f.path);
          imgIdx += count;
        });
      }

      // Save to MongoDB
      const newPackage = new Destination(data);
      await newPackage.save();

      res.json({ success: true, message: "Package added successfully", package: newPackage });
    } catch (err) {
      console.error("Error saving package:", err);
      res.status(500).json({ success: false, message: err.message });
    }
  }
);
app.put(
  "/api/admin/packages/:id",
  upload.fields([
    { name: "thumbnail", maxCount: 1 },
    { name: "images", maxCount: 10 },
    { name: "activityImages", maxCount: 50 },
  ]),
  async (req, res) => {
    try {
      const existingPackage = await Destination.findById(req.params.id);
      if (!existingPackage)
        return res.status(404).json({ message: "Package not found" });

      const data = {};

      // Parse fields
      for (const key in req.body) {
        try {
          data[key] = JSON.parse(req.body[key]);
        } catch {
          data[key] = req.body[key];
        }
      }

      // Update thumbnail if new file uploaded
      if (req.files.thumbnail?.length) {
        data.thumbnail = req.files.thumbnail[0].path;
      } else {
        data.thumbnail = existingPackage.thumbnail;
      }

      // Merge images
      if (req.files.images?.length) {
        data.images = [...(existingPackage.images || []), ...req.files.images.map(f => f.path)];
      } else {
        data.images = existingPackage.images;
      }

      // Merge activity images
      if (Array.isArray(existingPackage.activities)) {
        data.activities = existingPackage.activities.map((act, idx) => {
          const existingImgs = act.images || [];
          let newImgs = [];

          if (data.activities?.[idx]?.images) {
            newImgs = data.activities[idx].images;
          }

          // Append new uploaded activity files
          const uploadedFiles = req.files.activityImages || [];
          const count = uploadedFiles.splice(0, newImgs.length).map(f => f.path);

          return {
            ...act,
            ...data.activities?.[idx],
            images: [...existingImgs, ...count]
          };
        });
      }

      const updatedPackage = await Destination.findByIdAndUpdate(
        req.params.id,
        data,
        { new: true }
      );

      res.json({ success: true, message: "Package updated successfully", package: updatedPackage });
    } catch (err) {
      console.error("Update Error:", err);
      res.status(500).json({ success: false, message: err.message });
    }
  }
);














app.delete("/api/admin/packages/:id", async (req, res) => {
  try {
    const pkg = await Destination.findById(req.params.id);
    if (!pkg) return res.status(404).json({ message: "Package not found" });

    // Collect all Cloudinary public IDs to delete
    const publicIds = [];

    // Thumbnail
    if (pkg.thumbnail) {
      publicIds.push(getPublicId(pkg.thumbnail));
    }

    // Main images
    if (Array.isArray(pkg.images)) {
      pkg.images.forEach(url => publicIds.push(getPublicId(url)));
    }

    // Activity images
    if (Array.isArray(pkg.activities)) {
      pkg.activities.forEach(act => {
        if (Array.isArray(act.images)) {
          act.images.forEach(url => publicIds.push(getPublicId(url)));
        }
      });
    }

    // Delete images from Cloudinary
    await Promise.all(publicIds.filter(Boolean).map(id => cloudinary.uploader.destroy(id)));


    // Delete from MongoDB
    await Destination.findByIdAndDelete(req.params.id);

    res.json({ success: true, message: "Package and images deleted" });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ message: err.message });
  }
});

// Helper: extract Cloudinary public ID from URL
function getPublicId(url) {
  try {
    // Remove query string
    const cleanUrl = url.split("?")[0];

    // Match folder/filename without extension, ignoring version
    const match = cleanUrl.match(/\/upload\/(?:v\d+\/)?(.+)\.\w+$/);
    if (!match) return null;

    return match[1]; // returns: destinations/tofahzbdxqjbtieyrkxd
  } catch (err) {
    console.error("Error extracting public_id from:", url, err);
    return null;
  }
}
app.get("/api/packagesearch", async (req, res) => {
  try {
    const { title, minPrice, maxPrice, days } = req.query;

    let filter = {};

    // Title filter (if provided)
    if (title && title.trim() !== "") {
      filter.title = { $regex: title, $options: "i" };
    }

    // Price filter
    if (minPrice && maxPrice) {
      filter.price = { $gte: Number(minPrice), $lte: Number(maxPrice) };
    }

    // Days filter
    if (days) {
      filter.days = days; // exact match
    }

    let results = await Destination.find(filter);

    res.json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});






app.get("/api/packageprices", async (req, res) => {
  try {
    const prices = await Destination.distinct("price"); // now numbers
    res.json(prices.sort((a, b) => a - b));
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

const hotelSchema = new mongoose.Schema({
  title: { type: String, required: true },
  images: [String],        // Array of Cloudinary URLs
  price: String,
  perPerson: String,
  location: String,
  reviews: Number,
  overview: String,
  popularAmenities: [String],
  highlights: [String],
  type: String,
  roomType: String,
}, { timestamps: true });

const Hotel = mongoose.model("Hotel", hotelSchema);
app.get("/api/admin/hotels", async (req, res) => {
  try {
    const hotels = await Hotel.find();
    res.json(hotels);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get hotel by ID
app.get("/api/admin/hotels/:id", async (req, res) => {
  try {
    const hotel = await Hotel.findById(req.params.id);
    if (!hotel) return res.status(404).json({ message: "Hotel not found" });
    res.json(hotel);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Add new hotel
app.post(
  "/api/admin/hotels",
  upload.array("images", 10), // multiple hotel images
  async (req, res) => {
    try {
      const data = { ...req.body };

      // Parse array fields safely if sent as JSON strings
      ["popularAmenities", "highlights"].forEach((field) => {
        if (data[field] && typeof data[field] === "string") {
          try {
            data[field] = JSON.parse(data[field]);
          } catch {
            data[field] = data[field].split(",").map((i) => i.trim());
          }
        }
      });

      // Handle images uploaded via Cloudinary
      if (req.files?.length) {
        data.images = req.files.map((f) => f.path);
      }

      const newHotel = new Hotel(data);
      await newHotel.save();
      res.json({ success: true, message: "Hotel added", hotel: newHotel });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: err.message });
    }
  }
);

// Update hotel
app.put(
  "/api/admin/hotels/:id",
  upload.array("images", 10),
  async (req, res) => {
    try {
      const data = {};

      // Only copy non-empty values
      for (const [key, value] of Object.entries(req.body)) {
        if (value === "" || value === "null" || value === null || value === undefined) {
          continue; // skip empty
        }
        data[key] = value;
      }

      // Parse array fields
      ["popularAmenities", "highlights"].forEach((field) => {
        if (data[field] && typeof data[field] === "string") {
          try {
            data[field] = JSON.parse(data[field]);
          } catch {
            data[field] = data[field].split(",").map((i) => i.trim());
          }
        }
      });

      // Parse existingImages JSON string
      const oldImages = req.body.existingImages ? JSON.parse(req.body.existingImages) : [];

      // New uploaded images
      const newImages = req.files ? req.files.map((f) => f.path) : [];

      // Merge
      data.images = [...oldImages, ...newImages];

      // Update only given fields
      const updatedHotel = await Hotel.findByIdAndUpdate(
        req.params.id,
        { $set: data },
        { new: true }
      );

      if (!updatedHotel) {
        return res.status(404).json({ message: "Hotel not found" });
      }

      res.json({ success: true, message: "Hotel updated", hotel: updatedHotel });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: err.message });
    }
  }
);



// Delete hotel
app.delete("/api/admin/hotels/:id", async (req, res) => {
  try {
    const hotel = await Hotel.findById(req.params.id);
    if (!hotel) return res.status(404).json({ message: "Hotel not found" });

    // Collect all Cloudinary public IDs
    const publicIds = [];

    // Hotel images
    if (Array.isArray(hotel.images)) {
      hotel.images.forEach(url => {
        const publicId = getPublicId(url);
        if (publicId) publicIds.push(publicId);
      });
    }

    // Delete images from Cloudinary
    await Promise.all(publicIds.map(id => cloudinary.uploader.destroy(id)));

    // Delete hotel from MongoDB
    await Hotel.findByIdAndDelete(req.params.id);

    res.json({ success: true, message: "Hotel and images deleted" });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ message: err.message });
  }
});

// Helper: extract Cloudinary public ID from URL
function getPublicId(url) {
  try {
    // Remove query string
    const cleanUrl = url.split("?")[0];

    // Match folder/filename without extension, ignoring version
    const match = cleanUrl.match(/\/upload\/(?:v\d+\/)?(.+)\.\w+$/);
    if (!match) return null;

    return match[1]; // e.g., hotels/abc123xyz
  } catch (err) {
    console.error("Error extracting public_id from:", url, err);
    return null;
  }
}
// Visa Schema
const visaSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    image: { type: String },           // Cloudinary URL
    visaType: { type: String },
    validity: { type: String },
    processingTime: { type: String },
    visaMode: { type: String },
    country: { type: String },
    overview: { type: String },
    requiredDocuments: [{ type: String }],
  },
  { timestamps: true }
);

const Visa = mongoose.model("Visa", visaSchema, "visa");

// Helper: extract Cloudinary public ID from URL
function getPublicId(url) {
  try {
    const cleanUrl = url.split("?")[0];
    const match = cleanUrl.match(/\/upload\/(?:v\d+\/)?(.+)\.\w+$/);
    return match ? match[1] : null;
  } catch (err) {
    console.error("Error extracting public_id from:", url, err);
    return null;
  }
}

// GET all visas
app.get("/api/admin/visas", async (req, res) => {
  try {
    const visas = await Visa.find();
    res.json({ success: true, visas });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET visa by ID
app.get("/api/admin/visas/:id", async (req, res) => {
  try {
    const v = await Visa.findById(req.params.id);
    if (!v) return res.status(404).json({ success: false, message: "Visa not found" });

    const visaData = {
      ...v.toObject(),
      requiredDocuments: Array.isArray(v.requiredDocuments) ? v.requiredDocuments : [],
      image: v.image || ""
    };

    res.json({ success: true, visa: visaData });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ADD new visa
// POST
app.post(
  "/api/admin/visas",
  upload.fields([{ name: "image", maxCount: 1 }]), // Use fields instead of single
  async (req, res) => {
    try {
      const data = { ...req.body };

      // ===== Handle image upload =====
      if (req.files?.image?.length) {
        const file = req.files.image[0];
        const url = file.path || file.filename || file.secure_url;
        if (!url) {
          return res
            .status(400)
            .json({ success: false, message: "Image upload failed" });
        }
        data.image = url;
      } else if (req.body.existingImage) {
        data.image = req.body.existingImage;
      } else {
        data.image = ""; // default if no image
      }

      // ===== Handle requiredDocuments =====
      if (data.requiredDocuments) {
        if (typeof data.requiredDocuments === "string") {
          try {
            data.requiredDocuments = JSON.parse(data.requiredDocuments);
          } catch {
            data.requiredDocuments = data.requiredDocuments
              .split(",")
              .map((d) => d.trim())
              .filter((d) => d);
          }
        }
      } else {
        data.requiredDocuments = [];
      }

      // ===== Save to MongoDB =====
      const newVisa = new Visa(data);
      await newVisa.save();

      res.json({
        success: true,
        message: "Visa added successfully",
        visa: newVisa,
      });
    } catch (err) {
      console.error("Error in POST /api/admin/visas:", err);
      res.status(500).json({ success: false, message: err.message });
    }
  }
);




// PUT (update)
app.put("/api/admin/visas/:id", upload.single("image"), async (req, res) => {
  try {
    const data = { ...req.body };

    if (req.file) data.image = req.file.path;
    if (!req.file && req.body.existingImage) data.image = req.body.existingImage;

    if (data.requiredDocuments) {
      if (typeof data.requiredDocuments === "string") {
        try {
          data.requiredDocuments = JSON.parse(data.requiredDocuments);
        } catch {
          data.requiredDocuments = data.requiredDocuments
            .split(",")
            .map(d => d.trim())
            .filter(d => d);
        }
      }
    } else {
      data.requiredDocuments = [];
    }

    const updatedVisa = await Visa.findByIdAndUpdate(req.params.id, data, { new: true });

    res.json({ success: true, message: "Visa updated successfully", visa: updatedVisa });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});
;

// DELETE visa
app.delete("/api/admin/visas/:id", async (req, res) => {
  try {
    const v = await Visa.findById(req.params.id);
    if (!v) return res.status(404).json({ success: false, message: "Visa not found" });

    // Delete image from Cloudinary
    if (v.image) {
      const publicId = getPublicId(v.image);
      if (publicId) await cloudinary.uploader.destroy(publicId);
    }

    await Visa.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Visa deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});


const flightSchema = new mongoose.Schema(
  {
    flightNumber: { type: String, required: true },
    airline: { type: String, required: true },
    logo: { type: String }, // Cloudinary URL or file path

    departure: {
      iataCode: { type: String, required: true },
      time: { type: String, required: true },
    },

    arrival: {
      iataCode: { type: String, required: true },
      time: { type: String, required: true },
    },

    duration: { type: String }, // e.g., "2h 30m"

    services: [
      {
        type: { type: String, required: true }, // Classic, Value, Flex
        price: { type: Number, required: true },
        features: [{ type: String }],
      },
    ],
  },
  { timestamps: true }
);

const Flight = mongoose.model("Flight", flightSchema, "flights");
async function fetchAmadeusFlights(origin, destination, departureDate) {
  try {
    const tokenResponse = await axios.post(
      "https://test.api.amadeus.com/v1/security/oauth2/token",
      new URLSearchParams({
        grant_type: "client_credentials",
        client_id: process.env.AMADEUS_CLIENT_ID,
        client_secret: process.env.AMADEUS_CLIENT_SECRET,
      })
    );

    const token = tokenResponse.data.access_token;

    const response = await axios.get(
      "https://test.api.amadeus.com/v2/shopping/flight-offers",
      {
        headers: { Authorization: `Bearer ${token}` },
        params: {
          originLocationCode: origin.toUpperCase(),
          destinationLocationCode: destination.toUpperCase(),
          departureDate,
          adults: 1,
          max: 10,
        },
      }
    );

    // Map Amadeus response to your MongoDB schema format
    const flights = response.data.data.map((f) => ({
      flightNumber: f.itineraries[0]?.segments[0]?.flightNumber || "N/A",
      airline: f.itineraries[0]?.segments[0]?.carrierCode || "N/A",
      logo: "", // optional, you can map carrier logos if you have them
      departure: {
        iataCode: f.itineraries[0]?.segments[0]?.departure.iataCode || "",
        time: f.itineraries[0]?.segments[0]?.departure.at || "",
      },
      arrival: {
        iataCode: f.itineraries[0]?.segments[0]?.arrival.iataCode || "",
        time: f.itineraries[0]?.segments[0]?.arrival.at || "",
      },
      duration: f.itineraries[0]?.duration?.replace("PT", "").toLowerCase() || "",
      services: [
        {
          type: "Standard",
          price: f.price?.total || 0,
          features: [],
        },
      ],
    }));

    return flights;
  } catch (err) {
    console.error("Amadeus API error:", err.response?.data || err.message);
    return [];
  }
}


// CREATE flight
app.post("/api/flights", upload.single("logo"), async (req, res) => {
  try {
    const { flightNumber, airline, departure, arrival, duration, services } = req.body;

    const flight = new Flight({
      flightNumber,
      airline,
      duration,
      departure: JSON.parse(departure),
      arrival: JSON.parse(arrival),
      services: JSON.parse(services),
      logo: req.file ? req.file.path : null,
    });

    await flight.save();
    res.status(201).json({ success: true, flight });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to add flight" });
  }
});

// GET all flights
app.get("/api/flights", async (req, res) => {
  try {
    const flights = await Flight.find();
    res.json({ success: true, flights });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to get flights" });
  }
});

// GET single flight
app.get("/api/flight/:id", async (req, res) => {
  try {
    const flight = await Flight.findById(req.params.id);
    if (!flight)
      return res.status(404).json({ success: false, message: "Flight not found" });
    res.json({ success: true, flight });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to get flight" });
  }
});

// UPDATE flight
app.put("/api/flight/:id", upload.single("logo"), async (req, res) => {
  try {
    const { flightNumber, airline, departure, arrival, duration, services, existingLogo } = req.body;

    const updatedFlight = await Flight.findByIdAndUpdate(
      req.params.id,
      {
        flightNumber,
        airline,
        duration,
        departure: JSON.parse(departure),
        arrival: JSON.parse(arrival),
        services: JSON.parse(services),
        logo: req.file ? req.file.path : existingLogo || null,
      },
      { new: true }
    );

    if (!updatedFlight)
      return res.status(404).json({ success: false, message: "Flight not found" });
    res.json({ success: true, flight: updatedFlight });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to update flight" });
  }
});

// DELETE flight
app.delete("/api/flight/:id", async (req, res) => {
  try {
    const flight = await Flight.findById(req.params.id);
    if (!flight) return res.status(404).json({ success: false, message: "Flight not found" });

    // Delete image (logo) from Cloudinary
    if (flight.logo) {
      const publicId = getPublicId(flight.logo);
      if (publicId) await cloudinary.uploader.destroy(publicId);
    }

    await Flight.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Flight deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});
// SEARCH flights
app.get("/api/flights/search", async (req, res) => {
  try {
    const { origin, destination, departureDate, source } = req.query;

    if (!origin || !destination) {
      return res.status(400).json({ success: false, message: "Origin and destination required" });
    }

    let flights = [];

    if (source === "amadeus") {
      // Fetch live flights from Amadeus
      flights = await fetchAmadeusFlights(origin, destination, departureDate);
    } else {
      // Fetch from MongoDB
      const query = {
        "departure.iataCode": origin.toUpperCase(),
        "arrival.iataCode": destination.toUpperCase(),
      };
      if (departureDate) query.departureDate = departureDate;

      const dbFlights = await Flight.find(query);
      flights = dbFlights.map(f => f.toObject());
    }

    res.json({ success: true, flights });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to search flights" });
  }
});


const querySchema = new mongoose.Schema({
  name: String,
  email: String,
  phone: String,
  package: String,
  travelFrom: Date,
  travelTo: Date,
  adults: Number,
  children: Number,
  budget: String,
  message: String,
  date: { type: Date, default: Date.now },
});

const Query = mongoose.model("Query", querySchema);

// Simple HTML escape
function escapeHtml(text = "") {
  return text
    .toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Only Formspree submission
app.post("/api/query", async (req, res) => {
  const { name, email, phone, package: pkg, travelFrom, travelTo, adults, children, budget, message } = req.body;

  try {
    // Save in DB (optional)
    const newQuery = new Query({ name, email, phone, package: pkg, travelFrom, travelTo, adults, children, budget, message });
    await newQuery.save();

    // Send to Formspree
    const FORMSPREE_URL = process.env.FORMSPREE_URL || "https://formspree.io/f/xrbajbog";

    await axios.post(FORMSPREE_URL, { name, email, phone, package: pkg, travelFrom, travelTo, adults, children, budget, message }, {
      headers: { "Content-Type": "application/json" },
    });

    res.status(201).json({ message: "Query submitted successfully via Formspree & saved in DB!" });
  } catch (err) {
    console.error("Formspree submission failed:", err);
    res.status(500).json({ error: "Failed to submit query via Formspree." });
  }
});

// Fetch queries (admin)
app.get("/api/query", async (req, res) => {
  try {
    const queries = await Query.find().sort({ date: -1 });
    res.json(queries);
  } catch (err) {
    console.error("Error fetching queries:", err);
    res.status(500).json({ error: "Failed to fetch queries" });
  }
});

app.get("/api/admin/stats", async (req, res) => {
  try {
    const [packages, hotels, visas, flights, enquiries] = await Promise.all([
      Destination.countDocuments(),
      Hotel.countDocuments(),
      Visa.countDocuments(),
      Flight.countDocuments(),
      Query.countDocuments(), // ✅ total enquiries from Query collection
    ]);

    res.json({
      packages,
      hotels,
      visas,
      flights,
      enquiries,
    });
  } catch (err) {
    console.error("Error fetching stats:", err);
    res.status(500).json({ message: "Error fetching stats" });
  }
});
app.get("/api/query/monthly", async (req, res) => {
  try {
    const monthly = await Query.aggregate([
      {
        $group: {
          _id: { $month: "$date" },
          total: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    // Map month numbers to names
   const monthNames = [
  "January","February","March","April","May","June",
  "July","August","September","October","November","December"
];
    const formatted = monthly.map(m => ({
      month: monthNames[m._id - 1],
      enquiries: m.total
    }));

    res.json(formatted);
  } catch (err) {
    console.error("Error fetching monthly queries:", err);
    res.status(500).json({ error: "Failed to fetch monthly enquiries" });
  }
});
const activitySchema = new mongoose.Schema({
  title: { type: String, required: true },       // Activity name
  type: { type: String, required: true },        // e.g., Adventure, Sightseeing, Cultural
  description: { type: String, required: true }, // Full description
  schedules: [String],                           // Multiple timings
  price: { type: String, required: true },       // e.g., "₹2000" or "$50"
  location: { type: String },                    // Where the activity is located
  images: [String],                              // Array of Cloudinary URLs
  highlights: [String],                          // Key points or features of activity
}, { timestamps: true });

const Activity = mongoose.model("Activity", activitySchema);
app.get("/api/admin/activities", async (req, res) => {
  try {
    const activities = await Activity.find();
    res.json(activities);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get activity by ID
app.get("/api/admin/activities/:id", async (req, res) => {
  try {
    const activity = await Activity.findById(req.params.id);
    if (!activity) return res.status(404).json({ message: "Activity not found" });
    res.json(activity);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Add new activity
app.post(
  "/api/admin/activities",
  upload.array("images", 10),
  async (req, res) => {
    try {
      const data = { ...req.body };

      // Parse array fields
      ["highlights", "schedules"].forEach((field) => {
        if (data[field] && typeof data[field] === "string") {
          try {
            data[field] = JSON.parse(data[field]);
          } catch {
            data[field] = data[field].split(",").map((i) => i.trim());
          }
        }
      });

      // Handle images uploaded via Cloudinary
      if (req.files?.length) {
        data.images = req.files.map((f) => f.path);
      }

      const newActivity = new Activity(data);
      await newActivity.save();

      res.json({ success: true, message: "Activity added", activity: newActivity });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: err.message });
    }
  }
);

// Update activity
app.put(
  "/api/admin/activities/:id",
  upload.array("images", 10),
  async (req, res) => {
    try {
      const data = {};

      // Copy only non-empty fields
      for (const [key, value] of Object.entries(req.body)) {
        if (value !== "" && value !== "null" && value !== null && value !== undefined) {
          data[key] = value;
        }
      }

      // Parse array fields
      ["highlights", "schedules"].forEach((field) => {
        if (data[field] && typeof data[field] === "string") {
          try {
            data[field] = JSON.parse(data[field]);
          } catch {
            data[field] = data[field].split(",").map((i) => i.trim());
          }
        }
      });

      // Merge images
      const oldImages = req.body.existingImages ? JSON.parse(req.body.existingImages) : [];
      const newImages = req.files ? req.files.map((f) => f.path) : [];
      data.images = [...oldImages, ...newImages];

      const updatedActivity = await Activity.findByIdAndUpdate(
        req.params.id,
        { $set: data },
        { new: true }
      );

      if (!updatedActivity) return res.status(404).json({ message: "Activity not found" });

      res.json({ success: true, message: "Activity updated", activity: updatedActivity });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: err.message });
    }
  }
);


// Delete activity
app.delete("/api/admin/activities/:id", async (req, res) => {
  try {
    const activity = await Activity.findById(req.params.id);
    if (!activity) return res.status(404).json({ message: "Activity not found" });

    // Collect all Cloudinary public IDs
    const publicIds = [];

    // Activity images
    if (Array.isArray(activity.images)) {
      activity.images.forEach(url => {
        const publicId = getPublicId(url);
        if (publicId) publicIds.push(publicId);
      });
    }

    // Delete images from Cloudinary
    await Promise.all(publicIds.map(id => cloudinary.uploader.destroy(id)));

    // Delete activity from MongoDB
    await Activity.findByIdAndDelete(req.params.id);

    res.json({ success: true, message: "Activity and images deleted" });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ message: err.message });
  }
});
// const visaQuerySchema = new mongoose.Schema(
//   {
//     visaId: { type: mongoose.Schema.Types.ObjectId, ref: "Visa", required: true },
//     name: { type: String, required: true },
//     email: { type: String, required: true },
//     phone: { type: String, required: true },
//     message: { type: String },
//     documents: [{ type: String }] // only file names
//   },
//   { timestamps: true }
// );

// const visaqueries= mongoose.model("VisaQuery", visaQuerySchema);
// app.post(
//   "/api/submit-documents",
//   upload.array("documents"), // "documents" matches the field name from frontend
//   async (req, res) => {
//     try {
//       const { visaId, name, email, phone, message, documentFields } = req.body;

//       if (!visaId || !name || !email || !phone) {
//         return res.status(400).json({ error: "Missing required fields" });
//       }

//       const visa = await mongoose.model("Visa").findById(visaId).select("name");
//       if (!visa) return res.status(404).json({ error: "Visa not found" });

//       if (!req.files || req.files.length === 0) {
//         return res.status(400).json({ error: "No documents uploaded" });
//       }

//       const fields = Array.isArray(documentFields)
//         ? documentFields
//         : [documentFields];

//       const uploadedDocs = [];

//       for (let i = 0; i < req.files.length; i++) {
//         const file = req.files[i];
//         const fieldName = fields[i] || file.originalname.split(".")[0];

//         const result = await cloudinary.uploader.upload_stream(
//           { folder: "visa_uploads", resource_type: "raw", public_id: file.originalname.replace(/\.[^/.]+$/, "") },
//           (err, result) => {
//             if (err) throw err;
//             uploadedDocs.push({
//               field: fieldName,
//               url: result.secure_url,
//               name: file.originalname,
//             });
//           }
//         );

//         // Use buffer stream
//         const stream = require("stream");
//         const bufferStream = new stream.PassThrough();
//         bufferStream.end(file.buffer);
//         bufferStream.pipe(result);
//       }

//       const newVisaQuery = new visaqueries({
//         visaId,
//         name,
//         email,
//         phone,
//         message,
//         documents: uploadedDocs.map(d => d.url),
//       });
//       await newVisaQuery.save();

//       res.status(201).json({
//         message: "Visa query saved & emails sent successfully!",
//         documents: uploadedDocs,
//       });
//     } catch (err) {
//       console.error("Visa query error:", err);
//       res.status(500).json({ error: "Failed to submit visa query" });
//     }
//   }
// );






// Admin fetch all visa queries
app.get("/api/admin/visa-queries", async (req, res) => {
  try {
    const queries = await visaqueries.find().populate("visaId").sort({ createdAt: -1 });
    res.json(queries);
  } catch (err) {
    console.error("Fetch visa queries error:", err);
    res.status(500).json({ error: "Failed to fetch visa queries" });
  }
});
const contactQuerySchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String, required: true },
    message: { type: String, required: true },
    date: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const ContactQuery = mongoose.model("ContactQuery", contactQuerySchema);

// Formspree URL
const FORMSPREE_URL = process.env.FORMSPREE_URL;

// Contact route (Formspree only)
app.post("/api/contact", async (req, res) => {
  const { name, email, phone, message } = req.body;

  try {
    // Send to Formspree
    await axios.post(FORMSPREE_URL, { name, email, phone, message }, {
      headers: { "Content-Type": "application/json" },
    });

    // Optional: save in DB for record
    const newQuery = new ContactQuery({ name, email, phone, message });
    await newQuery.save();

    res.status(201).json({ message: "Message sent via Formspree & saved in DB!" });
  } catch (err) {
    console.error("Formspree failed:", err);
    res.status(500).json({ error: "Failed to submit message via Formspree." });
  }
});

// Admin fetch (DB only)
app.get("/admin/contacts", async (req, res) => {
  try {
    const contacts = await ContactQuery.find().sort({ date: -1 });
    res.json(contacts);
  } catch (err) {
    console.error("Fetch contact error:", err);
    res.status(500).json({ error: "Failed to fetch queries" });
  }
});

// Health check
app.get("/health", (req, res) => res.status(200).send("ok"));

// Start server
const PORT = process.env.PORT || 9000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
