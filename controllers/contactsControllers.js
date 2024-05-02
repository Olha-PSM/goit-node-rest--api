import Contact from "../models/contacts.js";
import HttpError from "../helpers/HttpError.js";
import {
  createContactSchema,
  updateContactSchema,
  updateStatusSchema,
} from "../schemas/contactsSchemas.js";

async function getAllContacts(req, res, next) {
  try {
    const result = await Contact.find({ owner: req.user.id });
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
}
async function getOneContact(req, res, next) {
  const { id } = req.params;
  const { _id: owner } = req.user;
  try {
    const result = await Contact.findById({ _id: id, owner });

    if (!result) {
      throw HttpError(404);
    }
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
}
async function createContact(req, res, next) {
  const contact = {
    name: req.body.name,
    email: req.body.email,
    phone: req.body.phone,
    favorite: req.body.favorite,
    owner: req.user.id,
  };
  try {
    const { error } = createContactSchema.validate(req.body);
    if (error) throw HttpError(400, error.message);
    const result = await Contact.create(contact);

    res.status(201).json(result);
  } catch (error) {
    next(error);
  }
}
async function updateContact(req, res, next) {
  const { id } = req.params;

  const contact = {
    name: req.body.name,
    email: req.body.email,
    phone: req.body.phone,
    favorite: req.body.favorite,
  };

  try {
    const { error } = updateContactSchema.validate(req.body);
    if (error) throw HttpError(400, error.message);
    if (Object.keys(req.body).length === 0) {
      throw HttpError(400, "Body must have at least one field");
    }
    const result = await Contact.findByIdAndUpdate(id, contact, { new: true });
    if (!result) {
      throw HttpError(404);
    }
    if (result.owner.toString() !== req.user._id.toString()) {
      return res.status(404).json("Contact not found");
    }
    res.json(result);
  } catch (error) {
    next(error);
  }
}
async function deleteContact(req, res, next) {
  const { id } = req.params;

  try {
    const result = await Contact.findByIdAndDelete(id);

    if (!result) {
      throw HttpError(404);
    }
    if (result.owner.toString() !== req.user.id) {
      return res.status(404).send("Contact not found");
    }
    res.json({ id });
  } catch (error) {
    next(error);
  }
}

async function updateFavorite(req, res, next) {
  const { id } = req.params;
  const { favorite } = req.body;

  try {
    const result = await Contact.findByIdAndUpdate(
      id,
      { favorite },
      { new: true }
    );
    const { error } = updateStatusSchema.validate(req.body);
    if (error) throw HttpError(400, error.message);
    if (!result) {
      throw HttpError(404, "Not found");
    }
    if (result.owner.toString() !== req.user._id.toString()) {
      return res.status(404).json("Contact not found");
    }
    res.status(200).json(result);
  } catch (error) {
    next(error);
  }
}

export default {
  getAllContacts,
  getOneContact,
  createContact,
  updateContact,
  deleteContact,
  updateFavorite,
};






