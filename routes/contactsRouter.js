import express from "express";
import ContactController from "../controllers/contactsControllers.js";
import isValidId from "../helpers/isValidid.js";
const router = express.Router();
const jsonParser = express.json();

router.get("/", ContactController.getAllContacts);

router.get("/:id", isValidId, ContactController.getOneContact);

router.post("/", jsonParser, ContactController.createContact);
router.patch(
  "/:id/favorite",
  jsonParser,
  isValidId,
  ContactController.updateFavorite
);

router.put("/:id", isValidId, jsonParser, ContactController.updateContact);

router.delete("/:id", isValidId, ContactController.deleteContact);
export default router;
