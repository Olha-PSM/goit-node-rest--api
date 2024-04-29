import express from "express";
import AuthController from "../controllers/authControllers.js";
import auth from "../middlewares/auth.js";
import upload from "../middlewares/upload.js";

const router = express.Router();
const jsonParser = express.json();
router.post("/register", jsonParser, AuthController.register);

router.post("/login", jsonParser, AuthController.login);
router.get("/current", auth, AuthController.getCurrent);
router.post("/logout", auth, AuthController.logout);

router.patch(
  "/avatars",
  auth,
  upload.single("avatar"),
  AuthController.uploadAvatar
);

export default router;
