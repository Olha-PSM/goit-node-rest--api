import express from "express";
import AuthController from "../controllers/authControllers.js";
import auth from "../middlewares/auth.js";

const router = express.Router();
const jsonParser = express.json();
router.post("/register", jsonParser, AuthController.register);

router.post("/login", jsonParser, AuthController.login);
router.get("/current", auth, AuthController.getCurrent);
router.get("/logout", auth, AuthController.logout);

export default router;
