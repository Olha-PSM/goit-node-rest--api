import * as fs from "node:fs/promises";
import * as path from "node:path";

import crypto from "crypto";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Jimp from "jimp";

import User from "../models/users.js";
import HttpError from "../helpers/HttpError.js";
import { userLoginSchema, userRegisterSchema } from "../models/users.js";
const { JWT_SECRET } = process.env;

async function register(req, res, next) {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    const { error } = userRegisterSchema.validate(req.body);
    if (error) throw HttpError(400, error.message);
    if (user !== null) {
      return res.status(409).send({ message: "Email in use" });
    }

    const emailHash = crypto.createHash("md5").update(email).digest("hex");

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      email,
      password: passwordHash,
      avatarURL: `https://gravatar.com/avatar/${emailHash}.jpg?d=robohash`,
    });

    res.status(201).json({
      email: newUser.email,
      subscription: newUser.subscription,
      avatarURL: newUser.avatarURL,
    });
  } catch (error) {
    next(error);
  }
}
async function login(req, res, next) {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    const { error } = userLoginSchema.validate(req.body);
    if (error) throw HttpError(400, error.message);
    if (!user) {
      return res.status(401).send({ message: "Email or password is wrong" });
    }
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch === false) {
      return res.status(401).send({ message: "Email or password is wrong" });
    }

    const payload = { id: user._id, name: user.name };
    const token = jwt.sign(payload, JWT_SECRET, {
      expiresIn: "23h",
    });
    await User.findByIdAndUpdate(user._id, { token });

    res.json({
      token,
      user: {
        email: user.email,
        subscription: user.subscription,
      },
    });
  } catch (error) {
    next(error);
  }
}
async function getCurrent(req, res) {
  const { email, subscription } = req.user;

  try {
    res.send({ email, subscription });
  } catch (error) {
    next(error);
  }
}

async function logout(req, res, next) {
  try {
    await User.findByIdAndUpdate(req.user.id, { token: null });

    res.status(204).end();
  } catch (error) {
    next(error);
  }
}

async function uploadAvatar(req, res, next) {
  const { id } = req.user;

  try {
    const { path: tmpUpload, originalname } = req.file;
    if (!req.file) {
      throw HttpError(400, "File not uploaded");
    }

    const filename = `${id}-${originalname}`;

    const changeSizeAvatar = await Jimp.read(tmpUpload);
    changeSizeAvatar.resize(250, 250).write(tmpUpload);

    await fs.rename(tmpUpload, path.join("public/avatars", filename));

    const avatarURL = path.join("/avatars", filename);

    const user = await User.findByIdAndUpdate(
      id,
      { avatarURL: avatarURL },
      { new: true }
    );
    if (user === null) {
      return res.status(404).send({ message: "User not found" });
    }

    res.json({ avatarURL: user.avatarURL });
  } catch (error) {
    next(error);
  }
}

export default { register, login, getCurrent, logout, uploadAvatar };
