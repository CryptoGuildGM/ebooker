import jwt from 'jsonwebtoken';
import { createError } from '../utils/error.js';

export const verifyToken = (req, res, next, callback) => {
  const token = req.cookies.access_token;

  if (!token) {
    return next(createError(401, 'Not Authenticated'));
  }

  jwt.verify(token, `${process.env.JWT}`, (err, user) => {
    if (err) return next(createError(403, 'Token not valid'));
    req.user = user;
    if (callback) {
      callback()
    } else {
      next();
    }
  });
};

export const verifyUser = (req, res, next) => {
  verifyToken(req, res, next, (err) => {
    if (err) return next(err);
    if (req.user.id === req.params.id || req.user.isAdmin) {
      next();
    } else {
      return next(createError(403, 'You are not authorised'));
    }
  });
};

export const verifyAdmin = (req, res, next) => {
  verifyToken(req, res, next, (err) => {
    if (err) return next(err);
    if (req.user && req.user.isAdmin) {
      next();
    } else {
      return next(createError(403, 'You are not authorised'));
    }
  });
};
