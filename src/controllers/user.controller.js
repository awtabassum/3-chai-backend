import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

// 5- make access token & refresh token in Log In Function
const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access tokens"
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  // 1- get user details from frontend
  // 2- validation - not empty, enail format etc
  // 3- check if user already exists: username, email
  // 4- check for images, check for avatar
  // 5- upload them to cloudinary - check avatar is uploaded successfully on cloudinary or not
  // 6- create user object - create entry in db
  // 7- remove password and refresh token field from response
  // 8- check for user creation
  // 9- return response, if user is created; else send error message

  // 1- get user details from frontend
  console.log("req.files:", req.files);
  const { fullName, email, username, password } = req.body;
  console.log("email: ", email);

  // 2- validation - not empty, enail format etc
  // if (fullName === "") {
  //   throw new ApiError(400, "fullName is required");
  // }
  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  // 3- check if user already exists: username, email

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });
  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }
  // 4- check for images, check for avatar
  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path;

  let coverImageLocalPath;

  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  // 5- upload them to cloudinary - check avatar is uploaded successfully on cloudinary or not
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);
  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  // 6- create user object - create entry in db
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  // 7- remove password and refresh token field from response
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  // 8- check for user creation
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registring the user");
  }

  // 9- return response, if user is created; else send error message
  return res.status(201).json(
    new ApiResponse(200, createdUser, "user registered Successfully") // making new object
  );
});

// Log In Code

const loginUser = asyncHandler(async (req, res) => {
  // 1- req body -> data
  // 2- want to give access to user on user name or email basis
  // 3- find the user; if it is coming in req.body
  // 4- check password if user is there
  // 5- If password is checked we will generate access token & refresh token &
  //    will send to user
  // 6- Send these tokens via cookies

  // 1- req body -> data
  const { email, username, password } = req.body;
  console.log(email);
  if (!(username || email)) {
    throw new ApiError(400, "username or email is required");
  }
  // 2- want to give access to user on user name or email basis
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });
  // 3- find the user; if it is coming in req.body
  if (!user) {
    throw new ApiError(404, "User does not exits");
  }
  // 4- check password if user is there
  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credential");
  }
  // 5- use access token & refresh token after calling it
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );
  // 6- Send these tokens via cookies
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in Successfully"
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );
  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "unauthorized request");
  }
  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, "Invalid Refresh Token");
    }
    if (incomingRefreshToken !== user.refreshToken) {
      throw new ApiError(401, "Refresh Token is expired or used");
    }

    const options = {
      httpOnly: true,
      secure: true,
    };
    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id);
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access Token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

export { registerUser, loginUser, logoutUser, refreshAccessToken };

/*
const registerUser = asyncHandler(async (req, res) => {
  // ...other code...

  // 4- check for images, check for avatar
  console.log("req.files:", req.files); // Log the req.files object
  let avatarLocalPath;
  let coverImageLocalPath;

  if (
    req.files &&
    req.files.avatar &&
    req.files.avatar[0] &&
    req.files.avatar[0].path
  ) {
    avatarLocalPath = req.files.avatar[0].path;
  } else {
    throw new ApiError(400, "Avatar file is required");
  }

  if (
    req.files &&
    req.files.coverImage &&
    req.files.coverImage[0] &&
    req.files.coverImage[0].path
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  console.log("avatarLocalPath:", avatarLocalPath); // Log the avatarLocalPath
  console.log("coverImageLocalPath:", coverImageLocalPath); // Log the coverImageLocalPath

  // 5- upload them to cloudinary - check avatar is uploaded successfully on cloudinary or not
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avatar upload failed or file is required");
  }

*/
