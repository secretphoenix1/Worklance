import Otp from "../models/Otp.js";
import { sendOTPEmail } from "../utils/email.js";
console.log("OTP for", email, ":", otp);
router.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  const record = await Otp.findOne({ email });

  if (!record) return res.status(400).json({ message: "No OTP found" });

  if (record.otp !== otp)
    return res.status(400).json({ message: "Invalid OTP" });

  if (record.expiresAt < new Date())
    return res.status(400).json({ message: "OTP expired" });

  await Otp.deleteMany({ email });

  res.json({ success: true, message: "OTP verified" });
});
router.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  await Otp.deleteMany({ email });

  await Otp.create({
    email,
    otp,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
  });

  try {
    await sendOTPEmail(email, otp);
  } catch (err) {
    console.error("Email failed:", err.message);
  }

  // IMPORTANT: always respond
  res.json({ success: true, message: "OTP generated (email may fail)" });
});