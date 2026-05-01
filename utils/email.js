import axios from "axios";

export const sendOTPEmail = async (email, otp) => {
  try {
    await axios.post(
      "https://api.brevo.com/v3/smtp/email",
      {
        sender: {
          name: "Worklance",
          email: process.env.EMAIL_FROM.replace(/.*<|>/g, "")
        },
        to: [{ email }],
        subject: "Your OTP Code",
        htmlContent: `
          <div style="font-family:sans-serif;">
            <h2>Your OTP Code</h2>
            <p>Your verification code is:</p>
            <h1>${otp}</h1>
            <p>This code expires in 5 minutes.</p>
          </div>
        `,
      },
      {
        headers: {
          "api-key": process.env.BREVO_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("Email sent successfully");
  } catch (error) {
    console.error("Brevo API error:", error.response?.data || error.message);
  }
};