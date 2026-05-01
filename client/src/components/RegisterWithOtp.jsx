import { useEffect, useState } from "react";
import axios from "../utils/axios";

export default function RegisterWithOtp() {
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [isOtpSent, setIsOtpSent] = useState(false);
  const [isOtpVerified, setIsOtpVerified] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [message, setMessage] = useState("");
  const [messageType, setMessageType] = useState("info");
  const [cooldown, setCooldown] = useState(0);

  const isEmailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = window.setInterval(() => {
      setCooldown((current) => Math.max(0, current - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [cooldown]);

  const resetFeedback = () => {
    setMessage("");
    setMessageType("info");
  };

  const sendOtp = async () => {
    resetFeedback();
    if (!isEmailValid) {
      setMessage("Please enter a valid email address.");
      setMessageType("error");
      return;
    }

    setIsSending(true);
try {
  const response = await axios.post("/send-otp", { email });

  // ✅ use status instead of data.success
  if (response.status === 200) {
    setIsOtpSent(true);
    setMessage(response.data?.message || "OTP sent successfully. Please check your inbox or spam folder for the code.");
    setMessageType("success");
    setCooldown(45);
  } else {
    setMessage("Failed to send OTP. Please try again.");
    setMessageType("error");
  }

} catch (error) {
  console.error("OTP error:", error); // 🔥 important for debugging
  setMessage(error.response?.data?.message || "Unable to send OTP.");
  setMessageType("error");
} finally {
  setIsSending(false);
}
  };

  const verifyOtp = async () => {
    resetFeedback();
    if (!otp || otp.length !== 6) {
      setMessage("Please enter the 6-digit OTP.");
      setMessageType("error");
      return;
    }

    setIsVerifying(true);
    try {
      const response = await axios.post("/verify-otp", { email, otp });
      if (response.data?.success) {
        setIsOtpVerified(true);
        setMessage("OTP verified successfully. You can now create your account.");
        setMessageType("success");
      } else {
        setMessage("OTP verification failed. Please try again.");
        setMessageType("error");
      }
    } catch (error) {
      setMessage(error.response?.data?.message || "Unable to verify OTP.");
      setMessageType("error");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleGoogleSignup = () => {
    console.log("Google signup placeholder clicked");
  };

  return (
    <div className="max-w-xl rounded-3xl border border-slate-200 bg-white p-8 shadow-xl shadow-slate-200/40">
      <div className="mb-6">
        <p className="text-sm font-semibold uppercase tracking-[0.2em] text-indigo-600">Register</p>
        <h2 className="mt-3 text-3xl font-semibold text-slate-950">Create your account with OTP verification</h2>
        <p className="mt-2 text-sm leading-6 text-slate-500">Secure onboarding with email verification before account creation.</p>
      </div>

      <div className="space-y-5">
        <div>
          <label className="text-sm font-medium text-slate-700">Enter Gmail</label>
          <div className="mt-2 flex gap-2">
            <input
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                setIsOtpVerified(false);
              }}
              placeholder="Enter Gmail"
              className="input grow rounded-xl border-slate-300 bg-slate-50 px-4 py-3 text-sm outline-none transition focus:border-indigo-500 focus:bg-white"
            />
            <button
              type="button"
              onClick={sendOtp}
              disabled={isSending || cooldown > 0}
              className="inline-flex items-center justify-center rounded-xl bg-indigo-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500"
            >
              {isSending ? "Sending..." : cooldown > 0 ? `Resend ${cooldown}s` : "Send OTP"}
            </button>
          </div>
        </div>

        <div>
          <label className="text-sm font-medium text-slate-700">Enter OTP</label>
          <div className="mt-2 flex gap-2">
            <input
              type="text"
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, ""))}
              placeholder="Enter OTP"
              className="input grow rounded-xl border-slate-300 bg-slate-50 px-4 py-3 text-sm outline-none transition focus:border-indigo-500 focus:bg-white"
              maxLength={6}
            />
            <button
              type="button"
              onClick={verifyOtp}
              disabled={!isOtpSent || isVerifying}
              className="inline-flex items-center justify-center rounded-xl bg-slate-900 px-5 py-3 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500"
            >
              {isVerifying ? "Verifying..." : "Verify OTP"}
            </button>
          </div>
        </div>

        {message && (
          <div
            className={`rounded-2xl px-4 py-3 text-sm font-medium ${
              messageType === "success" ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"
            }`}
          >
            {message}
          </div>
        )}

        <button
          type="button"
          disabled={!isOtpVerified}
          className="w-full rounded-2xl bg-indigo-600 px-5 py-3 text-sm font-semibold text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-500"
        >
          Create Account
        </button>

        <div className="flex items-center gap-3">
          <span className="h-px flex-1 bg-slate-200" />
          <span className="text-sm text-slate-400">or continue with</span>
          <span className="h-px flex-1 bg-slate-200" />
        </div>

        <button
          type="button"
          onClick={handleGoogleSignup}
          className="mx-auto inline-flex h-14 w-14 items-center justify-center rounded-full border border-slate-200 bg-white shadow-sm transition hover:shadow-md"
          aria-label="Continue with Google"
        >
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M23.954 12.242c0-.816-.073-1.602-.209-2.362H12.24v4.467h6.448c-.278 1.48-1.106 2.73-2.356 3.57v2.965h3.808c2.238-2.064 3.518-5.09 3.518-8.64z" fill="#4285F4"/>
            <path d="M12.24 24c3.24 0 5.957-1.076 7.944-2.924l-3.808-2.964c-1.06.713-2.415 1.13-4.136 1.13-3.183 0-5.885-2.15-6.848-5.041H1.551v3.164C3.503 21.678 7.602 24 12.24 24z" fill="#34A853"/>
            <path d="M5.392 14.2a7.21 7.21 0 0 1 0-4.405V6.63H1.551a11.98 11.98 0 0 0 0 10.74l3.841-3.17z" fill="#FBBC05"/>
            <path d="M12.24 4.797c1.75 0 3.31.604 4.545 1.79l3.41-3.41C18.192 1.295 15.48 0 12.24 0 7.602 0 3.503 2.322 1.551 5.63l3.841 3.164C6.355 6.945 9.057 4.797 12.24 4.797z" fill="#EA4335"/>
          </svg>
        </button>
      </div>
    </div>
  );
}
