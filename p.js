const axios = require("axios");

const url = "https://pnr.phinisipoint.com/submitRegis.php";

const params = new URLSearchParams({
  fullname: "Nama",
  gender: "Male",
  dob: "2000-11-11",
  wa: "62988228811",
  email: "aaeas@gmail.com",
  emergencyname: "nama",
  emergency: "62887837",
  jersey: "M",
  blood: "AB",
  price: "100",
  referral: "",
  tc: "agree",
  "submit-regis": "Submit"
});

async function submitRegistration() {
  try {
    const response = await axios.post(url, params.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      maxRedirects: 5
    });

    console.log("HTTP Status:", response.status);
    console.log("Respons:", response.data);
  } catch (error) {
    console.error(
      "Gagal mengirim:",
      error.response?.status || error.message
    );
  }
}

submitRegistration();