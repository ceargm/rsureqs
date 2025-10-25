// -------------------------
// Register Auth with live validation
// -------------------------
const registerForm = document.getElementById("registerForm");
const alertBox = document.getElementById("registerAlert");

// Inputs
const fullNameInput = document.getElementById("fullName");
const emailInput = document.getElementById("email");
const phoneInput = document.getElementById("phone");
const passwordInput = document.getElementById("registerPassword");
const confirmPasswordInput = document.getElementById("confirmPassword");
const confirmMsg = document.getElementById("confirmMsg");

// Add checklist elements for live validation
const passwordChecklist = {
  length: document.getElementById("length"),
  uppercase: document.getElementById("uppercase"),
  lowercase: document.getElementById("lowercase"),
  number: document.getElementById("number"),
  special: document.getElementById("special")
};

// Live validation for password
passwordInput.addEventListener("input", () => {
  const val = passwordInput.value;
  passwordChecklist.length.classList.toggle("valid", val.length >= 8);
  passwordChecklist.uppercase.classList.toggle("valid", /[A-Z]/.test(val));
  passwordChecklist.lowercase.classList.toggle("valid", /[a-z]/.test(val));
  passwordChecklist.number.classList.toggle("valid", /\d/.test(val));
  passwordChecklist.special.classList.toggle("valid", /[!@#$%^&*]/.test(val));
});

// Confirm password live check
confirmPasswordInput.addEventListener("input", () => {
  confirmMsg.classList.toggle("d-none", confirmPasswordInput.value === passwordInput.value);
});

// Live validation for fullname
fullNameInput.addEventListener("input", () => {
  const regex = /^[A-Za-z\s]{2,50}$/;
  fullNameInput.classList.toggle("is-valid", regex.test(fullNameInput.value));
  fullNameInput.classList.toggle("is-invalid", !regex.test(fullNameInput.value));
});

// Live validation for Gmail
emailInput.addEventListener("input", () => {
  const regex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
  emailInput.classList.toggle("is-valid", regex.test(emailInput.value));
  emailInput.classList.toggle("is-invalid", !regex.test(emailInput.value));
});

// Live validation for phone number
phoneInput.addEventListener("input", () => {
  const regex = /^09\d{9}$/;
  phoneInput.classList.toggle("is-valid", regex.test(phoneInput.value));
  phoneInput.classList.toggle("is-invalid", !regex.test(phoneInput.value));
});

// Form submit
registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const fullName = fullNameInput.value.trim();
  const email = emailInput.value.trim();
  const phone = phoneInput.value.trim();
  const password = passwordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  // Validation regex
  const fullnameRegex = /^[A-Za-z\s]{2,50}$/;
  const emailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
  const phoneRegex = /^09\d{9}$/;

  // Check fullname
  if (!fullnameRegex.test(fullName)) {
    alertBox.className = "alert alert-danger";
    alertBox.textContent = "Full Name must be 2-50 letters and spaces only.";
    alertBox.classList.remove("d-none");
    return;
  }

  // Check email
  if (!emailRegex.test(email)) {
    alertBox.className = "alert alert-danger";
    alertBox.textContent = "Email must be a valid Gmail address.";
    alertBox.classList.remove("d-none");
    return;
  }

  // Check phone
  if (!phoneRegex.test(phone)) {
    alertBox.className = "alert alert-danger";
    alertBox.textContent = "Phone number must start with 09 and be 11 digits.";
    alertBox.classList.remove("d-none");
    return;
  }

  // Check password
  const checklist = {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /\d/.test(password),
    special: /[!@#$%^&*]/.test(password)
  };

  if (Object.values(checklist).includes(false)) {
    alertBox.className = "alert alert-danger";
    alertBox.textContent = "Password does not meet requirements.";
    alertBox.classList.remove("d-none");
    return;
  }

  if (password !== confirmPassword) {
    alertBox.className = "alert alert-danger";
    alertBox.textContent = "Passwords do not match.";
    alertBox.classList.remove("d-none");
    return;
  }

  // Send registration request
  try {
    const response = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fullName, email, phone, password })
    });

    const data = await response.json();

    if (data.success) {
      alertBox.className = "alert alert-success";
      alertBox.textContent = "Registration successful! Redirecting to login...";
      alertBox.classList.remove("d-none");

      setTimeout(() => {
        window.location.href = "/login";
      }, 1500);
    } else {
      alertBox.className = "alert alert-danger";
      alertBox.textContent = data.message;
      alertBox.classList.remove("d-none");
    }
  } catch (error) {
    console.error("❌ Register error:", error);
    alertBox.className = "alert alert-danger";
    alertBox.textContent = "Something went wrong. Please try again.";
    alertBox.classList.remove("d-none");
  }
});
