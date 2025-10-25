// -------------------------
// Login Auth
// -------------------------

const loginForm = document.getElementById("loginForm");
const loginAlert = document.getElementById("loginAlert");

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const emailOrPhone = document.getElementById("emailOrPhone").value;
  const password = document.getElementById("loginPassword").value;

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ emailOrPhone, password }),
    });

    const data = await response.json();

    if (data.success) {
      // Store user id and fullname in localSTorage
      localStorage.setItem("userId", data.userId);
      localStorage.setItem("fullname", data.fullname);
      localStorage.setItem("phone", data.phone);
      localStorage.setItem("email", data.email);
      localStorage.setItem("loginTime", new Date().getTime()); // For session tracking
   

      // redirect to dashboard
      window.location.href = "/dashboard";
    } else {
      // Login failed: show alert
      loginAlert.classList.remove("d-none", "alert-success");
      loginAlert.classList.add("alert-danger");
      loginAlert.textContent = data.message;
    }
  } catch (err) {
    console.error("Error:", err);
    loginAlert.classList.remove("d-none", "alert-success");
    loginAlert.classList.add("alert-danger");
    loginAlert.textContent = "Something went wrong. Please try again.";
  }
});
