// ===== AUTHENTICATION CHECK =====
function checkAuthentication() {
  const userId = localStorage.getItem("userId");
  if (!userId) {
    // Not logged in → redirect to welcome page
    window.location.href = "/";
    return false;
  }
  return true;
}

// ===== UTILITY FUNCTIONS =====

// Auto logout functionality for security
let inactivityTimer;

function resetInactivityTimer() {
  // Clear existing timer
  clearTimeout(inactivityTimer);

  // Set new timer (30 minutes = 1800000 ms)
  inactivityTimer = setTimeout(logout, 1800000); // 30 minutes
}

function logout() {
  // Remove user data from localStorage
  localStorage.removeItem("fullname");
  localStorage.removeItem("userId");
  localStorage.removeItem("userPhone");
  localStorage.removeItem("userEmail");
  localStorage.removeItem("loginTime");

  // Redirect to login page
  window.location.href = "/login";
}

function setupActivityListeners() {
  // Reset timer on any of these events
  const events = ["mousedown", "mousemove", "keypress", "scroll", "touchstart"];

  events.forEach((event) => {
    document.addEventListener(event, resetInactivityTimer);
  });

  // Initialize the timer
  resetInactivityTimer();
}

// Check session function
function checkSession() {
  const loginTime = localStorage.getItem("loginTime");
  const now = new Date().getTime();
  const sessionDuration = 30 * 60 * 1000; // 30 minutes in milliseconds

  if (loginTime && now - loginTime > sessionDuration) {
    logout();
    return false;
  }
  return true;
}

// Show profile update modal function
function showProfileUpdateModal() {
  const modal = new bootstrap.Modal(
    document.getElementById("profileUpdateModal")
  );

  // Pre-fill phone and email from localStorage
  const phone = localStorage.getItem("userPhone") || "";
  const email = localStorage.getItem("userEmail") || "";

  document.getElementById("phone").value = phone;
  document.getElementById("email").value = email;

  modal.show();
}

// Show service confirmation modal function
function showServiceConfirmationModal() {
  const modal = new bootstrap.Modal(
    document.getElementById("serviceConfirmationModal")
  );
  modal.show();
}

// Update profile display
function updateProfileDisplay(user) {
  if (user.student_id)
    document.getElementById("profileStudentId").textContent = user.student_id;
  if (user.course)
    document.getElementById("profileCourse").textContent = user.course;
  if (user.year_level)
    document.getElementById("profileYear").textContent = user.year_level;
  if (user.school_year)
    document.getElementById("profileSchoolYear").textContent = user.school_year;
  if (user.year_graduated) {
    document.getElementById("profileYearGraduated").textContent =
      user.year_graduated;
  } else {
    document.getElementById("profileYearGraduated").textContent = "N/A";
  }

  // Update phone and email display in profile section
  if (user.phone)
    document.getElementById("profilePhone").textContent = user.phone;
  if (user.email)
    document.getElementById("profileEmail").textContent = user.email;
}

// ===== API FUNCTIONS =====

// Check if profile is complete
async function checkProfileComplete() {
  const userId = localStorage.getItem("userId");

  if (!userId) {
    console.error("No user ID found in localStorage");
    return false;
  }

  try {
    const response = await fetch(`/api/user/can-join-queue?userId=${userId}`);

    // Check if response is OK (status 200-299)
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    return data.success && data.canJoinQueue;
  } catch (error) {
    console.error("Error checking profile status:", error);
    return false;
  }
}

// Load user profile data
async function loadUserProfile() {
  const userId = localStorage.getItem("userId");

  if (!userId) {
    console.error("No user ID found in localStorage");
    return;
  }

  try {
    const response = await fetch(`/api/user/profile?userId=${userId}`);

    // Check if response is OK (status 200-299)
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    if (data.success) {
      // Update profile display
      updateProfileDisplay(data.user);

      // If profile is complete, hide the warning
      if (data.user.profile_complete) {
        const alert = document.querySelector(".alert-profile");
        if (alert) alert.style.display = "none";
      }
    } else {
      console.error("API returned error:", data.message);
    }
  } catch (error) {
    console.error("Error loading user profile:", error);
    // Don't show alert for 404 errors to avoid confusing users
    if (!error.message.includes("404")) {
      alert("Error loading profile data. Please try again later.");
    }
  }
}

// Save profile data to server
async function saveProfileToServer(profileData) {
  const userId = localStorage.getItem("userId");

  try {
    const response = await fetch("/api/user/update-profile", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        userId: userId,
        ...profileData,
      }),
    });

    const data = await response.json();

    if (data.success) {
      // Reload profile data
      await loadUserProfile();
      return true;
    } else {
      alert("Error updating profile: " + data.message);
      return false;
    }
  } catch (error) {
    console.error("Error saving profile:", error);
    alert("Error updating profile. Please try again.");
    return false;
  }
}

// ===== SERVICES DATA AND FUNCTIONS =====

// Services data
const servicesData = {
  "Transcript of Records": {
    description:
      "Official academic record showing all courses taken, grades earned, and degrees awarded.",
    requirements: [
      "Clearance",
      "Book-Bounded Thesis",
      "Documentary Stamp",
      "Receipt of Payment (cashier's office) ₱40.00",
    ],
    price: 40.0,
  },
  "Completion Grade Form": {
    description:
      "Registrar provides an official grade form upon student request.",
    requirements: [
      "Completion Form",
      "Instructor's Approval",
      "Receipt of Payment (cashier's office) ₱30.00",
    ],
    price: 20.0,
  },
  "Diploma Issuance": {
    description:
      "The Registrar issues official diplomas to graduates as proof of completion.",
    requirements: ["Clearance/Trascript Records", "Documentary Stamps"],
    price: null,
  },
  "Add/Drop Subjects": {
    description:
      "Process for modifying your current course load by adding new subjects or dropping existing ones.",
    requirements: [
      "Adding/Dropping Form",
      "Official Receipt (cashier's office) ₱20.00",
    ],
    price: 20.0,
  },
  "Certification of Grades": {
    description:
      "The Registrar issues official student grades upon request for academic records and verification.",
    requirements: ["Registration Form", "Grade Slip"],
    price: null,
  },
  "Other Services": {
    description:
      "For other registrar services not listed here. Please describe your concern when prompted.",
    requirements: ["Requirements vary depending on request"],
    price: null,
  },
};

let selectedServicesList = [];

function selectService(serviceName) {
  if (!checkAuthentication() || !checkSession()) return;

  const service = servicesData[serviceName];

  // Show modal with details before adding
  const descriptionEl = document.getElementById("serviceDescription");
  const requirementsEl = document.getElementById("serviceRequirements");
  const feeEl = document.getElementById("serviceFee");
  const confirmBtn = document.getElementById("confirmAddServiceBtn");

  descriptionEl.textContent = service.description;
  requirementsEl.innerHTML = service.requirements
    .map((r) => `<li>${r}</li>`)
    .join("");
  feeEl.textContent = service.price ? `₱${service.price.toFixed(2)}` : "N/A";

  // Remove old event listeners before adding a new one
  const newConfirmBtn = confirmBtn.cloneNode(true);
  confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

  newConfirmBtn.addEventListener("click", () => {
    addServiceToList(serviceName);
    const modalInstance = bootstrap.Modal.getInstance(
      document.getElementById("serviceConfirmationModal")
    );
    modalInstance.hide();

    // Open the selected services modal automatically
    const selectedModal = new bootstrap.Modal(
      document.getElementById("selectedModal")
    );
    selectedModal.show();
  });

  const modal = new bootstrap.Modal(
    document.getElementById("serviceConfirmationModal")
  );
  modal.show();
}

function addServiceToList(serviceName) {
  if (!selectedServicesList.includes(serviceName)) {
    selectedServicesList.push(serviceName);
    refreshModal();
  }
}

// function selectService(serviceName) {
//   // Check authentication and session before allowing action
//   if (!checkAuthentication() || !checkSession()) return;

//   const service = servicesData[serviceName];

//   // Add to selected services if not already added
//   if (!selectedServicesList.includes(serviceName)) {
//     selectedServicesList.push(serviceName);
//   }

//   // Update and show the modal
//   refreshModal();

//   // Show modal
//   const myModal = new bootstrap.Modal(document.getElementById("selectedModal"));
//   myModal.show();
// }

function removeService(serviceName) {
  selectedServicesList = selectedServicesList.filter((s) => s !== serviceName);
  refreshModal();
}

function refreshModal() {
  const modalBodyLeft = document.getElementById("selectedServicesList");
  const modalBodyRight = document.getElementById("requirementsList");
  const totalAmountEl = document.getElementById("totalAmount");

  if (selectedServicesList.length === 0) {
    modalBodyLeft.innerHTML =
      "<p class='p-3 text-center'>No services selected yet.</p>";
    modalBodyRight.innerHTML = "";
    totalAmountEl.textContent = "₱0.00";
  } else {
    let total = 0;
    let servicesHTML = "";
    let requirementsHTML = "";

    selectedServicesList.forEach((s) => {
      const service = servicesData[s];
      const price = service.price > 0 ? `₱${service.price.toFixed(2)}` : "N/A";
      total += service.price || 0;

      servicesHTML += `
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <span><strong>${s}</strong> (${price})</span>
                        <button class="btn btn-sm btn-outline-danger" onclick="removeService('${s}')">
                            <i class="bi bi-x-circle"></i>
                        </button>
                    </li>
                `;

      requirementsHTML += `
                    <div class="mb-3">
                        <strong>${s}</strong>
                        <ul class="mb-0 mt-1">${service.requirements
                          .map((r) => `<li class="small">${r}</li>`)
                          .join("")}</ul>
                    </div>
                `;
    });

    modalBodyLeft.innerHTML = servicesHTML;
    modalBodyRight.innerHTML = requirementsHTML;
    totalAmountEl.textContent = `₱${total.toFixed(2)}`;
  }
}

function viewServices() {
  // Check authentication and session before allowing action
  if (!checkAuthentication() || !checkSession()) return;

  refreshModal();

  // Show modal
  const myModal = new bootstrap.Modal(document.getElementById("selectedModal"));
  myModal.show();
}

// ===== EVENT LISTENERS AND INITIALIZATION =====

// Update the join queue button handler
// Replace the joinQueueBtn event handler in dashboard.js
document
  .getElementById("joinQueueBtn")
  .addEventListener("click", async function () {
    // Check authentication and session before allowing action
    if (!checkAuthentication() || !checkSession()) return;

    const canJoin = await checkProfileComplete();

    if (!canJoin) {
      // Show profile update modal instead of joining queue
      const selectedModal = bootstrap.Modal.getInstance(
        document.getElementById("selectedModal")
      );
      if (selectedModal) selectedModal.hide();

      showProfileUpdateModal();
      alert("Please complete your profile before submitting service requests.");
    } else {
      // Proceed with submitting request for admin approval
      await submitServiceRequest();
    }
  });

// New function to submit service request for admin approval
async function submitServiceRequest() {
  const userId = localStorage.getItem("userId");

  if (selectedServicesList.length === 0) {
    alert("Please select at least one service.");
    return;
  }

  try {
    // Show loading state
    const joinBtn = document.getElementById("joinQueueBtn");
    const originalText = joinBtn.innerHTML;
    joinBtn.innerHTML =
      '<i class="bi bi-hourglass-split me-1"></i> Submitting...';
    joinBtn.disabled = true;

    // Calculate total amount and prepare requirements
    let totalAmount = 0;
    const requirements = [];

    selectedServicesList.forEach((serviceName) => {
      const service = servicesData[serviceName];
      totalAmount += service.price || 0;
      requirements.push({
        service: serviceName,
        requirements: service.requirements,
      });
    });

    // Prepare request data
    const requestData = {
      userId: userId,
      services: selectedServicesList,
      totalAmount: totalAmount,
      requirements: requirements,
    };

    // Submit to backend
    const response = await fetch("/api/queue/submit-request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestData),
    });

    const result = await response.json();

    if (result.success) {
      // Close the modal
      const selectedModal = bootstrap.Modal.getInstance(
        document.getElementById("selectedModal")
      );
      if (selectedModal) selectedModal.hide();

      // Show success message
      showSubmissionSuccessModal(result.requestId);

      // Clear selected services
      selectedServicesList = [];
    } else {
      alert("Error submitting request: " + result.message);
    }
  } catch (error) {
    console.error("Error submitting service request:", error);
    alert("Error submitting request. Please try again.");
  } finally {
    // Reset button state
    const joinBtn = document.getElementById("joinQueueBtn");
    joinBtn.innerHTML =
      '<i class="bi bi-arrow-right-circle me-1"></i> Join Queue Now';
    joinBtn.disabled = false;
  }
}

// Function to show success modal after submission
function showSubmissionSuccessModal(requestId) {
  const successHTML = `
    <div class="modal fade" id="submissionSuccessModal" tabindex="-1">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header bg-success text-white">
            <h5 class="modal-title">
              <i class="bi bi-check-circle-fill me-2"></i> Request Submitted
            </h5>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body text-center">
            <div class="mb-3">
              <i class="bi bi-clock text-warning" style="font-size: 3rem;"></i>
            </div>
            <h5>Request Submitted for Approval</h5>
            <p>Your service request has been submitted and is waiting for admin approval.</p>
            <div class="alert alert-info">
              <strong>Request ID:</strong> ${requestId}<br>
              <strong>Status:</strong> <span class="badge bg-warning">Pending Approval</span>
            </div>
            <p>You will be notified once your request is approved or if additional information is needed.</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-success" data-bs-dismiss="modal">OK</button>
          </div>
        </div>
      </div>
    </div>
  `;

  // Remove existing modal if any
  const existingModal = document.getElementById("submissionSuccessModal");
  if (existingModal) {
    existingModal.remove();
  }

  // Add new modal to body
  document.body.insertAdjacentHTML("beforeend", successHTML);

  // Show the modal
  const successModal = new bootstrap.Modal(
    document.getElementById("submissionSuccessModal")
  );
  successModal.show();

  // Remove modal from DOM after hide
  document
    .getElementById("submissionSuccessModal")
    .addEventListener("hidden.bs.modal", function () {
      this.remove();
    });
}

// Update the profile update form submission
document
  .getElementById("saveProfileBtn")
  .addEventListener("click", async function () {
    const studentId = document.getElementById("studentId").value;
    const course = document.getElementById("course").value;
    const major = document.getElementById("major").value;
    const yearLevel = document.getElementById("yearLevel").value;
    const schoolYear = document.getElementById("schoolYear").value;
    const yearGraduated = document.getElementById("yearGraduated").value;

    // Basic validation
    if (!studentId || !course || !yearLevel || !schoolYear) {
      alert("Please fill in all required fields.");
      return;
    }

    const profileData = {
      studentId,
      course,
      major,
      yearLevel,
      schoolYear,
      yearGraduated: yearGraduated || null,
    };

    const success = await saveProfileToServer(profileData);

    if (success) {
      const modal = bootstrap.Modal.getInstance(
        document.getElementById("profileUpdateModal")
      );
      if (modal) modal.hide();
    }
  });

// Section switching functionality
document.addEventListener("DOMContentLoaded", async () => {
  // Check authentication first
  if (!checkAuthentication()) return;

  // Load user data
  const fullname = localStorage.getItem("fullname") || "User";
  const userId = localStorage.getItem("userId") || "N/A";
  if (!fullname || !userId) {
    // Not logged in → back to welcome page
    window.location.href = "/";
    return;
  }
  // else {
  //   document.getElementById("welcome").textContent = `Welcome, ${fullname}!`;
  //   document.getElementById("info").textContent = `Your unique account ID: ${userId}`;
  // }

  // Set profile information
  document.getElementById("profileName").textContent = fullname;

  // Load user profile data from server
  await loadUserProfile();

  // Setup auto-logout functionality
  setupActivityListeners();

  // Section switching
  const navLinks = document.querySelectorAll(".nav-link");
  const sections = document.querySelectorAll(".section");

  navLinks.forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const target = link.getAttribute("data-target");

      // Update active states
      sections.forEach((sec) => sec.classList.remove("active"));
      navLinks.forEach((l) => l.classList.remove("active"));

      link.classList.add("active");
      document.getElementById(target).classList.add("active");

      // Close mobile menu if open
      const navbar = document.querySelector(".navbar-collapse");
      if (navbar.classList.contains("show")) {
        new bootstrap.Collapse(navbar).hide();
      }
    });
  });

  // Navbar scroll effect
  window.addEventListener("scroll", function () {
    const navbar = document.querySelector(".navbar");
    if (window.scrollY > 10) {
      navbar.classList.add("scrolled");
    } else {
      navbar.classList.remove("scrolled");
    }
  });

  // Add logout button functionality
  const logoutBtn = document.querySelector(".btn-outline-danger");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", function () {
      logout();
    });
  }
});

// Add this to your dashboard.js to show user's request status
async function loadUserRequests() {
  const userId = localStorage.getItem("userId");

  if (!userId) return;

  try {
    const response = await fetch(`/api/user/service-requests?userId=${userId}`);
    const result = await response.json();

    if (result.success) {
      displayUserRequests(result.requests);
    }
  } catch (error) {
    console.error("Error loading user requests:", error);
  }
}

function displayUserRequests(requests) {
  const updatesSection = document.getElementById("updates");
  if (!updatesSection) return;

  // Clear existing content
  const existingCards = updatesSection.querySelectorAll(".update-card");
  existingCards.forEach((card) => card.remove());

  if (requests.length === 0) {
    updatesSection.innerHTML += `
      <div class="update-card">
        <h4>No Service Requests</h4>
        <p>You haven't submitted any service requests yet.</p>
      </div>
    `;
    return;
  }

  requests.forEach((request) => {
    let statusClass = "";
    let statusText = "";

    switch (request.status) {
      case "pending":
        statusClass = "status-pending";
        statusText = "Pending Approval";
        break;
      case "approved":
        statusClass = "status-processing";
        statusText = "Approved - Ready for Processing";
        break;
      case "declined":
        statusClass = "status-completed";
        statusText = "Declined";
        break;
      default:
        statusClass = "status-pending";
        statusText = "Pending";
    }

    const requestHTML = `
      <div class="update-card">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <h4 class="mb-0">${request.services.join(", ")}</h4>
          <span class="update-status ${statusClass}">${statusText}</span>
        </div>
        <p class="text-muted">Request ID: ${
          request.request_id
        } | Submitted: ${new Date(request.submitted_at).toLocaleString()}</p>
        ${
          request.status === "approved" && request.approved_by
            ? `
          <p><strong>Approved by:</strong> ${request.approved_by} on ${new Date(
                request.approved_at
              ).toLocaleString()}</p>
          ${
            request.approve_notes
              ? `<p><strong>Admin Notes:</strong> ${request.approve_notes}</p>`
              : ""
          }
        `
            : ""
        }
        ${
          request.status === "declined" && request.declined_by
            ? `
          <p><strong>Declined by:</strong> ${request.declined_by} on ${new Date(
                request.declined_at
              ).toLocaleString()}</p>
          <p><strong>Reason:</strong> ${request.decline_reason}</p>
        `
            : ""
        }
        <p><strong>Total Amount:</strong> ₱${parseFloat(
          request.total_amount
        ).toFixed(2)}</p>
      </div>
    `;

    updatesSection.innerHTML += requestHTML;
  });
}

// Call this function when the dashboard loads
document.addEventListener("DOMContentLoaded", async () => {
  // ... your existing code ...

  // Load user requests
  await loadUserRequests();
});
