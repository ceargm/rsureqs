// -------------------------
// Services data
// -------------------------
const servicesData = {
    "Transcript of Records": {
        description: "Official academic record showing all courses taken, grades earned, and degrees awarded.",
        requirements: [
            "Clearance",
            "Book-Bounded Thesis",
            "Documentary Stamp",
            "Receipt of Payment (cashier's office) ₱40.00"
        ],
        price: 40.00
    },
    "Completion Grade Form": {
        description: "Registrar provides an official grade form upon student request.",
        requirements: [
            "Completion Form",
            "Instructor's Approval",
            "Receipt of Payment (cashier's office) ₱20.00"
        ],
        price: 20.00
    },
    "Diploma Issuance": {
        description: "The Registrar issues official diplomas to graduates as proof of completion.",
        requirements: [
            "Clearance",
            "Graduation Fee Receipt",
            "Registrar Approval"
        ],
        price: 50.00
    },
    "Add/Drop Subjects": {
        description: "Process for modifying your current course load by adding new subjects or dropping existing ones.",
        requirements: [
            "Adding/Dropping Form",
            "Official Receipt (cashier's office) ₱20.00"
        ],
        price: 20.00
    },
    "Certification of Grades": {
        description: "The Registrar issues official student grades upon request for academic records and verification.",
        requirements: [
            "Adding/Dropping Form",
            "Official Receipt (cashier's office)"
        ],
        price: null
    },
    "Other Services": {
        description: "For other registrar services not listed here. Please describe your concern when prompted.",
        requirements: [
            "Requirements vary depending on request"
        ],
        price: null
    }
};

// -------------------------
// State
// -------------------------
let selectedServicesList = [];

// -------------------------
// Initialize the dashboard
// -------------------------
document.addEventListener("DOMContentLoaded", () => {
    // Check if user is logged in
    const fullname = localStorage.getItem("fullname");
    const userId = localStorage.getItem("userId");

    if (!fullname || !userId) {
        // Not logged in → back to login
        window.location.href = "/login";
        return;
    }

    // Set welcome message
    document.getElementById("welcome").textContent = `Welcome, ${fullname}!`;
    document.getElementById("info").textContent = `Your unique account ID: ${userId}`;
    
    // Set profile information
    document.getElementById("profileName").textContent = fullname;
    document.getElementById("profileId").textContent = userId;
    
    // Set up section navigation
    setupSectionNavigation();
    
    // Set up navbar scroll effect
    setupNavbarScroll();
    
    // Set up service selection
    setupServiceSelection();
    
    // Check if storage should be cleared (after 4 PM)
    checkAndClearStorage();
    
    // Load any previously selected services
    loadSelectedServices();
});

// -------------------------
// Section Navigation
// -------------------------
function setupSectionNavigation() {
    const navLinks = document.querySelectorAll(".nav-link");
    const sections = document.querySelectorAll(".section");

    navLinks.forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const target = link.getAttribute("data-target");

            // Update active states
            sections.forEach(sec => sec.classList.remove("active"));
            navLinks.forEach(l => l.classList.remove("active"));

            link.classList.add("active");
            document.getElementById(target).classList.add("active");

            // Close mobile menu if open
            const navbar = document.querySelector(".navbar-collapse");
            if (navbar.classList.contains("show")) {
                new bootstrap.Collapse(navbar).hide();
            }
        });
    });
}

// -------------------------
// Navbar Scroll Effect
// -------------------------
function setupNavbarScroll() {
    window.addEventListener('scroll', function() {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 10) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });
}

// -------------------------
// Service Selection
// -------------------------
function setupServiceSelection() {
    // Add click events to all service cards
    const serviceCards = document.querySelectorAll('.card[onclick^="selectService"]');
    serviceCards.forEach(card => {
        card.addEventListener('click', function() {
            const serviceName = this.querySelector('h3').textContent;
            selectService(serviceName);
        });
    });
}

function selectService(serviceName) {
    // Add to selected services if not already added
    if (!selectedServicesList.includes(serviceName)) {
        selectedServicesList.push(serviceName);
        // Save to localStorage
        localStorage.setItem('selectedServices', JSON.stringify(selectedServicesList));
    }
    
    // Update and show the modal
    refreshModal();
    
    // Show modal
    const myModal = new bootstrap.Modal(document.getElementById("selectedModal"));
    myModal.show();
}

function removeService(serviceName) {
    selectedServicesList = selectedServicesList.filter(s => s !== serviceName);
    // Update localStorage
    localStorage.setItem('selectedServices', JSON.stringify(selectedServicesList));
    refreshModal();
}

function refreshModal() {
    const modalBodyLeft = document.getElementById("selectedServicesList");
    const modalBodyRight = document.getElementById("requirementsList");
    const totalAmountEl = document.getElementById("totalAmount");

    if (selectedServicesList.length === 0) {
        modalBodyLeft.innerHTML = "<p class='p-3 text-center'>No services selected yet.</p>";
        modalBodyRight.innerHTML = "";
        totalAmountEl.textContent = "₱0.00";
    } else {
        let total = 0;
        let servicesHTML = "";
        let requirementsHTML = "";

        selectedServicesList.forEach(s => {
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
                    <ul class="mb-0 mt-1">${service.requirements.map(r => `<li class="small">${r}</li>`).join("")}</ul>
                </div>
            `;
        });

        modalBodyLeft.innerHTML = servicesHTML;
        modalBodyRight.innerHTML = requirementsHTML;
        totalAmountEl.textContent = `₱${total.toFixed(2)}`;
    }
}

function viewServices() {
    refreshModal();
    
    // Show modal
    const myModal = new bootstrap.Modal(document.getElementById("selectedModal"));
    myModal.show();
}

function loadSelectedServices() {
    // Load selected services from localStorage
    const savedServices = localStorage.getItem('selectedServices');
    if (savedServices) {
        selectedServicesList = JSON.parse(savedServices);
    }
}

// -------------------------
// Time-based Storage Clearing
// -------------------------
function checkAndClearStorage() {
    const now = new Date();
    const hours = now.getHours();
    const lastClearDate = localStorage.getItem('lastClearDate');
    const today = now.toDateString();
    
    // Clear if after 4 PM (16:00) and not cleared today
    if (hours >= 16 && lastClearDate !== today) {
        localStorage.removeItem('selectedServices');
        localStorage.setItem('lastClearDate', today);
        
        // Reset the selected services list
        selectedServicesList = [];
        
        console.log('Local storage cleared (after 4 PM)');
    }
}

// -------------------------
// Document Download Handlers
// -------------------------
function downloadDocument(docName) {
    // In a real application, this would link to actual PDF files
    console.log(`Downloading ${docName}`);
    alert(`This would download the ${docName} in a real application.`);
}

// -------------------------
// Profile Functions
// -------------------------
function editProfile() {
    alert('Edit profile functionality would go here.');
}

function logout() {
    // Clear user data and redirect to login
    localStorage.removeItem('fullname');
    localStorage.removeItem('userId');
    window.location.href = "/login";
}

// -------------------------
// Join Queue Function
// -------------------------
function joinQueue() {
    if (selectedServicesList.length === 0) {
        alert('Please select at least one service before joining the queue.');
        return;
    }
    
    // In a real application, this would send the selected services to the server
    console.log('Joining queue with services:', selectedServicesList);
    alert('Your request has been submitted. You will be notified when your turn comes.');
    
    // Clear selected services after submission
    selectedServicesList = [];
    localStorage.removeItem('selectedServices');
    
    // Close the modal
    const myModal = bootstrap.Modal.getInstance(document.getElementById("selectedModal"));
    myModal.hide();
}

// Add event listener to the Join Queue button
document.addEventListener('DOMContentLoaded', function() {
    const joinQueueBtn = document.querySelector('#selectedModal .btn-success');
    if (joinQueueBtn) {
        joinQueueBtn.addEventListener('click', joinQueue);
    }
});