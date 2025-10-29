import express from "express";
import mysql from "mysql2";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || "rsu-reqs-admin-secret-key-2024";

// MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "rsu_reqs_db",
  port: 3306,
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
    return;
  }
  console.log("✅ Connected to local MySQL");

  createQueueTable();
  createAdminStaffTable();
  createServiceRequestsTable(); // Add this line
});

// Create or update service_requests table
function createServiceRequestsTable() {
  const serviceRequestsTable = `
    CREATE TABLE IF NOT EXISTS service_requests (
      request_id VARCHAR(100) PRIMARY KEY,
      user_id INT NOT NULL,
      user_name VARCHAR(255) NOT NULL,
      student_id VARCHAR(50),
      course VARCHAR(255),
      year_level VARCHAR(50),
      services JSON,
      total_amount DECIMAL(10,2) DEFAULT 0,
      requirements JSON,
      status ENUM('pending', 'approved', 'declined') DEFAULT 'pending',
      queue_status VARCHAR(50) DEFAULT 'pending',
      queue_number VARCHAR(50),
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      approved_by VARCHAR(255),
      approved_by_id INT,
      approved_at DATETIME,
      approve_notes TEXT,
      declined_by VARCHAR(255),
      declined_by_id INT,
      declined_at DATETIME,
      decline_reason TEXT,
      contact_email VARCHAR(255),
      contact_phone VARCHAR(20),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (approved_by_id) REFERENCES admin_staff(id),
      FOREIGN KEY (declined_by_id) REFERENCES admin_staff(id)
    )
  `;

  db.query(serviceRequestsTable, (err) => {
    if (err) console.error("Error creating service_requests table:", err);
    else console.log("✅ service_requests table ready");
  });
}
// -------------------------------------------------------------------
// Get the next global queue number (A-001, A-002, …)
// Returns a string like "A-001"
// -------------------------------------------------------------------
function getNextQueueNumber(callback) {
  // 1. Find the highest existing number that starts with "A-"
  const sql = `
    SELECT queue_number 
    FROM queue 
    WHERE queue_number REGEXP '^A-[0-9]+$' 
    ORDER BY CAST(SUBSTRING(queue_number, 3) AS UNSIGNED) DESC 
    LIMIT 1
  `;

  db.query(sql, (err, rows) => {
    if (err) return callback(err);

    let nextSeq = 1;
    if (rows.length > 0) {
      const last = rows[0].queue_number; // e.g. "A-123"
      const num = parseInt(last.split("-")[1], 10);
      nextSeq = num + 1;
    }

    const nextNumber = `A-${String(nextSeq).padStart(3, "0")}`;
    callback(null, nextNumber);
  });
}

// Create admin_staff table
function createAdminStaffTable() {
  const staffTable = `
    CREATE TABLE IF NOT EXISTS admin_staff (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      full_name VARCHAR(255) NOT NULL,
      phone VARCHAR(20),
      department VARCHAR(100),
      role ENUM('super_admin', 'admin', 'staff') DEFAULT 'staff',
      is_active BOOLEAN DEFAULT TRUE,
      last_login DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `;

  db.query(staffTable, (err) => {
    if (err) {
      console.error("Error creating admin_staff table:", err);
    } else {
      console.log("✅ admin_staff table ready");
      createDefaultAdmin();
    }
  });
}

// Create default admin account
async function createDefaultAdmin() {
  const checkAdmin =
    "SELECT * FROM admin_staff WHERE email = 'admin@rsu.edu.ph'";

  db.query(checkAdmin, async (err, results) => {
    if (err) {
      console.error("Error checking admin account:", err);
      return;
    }

    if (results.length === 0) {
      const hashedPassword = await bcrypt.hash("admin123", 10);
      const insertAdmin = `
        INSERT INTO admin_staff (email, password, full_name, role) 
        VALUES (?, ?, ?, 'super_admin')
      `;

      db.query(
        insertAdmin,
        ["admin@rsu.edu.ph", hashedPassword, "System Administrator"],
        (err) => {
          if (err) {
            console.error("Error creating default admin:", err);
          } else {
            console.log(
              "✅ Default admin account created - Email: admin@rsu.edu.ph, Password: admin123"
            );
          }
        }
      );
    }
  });
}

// Create queue table
function createQueueTable() {
  const queueTable = `
    CREATE TABLE IF NOT EXISTS queue (
      queue_id INT AUTO_INCREMENT PRIMARY KEY,
      queue_number VARCHAR(50) UNIQUE NOT NULL,
      user_id INT NOT NULL,
      user_name VARCHAR(255) NOT NULL,
      student_id VARCHAR(50),
      course VARCHAR(255),
      year_level VARCHAR(50),
      request_id VARCHAR(50),
      services JSON,
      total_amount DECIMAL(10,2) DEFAULT 0,
      status ENUM('waiting', 'processing', 'ready', 'completed') DEFAULT 'waiting',
      is_priority BOOLEAN DEFAULT FALSE,
      priority_type VARCHAR(100),
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      started_at DATETIME,
      completed_at DATETIME,
      processed_by VARCHAR(255),
      processed_by_id INT,
      completed_by VARCHAR(255),
      completed_by_id INT,
      added_by VARCHAR(255),
      added_by_id INT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (request_id) REFERENCES service_requests(request_id) ON DELETE CASCADE,
      FOREIGN KEY (processed_by_id) REFERENCES admin_staff(id),
      FOREIGN KEY (completed_by_id) REFERENCES admin_staff(id),
      FOREIGN KEY (added_by_id) REFERENCES admin_staff(id)
    )
  `;

  db.query(queueTable, (err) => {
    if (err) console.error("Error creating queue table:", err);
    else console.log("✅ queue table ready");
  });
}

// Admin Authentication Middleware
const authenticateAdmin = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Access denied. No token provided.",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }
};

// Serve static files
app.use("/assets", express.static(path.join(__dirname, "assets")));
app.use(express.json());

// Service hours check middleware
function checkServiceHoursHTML(req, res, next) {
  const now = new Date();
  const hours = now.getHours();
  const openHour = 0;
  const closeHour = 24;

  if (req.path === "/admin" || req.path === "/adminLogin") {
    return next();
  }

  if (hours >= openHour && hours < closeHour) {
    next();
  } else {
    res.redirect("/");
  }
}

const protectedRoutes = ["/login", "/register", "/queue", "/dashboard"];
app.use(protectedRoutes, checkServiceHoursHTML);

// HTML Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "welcome.html"));
});

app.get("/privacy", (req, res) => {
  res.sendFile(path.join(__dirname, "privacy.html"));
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "register.html"));
});

app.get("/queue", (req, res) => {
  res.sendFile(path.join(__dirname, "queue.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admindashb.html"));
});

app.get("/adminLogin", (req, res) => {
  res.sendFile(path.join(__dirname, "adminLogin.html"));
});

// ADMIN AUTHENTICATION API ROUTES
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Email and password are required",
    });
  }

  try {
    db.query(
      "SELECT * FROM admin_staff WHERE email = ? AND is_active = 1",
      [email],
      async (err, results) => {
        if (err) {
          console.error("Admin login database error:", err);
          return res.status(500).json({
            success: false,
            message: "Database error",
          });
        }

        if (results.length === 0) {
          return res.json({
            success: false,
            message: "Invalid email or password",
          });
        }

        const admin = results[0];
        const isPasswordValid = await bcrypt.compare(password, admin.password);

        if (!isPasswordValid) {
          return res.json({
            success: false,
            message: "Invalid email or password",
          });
        }

        db.query("UPDATE admin_staff SET last_login = NOW() WHERE id = ?", [
          admin.id,
        ]);

        const token = jwt.sign(
          {
            adminId: admin.id,
            email: admin.email,
            role: admin.role,
            full_name: admin.full_name,
          },
          JWT_SECRET,
          { expiresIn: "8h" }
        );

        const { password: _, ...adminWithoutPassword } = admin;

        res.json({
          success: true,
          message: "Login successful",
          admin: adminWithoutPassword,
          token,
        });
      }
    );
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({
      success: false,
      message: "Server error occurred",
    });
  }
});

app.get("/api/admin/me", authenticateAdmin, (req, res) => {
  db.query(
    "SELECT id, email, full_name, phone, department, role, created_at, last_login FROM admin_staff WHERE id = ?",
    [req.admin.adminId],
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      if (results.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Admin not found",
        });
      }

      res.json({
        success: true,
        admin: results[0],
      });
    }
  );
});

// PROTECTED ADMIN ROUTES
const adminApiRoutes = [
  "/api/admin/service-requests",
  "/api/admin/pending-requests",
  "/api/admin/approve-request",
  "/api/admin/decline-request",
  "/api/admin/add-manual-queue",
  "/api/admin/make-priority",
  "/api/admin/move-to-regular",
  "/api/admin/make-current",
  "/api/admin/clear-priority",
  "/api/admin/add-to-queue",
  "/api/admin/queues",
  "/api/admin/start-processing",
  "/api/admin/mark-done",
  "/api/admin/notify-student",
];

// app.use(adminApiRoutes, authenticateAdmin);

// Admin Routes with Staff Tracking
app.post("/api/admin/approve-request", authenticateAdmin, (req, res) => {
  const { requestId, approveNotes } = req.body;
  const approvedBy = req.admin.full_name;
  const adminId = req.admin.adminId;

  if (!requestId) {
    return res.status(400).json({
      success: false,
      message: "Request ID is required",
    });
  }

  db.query(
    `UPDATE service_requests 
     SET status = 'approved', approved_by = ?, approved_by_id = ?, approved_at = NOW(), approve_notes = ?
     WHERE request_id = ?`,
    [approvedBy, adminId, approveNotes || "", requestId],
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: "Request not found",
        });
      }

      addToQueueSystem(requestId);

      res.json({
        success: true,
        message: "Request approved successfully and added to queue",
        approvedBy: approvedBy,
      });
    }
  );
});

app.post("/api/admin/decline-request", authenticateAdmin, (req, res) => {
  const { requestId, declineReason } = req.body;
  const declinedBy = req.admin.full_name;
  const adminId = req.admin.adminId;

  if (!requestId || !declineReason) {
    return res.status(400).json({
      success: false,
      message: "Request ID and reason are required",
    });
  }

  db.query(
    `UPDATE service_requests 
     SET status = 'declined', declined_by = ?, declined_by_id = ?, declined_at = NOW(), decline_reason = ?
     WHERE request_id = ?`,
    [declinedBy, adminId, declineReason, requestId],
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: "Request not found",
        });
      }

      res.json({
        success: true,
        message: "Request declined successfully",
        declinedBy: declinedBy,
      });
    }
  );
});
function addToQueueSystem(requestId) {
  console.log(`[DEBUG] Starting addToQueueSystem for requestId: ${requestId}`);

  const requestQuery = "SELECT * FROM service_requests WHERE request_id = ?";
  db.query(requestQuery, [requestId], (err, requests) => {
    if (err || requests.length === 0) {
      console.error("[ERROR] Request not found or DB error:", err);
      return;
    }

    const request = requests[0];

    // Generate queue number
    // Generate queue number
    getNextQueueNumber((err, queueNumber) => {
      if (err) {
        console.error("Error generating queue number:", err);
        return; // Exit early, caller will handle response
      }

      const isPriority = false;
      const priorityType = null;

      const insertQueueQuery = `
    INSERT INTO queue (
      queue_number, user_id, user_name, student_id, course, year_level,
      request_id, services, total_amount, status, is_priority, priority_type, submitted_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?, NOW())
  `;

      db.query(
        insertQueueQuery,
        [
          queueNumber,
          request.user_id,
          request.user_name,
          request.student_id,
          request.course,
          request.year_level,
          requestId,
          request.services,
          request.total_amount,
          isPriority,
          priorityType,
        ],
        (err, result) => {
          if (err) {
            console.error("Database error:", err);
            return; // Exit early
          }

          const updateRequestQuery = `
        UPDATE service_requests 
        SET queue_status = 'in_queue', queue_number = ? 
        WHERE request_id = ?
      `;

          db.query(updateRequestQuery, [queueNumber, requestId], (err) => {
            if (err) console.error("Error updating service request:", err);
            // No res.json here – caller (e.g., approval route) will respond
          });
        }
      );
    });
  });
}

app.post("/api/admin/start-processing", authenticateAdmin, (req, res) => {
  const { queueId } = req.body;
  const adminId = req.admin.adminId;
  const adminName = req.admin.full_name;

  if (!queueId) {
    return res.status(400).json({
      success: false,
      message: "Queue ID is required",
    });
  }

  // First, get the queue details to find the request_id
  const getQueueQuery = "SELECT * FROM queue WHERE queue_id = ?";

  db.query(getQueueQuery, [queueId], (err, queueResults) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    if (queueResults.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Queue not found",
      });
    }

    const queue = queueResults[0];
    const requestId = queue.request_id;

    const updateQuery = `
      UPDATE queue 
      SET status = 'processing', 
          started_at = NOW(),
        processed_by = ?,
        processed_by_id = ?
    WHERE queue_id = ?
  `;

    db.query(updateQuery, [adminName, adminId, queueId], (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: "Queue not found",
        });
      }

      // ✅ CRITICAL FIX: Also update the service_requests table
      if (requestId) {
        const updateServiceRequestQuery = `
          UPDATE service_requests 
          SET queue_status = 'processing'
          WHERE request_id = ?
        `;

        db.query(updateServiceRequestQuery, [requestId], (err) => {
          if (err) {
            console.error("Error updating service request:", err);
            // Don't fail the main request if this fails, but log it
          } else {
            console.log(`Service request ${requestId} marked as processing`);
          }
        });
      }

      res.json({
        success: true,
        message: "Queue moved to processing",
        processedBy: adminName,
      });
    });
  });
});

app.post("/api/admin/mark-done", authenticateAdmin, (req, res) => {
  const { queueId } = req.body;
  const adminId = req.admin.adminId;
  const adminName = req.admin.full_name;

  if (!queueId) {
    return res.status(400).json({
      success: false,
      message: "Queue ID is required",
    });
  }

  // First, get the queue details to find the request_id
  const getQueueQuery = "SELECT * FROM queue WHERE queue_id = ?";

  db.query(getQueueQuery, [queueId], (err, queueResults) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    if (queueResults.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Queue not found",
      });
    }

    const queue = queueResults[0];
    const requestId = queue.request_id;

    // Update queue status to completed with staff info
    const updateQueueQuery = `
      UPDATE queue 
      SET status = 'completed', 
          completed_at = NOW(),
          completed_by = ?,
          completed_by_id = ?
      WHERE queue_id = ?
    `;

    db.query(updateQueueQuery, [adminName, adminId, queueId], (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: "Queue not found",
        });
      }

      // ✅ CRITICAL FIX: Also update the service_requests table
      if (requestId) {
        const updateServiceRequestQuery = `
          UPDATE service_requests 
          SET queue_status = 'completed'
          WHERE request_id = ?
        `;

        db.query(updateServiceRequestQuery, [requestId], (err) => {
          if (err) {
            console.error("Error updating service request:", err);
            // Don't fail the main request if this fails, but log it
          } else {
            console.log(`Service request ${requestId} marked as completed`);
          }
        });
      }

      // ✅ FIXED: Remove automatic processing of next queue
      // Let the admin manually start the next queue when ready

      res.json({
        success: true,
        message: "Queue completed successfully",
        completedBy: adminName,
        nextQueueStarted: false // Always false now
      });
    });
  });
});

app.post("/api/admin/add-manual-queue", authenticateAdmin, (req, res) => {
  const { name, studentId, service, isPriority, transactionType, notes } =
    req.body;
  const adminId = req.admin.adminId;
  const adminName = req.admin.full_name;

  if (!name) {
    return res.status(400).json({
      success: false,
      message: "Name is required",
    });
  }

  const queueNumberQuery = `
    SELECT COUNT(*) as count 
    FROM queue 
    WHERE DATE(submitted_at) = CURDATE()
  `;

  db.query(queueNumberQuery, (err, countResult) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    const queueCount = countResult[0].count + 1;
    const queueNumber = isPriority
      ? `P-${String(queueCount).padStart(3, "0")}`
      : `A-${String(queueCount).padStart(3, "0")}`;

    const insertQueueQuery = `
      INSERT INTO queue (
        queue_number, 
        user_name,
        student_id,
        services,
        status,
        is_priority,
        priority_type,
        transaction_type,
        admin_notes,
        added_by,
        added_by_id,
        submitted_at
      ) VALUES (?, ?, ?, ?, 'waiting', ?, ?, ?, ?, ?, ?, NOW())
    `;

    db.query(
      insertQueueQuery,
      [
        queueNumber,
        name,
        studentId || null,
        JSON.stringify([service]),
        isPriority,
        isPriority ? "Manual Priority" : null,
        transactionType || "walkin",
        notes || null,
        adminName,
        adminId,
      ],
      (err, result) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({
            success: false,
            message: "Database error",
          });
        }

        res.json({
          success: true,
          message: "Manual queue entry added successfully",
          queueNumber: queueNumber,
          addedBy: adminName,
        });
      }
    );
  });
});

// EXISTING STUDENT ROUTES
app.post("/api/login", (req, res) => {
  const { emailOrPhone, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ? OR phone = ?",
    [emailOrPhone, emailOrPhone],
    async (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ success: false, message: "Database error" });

      if (results.length === 0) {
        return res.json({ success: false, message: "Invalid credentials" });
      }

      const user = results[0];
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        console.log("User from DB:", user);

        return res.json({
          success: true,
          message: "Login successful",
          userId: user.id,
          fullname: user.fullname,
          phone: user.phone,
          email: user.email,
        });
      } else {
        return res.json({ success: false, message: "Invalid credentials" });
      }
    }
  );
});

app.post("/api/register", async (req, res) => {
  const { fullName, email, phone, password } = req.body;

  if (!fullName || !email || !phone || !password) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ? OR phone = ?",
    [email, phone],
    async (err, results) => {
      if (err)
        return res
          .status(500)
          .json({ success: false, message: "Database error" });

      if (results.length > 0) {
        return res.json({
          success: false,
          message: "Email or phone already registered",
        });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
          "INSERT INTO users (fullname, email, phone, password) VALUES (?, ?, ?, ?)",
          [fullName, email, phone, hashedPassword],
          (err, result) => {
            if (err)
              return res
                .status(500)
                .json({ success: false, message: "Database error" });

            return res.json({
              success: true,
              message: "User registered successfully",
            });
          }
        );
      } catch (hashErr) {
        return res
          .status(500)
          .json({ success: false, message: "Error securing password" });
      }
    }
  );
});

app.get("/api/user/profile", (req, res) => {
  const userId = req.query.userId;

  if (!userId) {
    return res
      .status(400)
      .json({ success: false, message: "User ID is required" });
  }

  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    if (results.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    const user = results[0];
    res.json({
      success: true,
      user: {
        id: user.id,
        fullname: user.fullname,
        email: user.email,
        phone: user.phone,
        student_id: user.student_id,
        course: user.course,
        major: user.major,
        year_level: user.year_level,
        school_year: user.school_year,
        year_graduated: user.year_graduated,
        profile_complete: user.profile_complete,
      },
    });
  });
});

app.post("/api/user/update-profile", (req, res) => {
  const {
    userId,
    studentId,
    course,
    major,
    yearLevel,
    schoolYear,
    yearGraduated,
  } = req.body;

  if (!userId || !studentId || !course || !yearLevel || !schoolYear) {
    return res.status(400).json({
      success: false,
      message: "All required fields must be filled",
    });
  }

  db.query(
    `UPDATE users 
     SET student_id = ?, course = ?, major = ?, year_level = ?, 
         school_year = ?, year_graduated = ?, profile_complete = 1 
     WHERE id = ?`,
    [studentId, course, major, yearLevel, schoolYear, yearGraduated, userId],
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      if (result.affectedRows === 0) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      res.json({
        success: true,
        message: "Profile updated successfully",
      });
    }
  );
});

app.get("/api/user/can-join-queue", (req, res) => {
  const userId = req.query.userId;

  if (!userId) {
    return res
      .status(400)
      .json({ success: false, message: "User ID is required" });
  }

  db.query(
    "SELECT profile_complete FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      if (results.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      res.json({
        success: true,
        canJoinQueue: results[0].profile_complete === 1,
      });
    }
  );
});

app.post("/api/queue/submit-request", (req, res) => {
  const { userId, services, totalAmount, requirements } = req.body;

  if (!userId || !services || !Array.isArray(services)) {
    return res.status(400).json({
      success: false,
      message: "User ID and services are required",
    });
  }

  const requestId =
    "REQ-" + Date.now() + "-" + Math.random().toString(36).substr(2, 9);

  db.query(
    "SELECT fullname, student_id, course, year_level, email, phone FROM users WHERE id = ?",
    [userId],
    (err, userResults) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      if (userResults.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      const user = userResults[0];

      db.query(
        `INSERT INTO service_requests 
         (request_id, user_id, user_name, student_id, course, year_level, 
          services, total_amount, requirements, status, submitted_at, contact_email, contact_phone) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NOW(), ?, ?)`,
        [
          requestId,
          userId,
          user.fullname,
          user.student_id,
          user.course,
          user.year_level,
          JSON.stringify(services),
          totalAmount,
          JSON.stringify(requirements),
          user.email,
          user.phone,
        ],
        (err, result) => {
          if (err) {
            console.error("Database error:", err);
            return res
              .status(500)
              .json({ success: false, message: "Database error" });
          }

          res.json({
            success: true,
            requestId: requestId,
            message: "Service request submitted for admin approval",
          });
        }
      );
    }
  );
});

app.get("/api/admin/service-requests", authenticateAdmin, (req, res) => {
  db.query(
    `SELECT * FROM service_requests ORDER BY 
     CASE 
       WHEN status = 'pending' THEN 1
       WHEN status = 'approved' THEN 2
       WHEN status = 'declined' THEN 3
     END, submitted_at DESC`,
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      const requests = results.map((request) => ({
        ...request,
        services: JSON.parse(request.services),
        requirements: JSON.parse(request.requirements),
      }));

      res.json({
        success: true,
        requests: requests,
      });
    }
  );
});

app.get("/api/admin/pending-requests", authenticateAdmin, (req, res) => {
  db.query(
    "SELECT * FROM service_requests WHERE status = 'pending' ORDER BY submitted_at ASC",
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }

      const requests = results.map((request) => ({
        ...request,
        services: JSON.parse(request.services),
        requirements: JSON.parse(request.requirements),
      }));

      res.json({
        success: true,
        requests: requests,
      });
    }
  );
});

app.post("/api/admin/make-priority", (req, res) => {
  const { queueId } = req.body;

  db.query(
    `UPDATE queue 
     SET is_priority = TRUE, priority_type = 'Manual Priority'
     WHERE queue_id = ?`,
    [queueId],
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      res.json({
        success: true,
        message: "Queue item moved to priority",
      });
    }
  );
});

app.post("/api/admin/move-to-regular", authenticateAdmin, (req, res) => {
  const { queueId } = req.body;

  db.query(
    `UPDATE queue 
     SET is_priority = FALSE, priority_type = NULL
     WHERE queue_id = ?`,
    [queueId],
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      res.json({
        success: true,
        message: "Queue item moved to regular",
      });
    }
  );
});

app.post("/api/admin/make-current", authenticateAdmin, (req, res) => {
  const { queueId } = req.body;

  db.query(
    `UPDATE queue SET status = 'waiting' WHERE status = 'processing'`,
    (err) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      db.query(
        `UPDATE queue 
         SET status = 'processing', started_at = NOW()
         WHERE queue_id = ?`,
        [queueId],
        (err, result) => {
          if (err) {
            console.error("Database error:", err);
            return res.status(500).json({
              success: false,
              message: "Database error",
            });
          }

          res.json({
            success: true,
            message: "Queue item set as current",
          });
        }
      );
    }
  );
});

app.post("/api/admin/clear-priority", authenticateAdmin, (req, res) => {
  db.query(
    `UPDATE queue 
     SET is_priority = FALSE, priority_type = NULL
     WHERE is_priority = TRUE AND status = 'waiting'`,
    (err, result) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      res.json({
        success: true,
        message: "Priority queue cleared",
      });
    }
  );
});

app.post("/api/admin/add-to-queue", authenticateAdmin, (req, res) => {
  const { requestId } = req.body;

  if (!requestId) {
    return res.status(400).json({
      success: false,
      message: "Request ID is required",
    });
  }

  const requestQuery = "SELECT * FROM service_requests WHERE request_id = ?";
  db.query(requestQuery, [requestId], (err, requests) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    if (requests.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Request not found",
      });
    }

    const request = requests[0];

    const checkQueueQuery = "SELECT * FROM queue WHERE request_id = ?";
    db.query(checkQueueQuery, [requestId], (err, existingQueue) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      if (existingQueue.length > 0) {
        return res.json({
          success: false,
          message: "Request already in queue",
        });
      }

      const queueNumberQuery = `
        SELECT COUNT(*) as count 
        FROM queue 
        WHERE DATE(submitted_at) = CURDATE()
      `;

      db.query(queueNumberQuery, (err, countResult) => {
        if (err) {
          console.error("Database error:", err);
          return res.status(500).json({
            success: false,
            message: "Database error",
          });
        }

        const queueCount = countResult[0].count + 1;
        const isPriority = false;
        const priorityType = null;
        const queueNumber = isPriority
          ? `P-${String(queueCount).padStart(3, "0")}`
          : `A-${String(queueCount).padStart(3, "0")}`;

        const insertQueueQuery = `
          INSERT INTO queue (
            queue_number, 
            user_id, 
            user_name,
            student_id,
            course,
            year_level,
            request_id,
            services,
            total_amount,
            status,
            is_priority,
            priority_type,
            submitted_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?, NOW())
        `;

        db.query(
          insertQueueQuery,
          [
            queueNumber,
            request.user_id,
            request.user_name,
            request.student_id,
            request.course,
            request.year_level,
            requestId,
            request.services,
            request.total_amount,
            isPriority,
            priorityType,
          ],
          (err, result) => {
            if (err) {
              console.error("Database error:", err);
              return res.status(500).json({
                success: false,
                message: "Database error",
              });
            }

            const updateRequestQuery = `
              UPDATE service_requests 
              SET queue_status = 'in_queue', 
                  queue_number = ? 
              WHERE request_id = ?
            `;

            db.query(updateRequestQuery, [queueNumber, requestId], (err) => {
              if (err) {
                console.error("Error updating service request:", err);
              }

              res.json({
                success: true,
                message: "Request added to queue successfully",
                queueNumber: queueNumber,
              });
            });
          }
        );
      });
    });
  });
});

app.get("/api/admin/queues", authenticateAdmin, (req, res) => {
  const query = `
    SELECT 
      queue_id,
      queue_number,
      user_id,
      user_name,
      student_id,
      course,
      year_level,
      request_id,
      services,
      total_amount,
      status,
      is_priority,
      priority_type,
      submitted_at,
      started_at,
      completed_at
    FROM queue
    WHERE DATE(submitted_at) = CURDATE()
    ORDER BY 
      CASE 
        WHEN is_priority = 1 THEN 0 
        ELSE 1 
      END,
      submitted_at ASC
  `;

  db.query(query, (err, queues) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    const processedQueues = queues.map((queue) => {
      try {
        return {
          ...queue,
          services:
            typeof queue.services === "string"
              ? JSON.parse(queue.services)
              : queue.services,
        };
      } catch (parseErr) {
        console.error("Error parsing services for queue:", queue.queue_id);
        return {
          ...queue,
          services: [],
        };
      }
    });

    const organizedQueues = {
      waiting: processedQueues.filter(
        (q) => q.status === "waiting" && !q.is_priority
      ),
      processing: processedQueues.filter((q) => q.status === "processing"),
      ready: processedQueues.filter((q) => q.status === "ready"),
      completed: processedQueues.filter((q) => q.status === "completed"),
      priority: processedQueues.filter(
        (q) => q.is_priority && q.status === "waiting"
      ),
    };

    res.json({
      success: true,
      queues: organizedQueues,
    });
  });
});

app.post("/api/admin/notify-student", authenticateAdmin, (req, res) => {
  const { queueId } = req.body;

  if (!queueId) {
    return res.status(400).json({
      success: false,
      message: "Queue ID is required",
    });
  }

  const queueQuery = "SELECT * FROM queue WHERE queue_id = ?";
  db.query(queueQuery, [queueId], (err, queues) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({
        success: false,
        message: "Database error",
      });
    }

    if (queues.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Queue not found",
      });
    }

    const queue = queues[0];

    console.log(
      `Notifying student ${queue.user_name} for queue ${queue.queue_number}`
    );

    res.json({
      success: true,
      message: `Student ${queue.user_name} notified for queue ${queue.queue_number}`,
    });
  });
});

app.get("/api/user/service-requests", (req, res) => {
  const userId = req.query.userId;

  if (!userId) {
    return res.status(400).json({
      success: false,
      message: "User ID is required",
    });
  }

  db.query(
    "SELECT * FROM service_requests WHERE user_id = ? ORDER BY submitted_at DESC",
    [userId],
    (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({
          success: false,
          message: "Database error",
        });
      }

      const requests = results.map((request) => {
        try {
          return {
            ...request,
            services: JSON.parse(request.services),
            requirements: JSON.parse(request.requirements),
          };
        } catch (parseErr) {
          console.error("Error parsing JSON for request:", request.request_id);
          return {
            ...request,
            services: [],
            requirements: [],
          };
        }
      });

      res.json({
        success: true,
        requests: requests,
      });
    }
  );
});
// === MANUAL QUEUE ENTRY ===
app.post("/api/admin/manual-queue-entry", authenticateAdmin, (req, res) => {
  const {
    user_name,
    student_id,
    course,
    year_level,
    services,
    total_amount = 0.0,
  } = req.body;

  if (!user_name || !student_id || !course || !year_level || !services) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required." });
  }

  // Generate queue number for today
  // Generate queue number
  getNextQueueNumber((err, queueNumber) => {
    if (err) {
      console.error("Queue count error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    // Insert into queue
    const insertQuery = `
    INSERT INTO queue (
      queue_number, user_id, user_name, student_id, course, year_level,
      request_id, services, total_amount, status, is_priority, priority_type,
      submitted_at, added_by, added_by_id
    ) VALUES (?, NULL, ?, ?, ?, ?, NULL, ?, ?, 'waiting', 0, NULL, NOW(), ?, ?)
  `;

    const adminName = req.admin.full_name || "System Administrator";
    const adminId = req.admin.id;

    db.query(
      insertQuery,
      [
        queueNumber,
        user_name,
        student_id,
        course,
        year_level,
        services,
        total_amount,
        adminName,
        adminId,
      ],
      (err, result) => {
        if (err) {
          console.error("Manual queue insert error:", err);
          return res.status(500).json({ success: false, message: err.message });
        }

        res.json({
          success: true,
          message: "Manual entry added to queue",
          queueNumber: queueNumber,
          queueId: result.insertId,
        });
      }
    );
  });
});
// === END MANUAL QUEUE ENTRY ===

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Admin dashboard: http://localhost:${PORT}/admin`);
  console.log(`🔑 Admin login: http://localhost:${PORT}/adminLogin`);
  console.log(`👤 Default admin: admin@rsu.edu.ph / admin123`);
});

export default db;
