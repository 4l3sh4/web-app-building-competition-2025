# eBhive 🐝

A mentorship & collaboration platform for MMU students and mentors, designed to make it easier to:

- find mentors,
- discover project opportunities,
- form teams, and
- communicate in one place.

---

## ✨ Features

### 👥 Authentication & Roles
- User registration & login with hashed passwords.
- Two main roles:
  - **Student**
  - **Mentor**
- Role-based flows (e.g. student profile vs mentor profile, mentorship requests, etc.).

### 🎓 Profiles

**Student Profile**
- Full name, faculty, programme, year, specialization.
- Short bio.
- Profile picture upload.

**Mentor Profile**
- Full name, academic position, faculty.
- Areas of expertise (up to 3).
- Office location & LinkedIn link.
- Profile picture upload.

### 📇 Directory
- Browse students & mentors in a single directory.
- Search by name.
- Filter by:
  - Role (student / mentor)
  - Faculty
  - Mentor expertise areas

### 🧑‍🏫 Mentorship Requests
- Students can send mentorship requests to mentors:
  - Choose mentorship type (FYP, course help, research, etc.).
  - Provide a title and detailed description.
  - Optionally upload supporting documents.
- Mentors can:
  - View incoming requests.
  - Accept or decline with comments.
  - See list of accepted mentees.

### 🧩 Projects & Opportunities Board
- Create project / opportunity posts (e.g. competitions, FYPs, events, research).
- Optional “Skills required” tags.
- Users can request to join a project.
- Project owner can:
  - View & manage join requests.
  - Accept/reject requests.
  - See current members.
  - Remove members from the project.
- Members get access to the project’s **chat space**.

### 💬 Project Chat
- Per-project chat room for all members.
- Messages are grouped under each project.
- Reply threading with limited nesting (up to 3 levels) to keep things readable.
- Inline reply UI with avatars & timestamps.

### 💭 Discussion Forum
- Create threads under categories like:
  - Find Team
  - Ask for Help
  - Share Resources
  - General Discussion
- Reply with threaded comments (limited depth).
- Upvote / downvote threads with a simple score system.
- “My Threads” view for quick access to your own posts.

### 🌓 Theming
- Light/dark mode toggle across the app.
- Consistent card-based UI with subtle gradients and shadows.

---

## 🛠 Tech Stack

- **Backend:** Python, Flask
- **Database:** SQLite (via SQLAlchemy)
- **Auth:** Flask-Login + Flask-Bcrypt
- **Forms:** Flask-WTF / WTForms
- **Frontend:** HTML, CSS, Jinja2 templates
- **Other:** File uploads for profile pictures & documents

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/web-app-building-competition-2025.git
cd web-app-building-competition-2025
