# CMFS Feature Implementation Plan

## Project: Citizen Feedback Management System (CMFS)

## Features to Implement:
1. **Password Reset Functionality**
2. **Government Project Tracking**
3. **Mobile App API**
4. **Chat/Messaging Between Users**

---

## 1. Password Reset Functionality

### Backend Changes:
- [ ] Add MongoDB collection for password reset tokens
- [ ] Create `/api/password-reset-request` endpoint (generate token, send email)
- [ ] Create `/api/password-reset/<token>` endpoint (validate token)
- [ ] Create `/api/reset-password` endpoint (update password)
- [ ] Configure Flask-Mail for sending emails
- [ ] Add token expiration (24 hours)

### Frontend Changes:
- [ ] Add "Forgot Password" link on login page
- [ ] Create PasswordResetRequestPage component
- [ ] Create PasswordResetPage component (enter new password)
- [ ] Add routes for password reset pages

---

## 2. Government Project Tracking

### Backend Changes:
- [ ] Add MongoDB collection for projects
- [ ] Create `/api/projects` GET endpoint (list all projects)
- [ ] Create `/api/projects` POST endpoint (admin only - create project)
- [ ] Create `/api/projects/<project_id>` PUT endpoint (update project)
- [ ] Create `/api/projects/<project_id>` DELETE endpoint (delete project)
- [ ] Add project status tracking (Planning, In Progress, Completed, On Hold)
- [ ] Link feedback to specific projects

### Frontend Changes:
- [ ] Create GovernmentProjects page component
- [ ] Add project cards with status indicators
- [ ] Add project creation form (admin only)
- [ ] Add project detail view with associated feedback
- [ ] Add navigation link to projects page
- [ ] Update Dashboard to show project-filtered feedback

---

## 3. Mobile App API

### Backend Changes:
- [ ] Create `/api/mobile/register` endpoint (simplified registration)
- [ ] Create `/api/mobile/login` endpoint (JWT-based auth)
- [ ] Create `/api/mobile/feedback` endpoints (CRUD operations)
- [ ] Create `/api/mobile/projects` endpoint (list projects)
- [ ] Add JWT token generation and validation
- [ ] Add rate limiting for mobile endpoints
- [ ] Create mobile-friendly JSON responses

### Configuration:
- [ ] Install PyJWT for token handling
- [ ] Add JWT_SECRET_KEY configuration
- [ ] Create token refresh mechanism

---

## 4. Chat/Messaging Between Users

### Backend Changes:
- [ ] Add MongoDB collection for conversations
- [ ] Add MongoDB collection for messages
- [ ] Create `/api/conversations` endpoints (list, create)
- [ ] Create `/api/messages/<conversation_id>` endpoints (send, receive)
- [ ] Create `/api/conversations/<conversation_id>` GET endpoint
- [ ] Add real-time support using Socket.IO
- [ ] Add unread message tracking

### Frontend Changes:
- [ ] Create Messages/Chat page component
- [ ] Create conversation list sidebar
- [ ] Create chat window component
- [ ] Add message input with send button
- [ ] Add unread message badge in navigation
- [ ] Integrate Socket.IO for real-time updates

---

## Implementation Order

1. **Phase 1**: Password Reset (Foundation for user management)
2. **Phase 2**: Government Project Tracking (Core feature enhancement)
3. **Phase 3**: Mobile App API (Extend accessibility)
4. **Phase 4**: Chat/Messaging (User engagement feature)

---

## Dependencies to Install

### Backend:
```bash
pip install flask-jwt-extended flask-redis flask-rate limiter
```

### Frontend:
```bash
# Already has socket.io-client installed
```

---

## File Structure After Changes

### Backend (new files):
- backend/routes/password_reset.py
- backend/routes/projects.py
- backend/routes/mobile.py
- backend/routes/chat.py

### Frontend (new files):
- frontend/src/components/PasswordResetRequest.js
- frontend/src/components/PasswordReset.js
- frontend/src/components/GovernmentProjects.js
- frontend/src/components/ProjectDetail.js
- frontend/src/components/Chat.js
- frontend/src/components/ConversationsList.js

---

