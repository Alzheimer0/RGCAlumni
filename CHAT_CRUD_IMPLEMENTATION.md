# Chat CRUD Implementation Plan

## Overview
This document outlines the implementation of full CRUD (Create, Read, Update, Delete) functionality for chat rooms and direct messages.

## Current Status
- ✅ Create: Messages can be sent
- ✅ Read: Messages are displayed
- ❌ Update: No editing capability
- ❌ Delete: Limited deletion (admin only)

## Backend Implementation

### 1. Database Schema Updates
```python
# Chat Messages Collection
{
    "_id": ObjectId,
    "sender": string,
    "message": string,
    "timestamp": datetime,
    "room": string,
    "edited": boolean,
    "edited_at": datetime,  # New field
    "file": {               # Already exists
        "name": string,
        "type": string,
        "data": string
    }
}

# Direct Messages Collection
{
    "_id": ObjectId,
    "sender": string,
    "recipient": string,
    "message": string,
    "timestamp": datetime,
    "read": boolean,
    "edited": boolean,
    "edited_at": datetime,  # New field
    "file": {               # Already exists
        "name": string,
        "type": string,
        "data": string
    }
}
```

### 2. SocketIO Event Handlers

#### Edit Message Events
```python
@socketio.on('edit_message')
def handle_edit_message(data):
    # Update chat room message
    pass

@socketio.on('edit_direct_message')
def handle_edit_direct_message(data):
    # Update direct message
    pass
```

#### Delete Message Events
```python
@socketio.on('delete_message')
def handle_delete_message(data):
    # Delete chat room message
    pass

@socketio.on('delete_direct_message')
def handle_delete_direct_message(data):
    # Delete direct message
    pass
```

## Frontend Implementation

### 1. UI Elements to Add

#### Message Actions Bar
```html
<div class="message-actions">
    <button class="edit-btn" title="Edit message">
        <i class="fas fa-edit"></i>
    </button>
    <button class="delete-btn" title="Delete message">
        <i class="fas fa-trash"></i>
    </button>
</div>
```

#### Edit Modal
```html
<div class="modal" id="editMessageModal">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Edit Message</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <textarea class="form-control" id="editMessageContent"></textarea>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-primary" id="saveEditButton">Save Changes</button>
            </div>
        </div>
    </div>
</div>
```

### 2. JavaScript Functionality

#### Edit Message Flow
1. Click edit button
2. Show modal with current message content
3. User modifies content
4. Send edit request via SocketIO
5. Update message display in real-time

#### Delete Message Flow
1. Click delete button
2. Show confirmation dialog
3. Send delete request via SocketIO
4. Remove message from display in real-time

## Security Considerations

1. **Authorization**: Only message owners can edit/delete their messages
2. **Admin Privileges**: Admins can delete any message
3. **Audit Trail**: Track who edited/deleted messages and when
4. **Rate Limiting**: Prevent spam editing/deleting

## Implementation Steps

### Phase 1: Backend
1. Update message storage to include IDs and edit tracking
2. Implement edit/delete SocketIO handlers
3. Add proper authorization checks

### Phase 2: Frontend
1. Add edit/delete UI elements
2. Implement edit modal functionality
3. Add real-time update listeners
4. Style the new elements

### Phase 3: Testing
1. Test edit functionality
2. Test delete functionality
3. Test authorization rules
4. Test real-time updates

## Files to Modify

### Backend:
- `app-using-mongodb.py` - Add CRUD SocketIO handlers

### Frontend:
- `templates/chat.html` - Add edit/delete UI
- `templates/conversation.html` - Add edit/delete UI
- JavaScript sections in both files - Add CRUD functionality

## Expected Outcome

After implementation, users will be able to:
- ✅ Edit their own messages in real-time
- ✅ Delete their own messages
- ✅ See "edited" indicators on modified messages
- ✅ Admins can delete any message
- ✅ Real-time updates for all users in the chat