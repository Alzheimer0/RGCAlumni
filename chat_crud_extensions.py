# Chat CRUD Operations Extension
# This file contains additional CRUD functionality for chat messages

from datetime import datetime
from bson import ObjectId

def add_chat_crud_operations(socketio, mongo):
    """Add CRUD operations to existing SocketIO instance"""
    
    @socketio.on('edit_message')
    def handle_edit_message(data):
        """Handle editing a message"""
        message_id = data['message_id']
        new_message = data['message']
        username = data['username']
        
        if mongo is not None:
            # Update message in database
            result = mongo.db.chat_messages.update_one(
                {'_id': ObjectId(message_id), 'sender': username},
                {
                    '$set': {
                        'message': new_message,
                        'edited': True,
                        'edited_at': datetime.now()
                    }
                }
            )
            
            if result.modified_count > 0:
                # Broadcast edit to room
                socketio.emit('message_edited', {
                    'message_id': message_id,
                    'message': new_message,
                    'edited_by': username,
                    'edited_at': datetime.now().strftime('%H:%M')
                }, room='global')

    @socketio.on('delete_message')
    def handle_delete_message(data):
        """Handle deleting a message"""
        message_id = data['message_id']
        username = data['username']
        is_admin = data.get('is_admin', False)
        
        if mongo is not None:
            # Check if user can delete (own message or admin)
            query = {'_id': ObjectId(message_id)}
            if not is_admin:
                query['sender'] = username
                
            # Delete message from database
            result = mongo.db.chat_messages.delete_one(query)
            
            if result.deleted_count > 0:
                # Broadcast deletion to room
                socketio.emit('message_deleted', {
                    'message_id': message_id,
                    'deleted_by': username
                }, room='global')

    @socketio.on('edit_direct_message')
    def handle_edit_direct_message(data):
        """Handle editing a direct message"""
        message_id = data['message_id']
        new_message = data['message']
        sender = data['sender']
        
        if mongo is not None:
            # Update message in database
            result = mongo.db.direct_messages.update_one(
                {'_id': ObjectId(message_id), 'sender': sender},
                {
                    '$set': {
                        'message': new_message,
                        'edited': True,
                        'edited_at': datetime.now()
                    }
                }
            )
            
            if result.modified_count > 0:
                # Get recipient to broadcast to
                message_doc = mongo.db.direct_messages.find_one({'_id': ObjectId(message_id)})
                if message_doc:
                    recipient = message_doc['recipient'] if message_doc['sender'] == sender else message_doc['sender']
                    # Broadcast edit to recipient
                    socketio.emit('direct_message_edited', {
                        'message_id': message_id,
                        'message': new_message,
                        'edited_by': sender,
                        'edited_at': datetime.now().strftime('%H:%M')
                    }, room=recipient)

    @socketio.on('delete_direct_message')
    def handle_delete_direct_message(data):
        """Handle deleting a direct message"""
        message_id = data['message_id']
        sender = data['sender']
        is_admin = data.get('is_admin', False)
        
        if mongo is not None:
            # Check if user can delete (own message or admin)
            query = {'_id': ObjectId(message_id)}
            if not is_admin:
                query['sender'] = sender
                
            # Get recipient before deletion for broadcasting
            message_doc = mongo.db.direct_messages.find_one(query)
            if message_doc:
                recipient = message_doc['recipient'] if message_doc['sender'] == sender else message_doc['sender']
                
                # Delete message from database
                result = mongo.db.direct_messages.delete_one(query)
                
                if result.deleted_count > 0:
                    # Broadcast deletion to recipient
                    socketio.emit('direct_message_deleted', {
                        'message_id': message_id,
                        'deleted_by': sender
                    }, room=recipient)