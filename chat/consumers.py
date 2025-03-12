import json
from channels.generic.websocket import AsyncWebsocketConsumer
from django.contrib.auth import get_user_model
from django.utils.timezone import now
from asgiref.sync import sync_to_async
from .models import Room, Message

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = f"chat_{self.room_name}"

        # ✅ Fix: Ensure `get_or_create()` works correctly
        self.room, _ = await sync_to_async(Room.objects.get_or_create)(name=self.room_name)

        # ✅ Add WebSocket to Redis channel group
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

        # ✅ Send chat history
        await self.send_chat_history()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        message = data.get("message", "").strip()
        username = data.get("username", "Anonymous")

        if not message:
            return  # Ignore empty messages

        try:
            user = await sync_to_async(User.objects.get)(username=username)
        except User.DoesNotExist:
            return  # Ignore messages from non-existent users

        # ✅ Save message to PostgreSQL
        new_message = await self.save_message(user, message)

        # ✅ Send message to Redis channel
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                "type": "chat_message",
                "message": new_message.content,
                "username": new_message.user.username,
                "timestamp": new_message.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            },
        )

    async def chat_message(self, event):
        """Receive message from Redis and send to WebSocket."""
        await self.send(text_data=json.dumps(event))

    @sync_to_async
    def save_message(self, user, message):
        """Save message to PostgreSQL."""
        return Message.objects.create(
            room=self.room,  # ✅ No need for `self.room[0]`
            user=user,
            content=message,
            timestamp=now()
        )

    async def send_chat_history(self):
        """Send last 20 messages to the user on connection."""
        messages = await sync_to_async(list)(
            Message.objects.filter(room=self.room).order_by('-timestamp')[:20]
        )
        messages.reverse()  # Show oldest first

        history = [
            {
                "username": msg.user.username,
                "message": msg.content,
                "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for msg in messages
        ]
        await self.send(text_data=json.dumps({"history": history}))
