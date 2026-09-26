import json

from channels.generic.websocket import AsyncWebsocketConsumer


class LiveConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.groups = ["events", "jobs"]
        target_id = self.scope["url_route"]["kwargs"].get("target_id")
        if target_id:
            self.groups.append(f"target_{target_id}")
        for g in self.groups:
            await self.channel_layer.group_add(g, self.channel_name)
        await self.accept()

    async def disconnect(self, code):
        for g in getattr(self, "groups", []):
            await self.channel_layer.group_discard(g, self.channel_name)

    async def event_message(self, event):
        await self.send(text_data=json.dumps(event.get("data", {})))
