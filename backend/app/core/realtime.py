"""WebSocket hub: pushes live updates to connected clients.

Channels a socket receives from:
  * its own user   -> hub.send_to_user(user_id, msg)
  * its role       -> hub.send_to_role(Role.ADMIN, msg)
  * topics it asked for, e.g. "route:3" or "trip:12" -> hub.send_to_topic("trip:12", msg)

Client protocol (JSON text frames):
  -> {"action": "subscribe", "topic": "route:3"}
  -> {"action": "unsubscribe", "topic": "route:3"}
  -> {"action": "ping"}                      <- {"type": "pong"}
  <- {"type": "<message type>", "data": {...}}

In-memory and single-process. To run several API workers, back this with Redis pub/sub.
"""

import asyncio
import logging
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.deps import Principal, authenticated_principal
from app.core.db import SessionLocal
from app.core.access import can_subscribe
from app.core.errors import DomainError
from app.core.events import jsonable
from app.core.roles import Role

log = logging.getLogger("transit.realtime")


class Hub:
    def __init__(self) -> None:
        self._by_user: dict[int, set[WebSocket]] = defaultdict(set)
        self._by_role: dict[Role, set[WebSocket]] = defaultdict(set)
        self._by_topic: dict[str, set[WebSocket]] = defaultdict(set)
        self._topics_of: dict[WebSocket, set[str]] = defaultdict(set)
        self._principal: dict[WebSocket, Principal] = {}
        self._tokens: dict[WebSocket, str] = {}

    def add(self, ws: WebSocket, p: Principal, token: str) -> None:
        self._principal[ws] = p
        self._tokens[ws] = token
        self._by_user[p.id].add(ws)
        self._by_role[p.role].add(ws)

    def remove(self, ws: WebSocket) -> None:
        self._tokens.pop(ws, None)
        p = self._principal.pop(ws, None)
        if p:
            self._by_user[p.id].discard(ws)
            self._by_role[p.role].discard(ws)
        for topic in self._topics_of.pop(ws, set()):
            self._by_topic[topic].discard(ws)

    def subscribe(self, ws: WebSocket, topic: str) -> None:
        self._by_topic[topic].add(ws)
        self._topics_of[ws].add(topic)

    def unsubscribe(self, ws: WebSocket, topic: str) -> None:
        self._by_topic[topic].discard(ws)
        self._topics_of[ws].discard(topic)

    async def _send(self, sockets: set[WebSocket], msg_type: str, data: Any) -> None:
        if not sockets:
            return
        frame = {"type": msg_type, "data": jsonable(data)}
        live = []
        for ws in list(sockets):
            try:
                async with SessionLocal() as session:
                    await authenticated_principal(self._tokens[ws], session)
                live.append(ws)
            except (DomainError, KeyError):
                await ws.close(code=4401)
                self.remove(ws)
        results = await asyncio.gather(
            *(ws.send_json(frame) for ws in live), return_exceptions=True
        )
        for ws, res in zip(live, results):
            if isinstance(res, Exception):
                self.remove(ws)

    async def send_to_user(self, user_id: int, msg_type: str, data: Any) -> None:
        await self._send(self._by_user.get(user_id, set()), msg_type, data)

    async def send_to_users(self, user_ids: list[int], msg_type: str, data: Any) -> None:
        sockets: set[WebSocket] = set()
        for uid in user_ids:
            sockets |= self._by_user.get(uid, set())
        await self._send(sockets, msg_type, data)

    async def send_to_role(self, role: Role, msg_type: str, data: Any) -> None:
        await self._send(self._by_role.get(role, set()), msg_type, data)

    async def send_to_topic(self, topic: str, msg_type: str, data: Any) -> None:
        permitted = set()
        async with SessionLocal() as session:
            for ws in list(self._by_topic.get(topic, set())):
                # A socket can disconnect (and be removed) while we await below.
                principal = self._principal.get(ws)
                if principal is None:
                    continue
                if await can_subscribe(session, principal, topic):
                    permitted.add(ws)
                else:
                    self.unsubscribe(ws, topic)
        await self._send(permitted, msg_type, data)

    def connection_count(self) -> int:
        return len(self._principal)


hub = Hub()
router = APIRouter(tags=["realtime"])


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    # Authenticate in a first frame rather than a URL, which proxies often log.
    await ws.accept()
    try:
        auth = await asyncio.wait_for(ws.receive_json(), timeout=10)
        token = auth.get("token") if isinstance(auth, dict) else None
        if not isinstance(token, str) or len(token) > 4096:
            await ws.close(code=4401)
            return
        async with SessionLocal() as session:
            principal = await authenticated_principal(token, session)
        hub.add(ws, principal, token)
        while True:
            # Periodic wake means even idle sockets expire/revoke within 30 seconds.
            try:
                msg = await asyncio.wait_for(ws.receive_json(), timeout=30)
            except asyncio.TimeoutError:
                msg = {}
            async with SessionLocal() as session:
                await authenticated_principal(token, session)
                action = msg.get("action") if isinstance(msg, dict) else None
                topic = msg.get("topic") if isinstance(msg, dict) else None
                if action == "subscribe" and isinstance(topic, str):
                    if (len(hub._topics_of[ws]) >= 20 or
                            not await can_subscribe(session, principal, topic)):
                        await ws.send_json({"type": "error", "data": {"code": "forbidden_topic"}})
                    else:
                        hub.subscribe(ws, topic)
                elif action == "unsubscribe" and isinstance(topic, str):
                    hub.unsubscribe(ws, topic)
                elif action == "ping":
                    await ws.send_json({"type": "pong", "data": {}})
    except DomainError:
        await ws.close(code=4401)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        log.exception("WebSocket error")
        await ws.close(code=1011)
    finally:
        hub.remove(ws)
