"""Auth security regressions: run with the repository's PostgreSQL fixtures."""
import asyncio

import jwt
import pytest
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.core.roles import Role
from app.core.security import hash_password
from app.modules.auth.schemas import LoginIn


async def tokens(client, user):
    r = await client.post('/auth/login', json={'email': user['email'], 'password': 'password123'})
    assert r.status_code == 200
    return r.json()


async def test_disable_invalidates_existing_access(world, client):
    user = await world.user(Role.STUDENT)
    await world.post('/auth/me', who=user, expect=405)  # read endpoint only
    r = await client.patch(f"/users/{user['id']}", headers=world.admin['headers'], json={'is_active': False})
    assert r.status_code == 200
    await world.get('/auth/me', who=user, expect=401)


async def test_password_reset_revokes_access_and_refresh(world, client):
    user = await world.user(Role.STUDENT)
    old = await tokens(client, user)
    r = await client.patch(f"/users/{user['id']}", headers=world.admin['headers'], json={'password': 'replacement123'})
    assert r.status_code == 200
    assert (await client.get('/auth/me', headers={'Authorization': f"Bearer {old['access_token']}"})).status_code == 401
    assert (await client.post('/auth/refresh', json={'refresh_token': old['refresh_token']})).status_code == 401


async def test_refresh_is_one_use_and_new_token_works(world, client):
    user = await world.user(Role.STUDENT)
    old = await tokens(client, user)
    first = await client.post('/auth/refresh', json={'refresh_token': old['refresh_token']})
    assert first.status_code == 200
    assert first.json()['refresh_token'] != old['refresh_token']
    assert (await client.post('/auth/refresh', json={'refresh_token': old['refresh_token']})).status_code == 401
    assert (await client.post('/auth/refresh', json={'refresh_token': first.json()['refresh_token']})).status_code == 200


async def test_concurrent_refresh_only_one_success(world, client):
    user = await world.user(Role.STUDENT)
    old = await tokens(client, user)
    results = await asyncio.gather(*(client.post('/auth/refresh', json={'refresh_token': old['refresh_token']}) for _ in range(2)))
    assert sorted(r.status_code for r in results) == [200, 401]


async def test_malformed_signed_claims_return_401(client):
    from datetime import datetime, timezone
    now = int(datetime.now(timezone.utc).timestamp())
    token = jwt.encode({'typ': 'access', 'sub': 'invalid', 'role': 'admin', 'iat': now, 'exp': now + 60}, settings.jwt_secret, algorithm='HS256')
    assert (await client.get('/auth/me', headers={'Authorization': f'Bearer {token}'})).status_code == 401


def test_bcrypt_byte_boundary():
    with pytest.raises(ValidationError):
        LoginIn(email='x@example.com', password='é' * 37)
    with pytest.raises(ValueError):
        hash_password('x' * 73)


def test_reject_public_signing_keys():
    for key in ['dev-secret-change-me-dev-secret-change-me', 'change-me-to-a-long-random-string', 'short']:
        with pytest.raises(ValidationError):
            Settings(jwt_secret=key)


async def test_student_cannot_subscribe_boarding_topic(world):
    from app.core.access import can_subscribe
    from app.core.db import SessionLocal
    from app.core.deps import Principal
    student = await world.user(Role.STUDENT)
    async with SessionLocal() as session:
        assert not await can_subscribe(session, Principal(student['id'], Role.STUDENT), 'trip:999')
        assert not await can_subscribe(session, Principal(student['id'], Role.STUDENT), 'arbitrary:1')
        assert not await can_subscribe(session, Principal(student['id'], Role.STUDENT), 'route:1')


async def test_trip_reads_and_topics_enforce_assignment(world):
    from app.core.access import can_subscribe
    from app.core.db import SessionLocal
    from app.core.deps import Principal
    w = await world.running_trip()
    student = await world.user(Role.STUDENT)
    driver = await world.user(Role.DRIVER)
    tid = w['trip']['id']
    for path in [f'/trips/{tid}', f'/trips/{tid}/live']:
        await world.get(path, who=student, expect=403)
        await world.get(path, who=driver, expect=403)
        await world.get(path, who=w['driver'])
    await world.allocate(student, w['route'], 0)
    await world.get(f'/trips/{tid}/live', who=student)
    async with SessionLocal() as session:
        sp = Principal(student['id'], Role.STUDENT)
        dp = Principal(w['driver']['id'], Role.DRIVER)
        assert await can_subscribe(session, sp, f"route:{w['route']['id']}")
        assert not await can_subscribe(session, sp, f'trip:{tid}')
        assert await can_subscribe(session, dp, f'trip:{tid}')


async def test_websocket_first_frame_auth_and_topic_denial(monkeypatch):
    from contextlib import asynccontextmanager
    from fastapi import WebSocketDisconnect
    from app.core import realtime
    from app.core.deps import Principal

    @asynccontextmanager
    async def sessions():
        yield object()

    async def authenticate(token, session):
        assert token == 'local-test-token'
        return Principal(999, Role.STUDENT)

    async def denied(*args):
        return False

    class Socket:
        def __init__(self):
            self.frames = iter([{'token': 'local-test-token'}, {'action': 'subscribe', 'topic': 'trip:1'}])
            self.sent = []
        async def accept(self):
            pass
        async def receive_json(self):
            try:
                return next(self.frames)
            except StopIteration:
                raise WebSocketDisconnect()
        async def send_json(self, frame):
            self.sent.append(frame)
        async def close(self, code):
            self.sent.append({'close': code})

    monkeypatch.setattr(realtime, 'SessionLocal', sessions)
    monkeypatch.setattr(realtime, 'authenticated_principal', authenticate)
    monkeypatch.setattr(realtime, 'can_subscribe', denied)
    ws = Socket()
    await realtime.websocket_endpoint(ws)
    assert ws.sent == [{'type': 'error', 'data': {'code': 'forbidden_topic'}}]
    assert ws not in realtime.hub._principal


async def test_send_to_topic_survives_socket_removed_mid_iteration(monkeypatch):
    from contextlib import asynccontextmanager
    from app.core import realtime
    from app.core.deps import Principal

    @asynccontextmanager
    async def sessions():
        yield object()

    hub = realtime.Hub()

    class Socket:
        def __init__(self):
            self.sent = []
        async def send_json(self, frame):
            self.sent.append(frame)
        async def close(self, code):
            pass

    first, second = Socket(), Socket()
    for ws, uid in ((first, 1), (second, 2)):
        hub.add(ws, Principal(uid, Role.STUDENT), 'tok')
        hub.subscribe(ws, 'trip:1')

    async def allowed(session, principal, topic):
        # The other socket disconnects while this permission check is awaited.
        hub.remove(second if principal.id == 1 else first)
        return True

    async def authenticate(token, session):
        return Principal(1, Role.STUDENT)

    monkeypatch.setattr(realtime, 'SessionLocal', sessions)
    monkeypatch.setattr(realtime, 'can_subscribe', allowed)
    monkeypatch.setattr(realtime, 'authenticated_principal', authenticate)
    await hub.send_to_topic('trip:1', 'ping', {})  # used to raise KeyError
