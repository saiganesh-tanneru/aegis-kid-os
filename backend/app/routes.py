"""Compatibility re-export: all routers live in app/routers/.

Import the routers from here (`from app.routes import routers`) or
directly from `app.routers.<module>`.
"""
from .routers.admin import router as admin_router
from .routers.digilocker import router as digilocker_router
from .routers.heartbeat import router as heartbeat_router
from .routers.unblock import router as unblock_router

routers = [heartbeat_router, unblock_router, digilocker_router, admin_router]

__all__ = ["routers", "heartbeat_router", "unblock_router", "digilocker_router", "admin_router"]
