"""Separate encrypted stores, shared local detectors. No fallback to another owner."""
from contextvars import ContextVar
from copy import copy
from dataclasses import replace
import threading

from .dictionary import DictionaryStore
from .storage import SessionStore


class TenantServices:
    def __init__(self, base, accounts):
        self.base = base
        self.accounts = accounts
        self.services = {}
        self.lock = threading.RLock()
        self.selected = ContextVar('wordshield_service')

    def for_user(self, user):
        if user['legacy_owner']:
            return self.base
        uid = user['id']
        with self.lock:
            if uid not in self.services:
                service = copy(self.base)
                service.settings = replace(self.base.settings, data_dir=self.base.settings.data_dir / 'users' / uid)
                service.store = SessionStore(service.settings.data_dir)
                service.dictionary = DictionaryStore(service.store)
                service._write_lock = threading.RLock()
                self.services[uid] = service
            return self.services[uid]

    def all(self):
        if not self.accounts:
            return [self.base]
        return [self.for_user(user) for user in self.accounts.list()
                if user['legacy_owner'] or (self.base.settings.data_dir / 'users' / user['id']).exists()]

    def __getattr__(self, name):
        # Missing request context is a programming error, never implicit admin access.
        return getattr(self.selected.get(), name)
