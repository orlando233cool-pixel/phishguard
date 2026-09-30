"""
cache_ttl.py
------------
Caché en memoria, thread-safe, con expiración (TTL) y desalojo LRU.

Para un despliegue con varios workers (gunicorn -w 4) cada proceso tendría su
propia caché; en ese caso sustituye esta clase por Redis manteniendo la misma
interfaz (get / set).
"""

import copy
import threading
import time
from collections import OrderedDict


class TTLCache:
    def __init__(self, max_entries: int = 500, ttl_seconds: int = 3600):
        self.max_entries = max(1, int(max_entries))
        self.ttl = max(1, int(ttl_seconds))
        self._datos = OrderedDict()          # clave -> (expira_en, valor)
        self._lock = threading.Lock()

    def get(self, clave):
        """Devuelve una COPIA del valor (para que nadie mute la caché) o None."""
        with self._lock:
            item = self._datos.get(clave)
            if item is None:
                return None
            expira, valor = item
            if expira < time.monotonic():
                del self._datos[clave]
                return None
            self._datos.move_to_end(clave)   # marca como usado recientemente
            return copy.deepcopy(valor)

    def set(self, clave, valor):
        with self._lock:
            self._datos[clave] = (time.monotonic() + self.ttl, copy.deepcopy(valor))
            self._datos.move_to_end(clave)
            while len(self._datos) > self.max_entries:
                self._datos.popitem(last=False)   # elimina el menos usado

    def __len__(self):
        with self._lock:
            return len(self._datos)
