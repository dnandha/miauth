#
#     MiAuth - Authenticate and interact with Xiaomi devices over BLE
#     Copyright (C) 2022  Daljeet Nandha
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as
#     published by the Free Software Foundation, either version 3 of the
#     License, or (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
from abc import ABC, abstractmethod


class BLEBase(ABC):

    @abstractmethod
    def set_handler(self, handler):
        raise NotImplementedError

    @abstractmethod
    def enable_notify(self, uuid):
        raise NotImplementedError

    @abstractmethod
    def read(self, ch):
        raise NotImplementedError

    @abstractmethod
    def write(self, ch, data, resp=False):
        raise NotImplementedError

    @abstractmethod
    def write_chunked(self, ch, data, resp=False, chunk_size=20):
        raise NotImplementedError

    @abstractmethod
    def write_parcel(self, ch, data, resp=False, chunk_size=18):
        raise NotImplementedError

    @abstractmethod
    def connect(self):
        raise NotImplementedError

    @abstractmethod
    def disconnect(self):
        raise NotImplementedError

    @abstractmethod
    def wait_notify(self, secs=1.0):
        raise NotImplementedError

    @abstractmethod
    def read_device_name(self):
        raise NotImplementedError

    @abstractmethod
    def has_channel(self):
        raise NotImplementedError
