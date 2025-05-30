import socket


class BSB:
    def __init__(self, data: bytearray = None, size: int = None):
        if data is None:
            data = bytearray()
        if size is None:
            size = len(data)
        self.buf = data  # 缓冲区
        self.ptr = 0  # 读写位置
        self.size = size  # 缓冲区大小
        self.error = False  # 错误状态
        self.end = len(data) if data and size >= 0 else 0

    def remaining(self):  # 剩余字节数
        return self.size - self.ptr

    def import_u8(self):  # 指针写入
        if self.remaining() >= 1:
            value = self.buf[self.ptr]
            self.ptr += 1
            return value
        else:
            self.error = True
            return 0

    def import_u16(self):
        if self.remaining() >= 2:
            value = int.from_bytes(self.buf[self.ptr:self.ptr + 2], 'big')
            self.ptr += 2
            return value
        else:
            self.error = True
            return 0

    def import_u24(self):
        if self.remaining() >= 3:
            value = int.from_bytes(self.buf[self.ptr:self.ptr + 3], 'big')
            self.ptr += 3
            return value
        else:
            self.error = True
            return 0

    def import_u40(self):
        if self.remaining() >= 5:
            value = int.from_bytes(self.buf[self.ptr:self.ptr + 5], 'big')
            self.ptr += 5
            return value
        else:
            self.error = True
            return 0

    def import_u32(self):
        if self.remaining() >= 4:
            value = int.from_bytes(self.buf[self.ptr:self.ptr + 4], 'big')
            self.ptr += 4
            return value
        else:
            self.error = True
            return 0

    def import_u64(self):
        if self.remaining() >= 8:
            value = int.from_bytes(self.buf[self.ptr:self.ptr + 8], 'big')
            self.ptr += 8
            return value
        else:
            self.error = True
            return 0

    def export_u8(self, value):
        if self.remaining() < 1 or self.error:
            self.error = True
            return
        # Handle both integer and single character string input
        if isinstance(value, str) and len(value) == 1:
            value = ord(value)  # Convert character to its ASCII/Unicode value
        self.buf[self.ptr] = value & 0xFF  # 强制转换为单字节
        self.ptr += 1

    def export_bytes(self, data: bytes):  # 指针批量写入
        data_size = len(data)
        if self.remaining() < data_size or self.error:
            self.error = True
            return
        self.buf[self.ptr:self.ptr + data_size] = data
        self.ptr += data_size

    def read_u8(self):
        if self.remaining() < 1 or self.error:
            self.error = True
            return 0
        val = self.buf[self.ptr]  # 取一个字节
        self.ptr += 1  # 读完，指针后移
        return val

    def write_u8(self, value: int):
        if self.error:
            return b''
        return value.to_bytes(1, 'big')  # 大端字节序 0x1234->0x12,0x34

    def read_u16(self):
        if self.remaining() < 2 or self.error:
            self.error = True
            return 0
        val = int.from_bytes(self.buf[self.ptr:self.ptr + 2], 'big')
        self.ptr += 2
        return val

    def write_u16(self, value: int):
        if self.remaining() < 2 or self.error:
            self.error = True
            return b''
        return value.to_bytes(2, 'big')

    def read_u32(self):
        if self.remaining() < 4 or self.error:
            self.error = True
            return 0
        val = int.from_bytes(self.buf[self.ptr:self.ptr + 4], 'little')
        self.ptr += 4
        return val

    def write_u32(self, value: int):
        if self.remaining() < 4 or self.error:
            self.error = True
            return b''
        return value.to_bytes(4, 'little')

    def read_u24(self):
        if self.remaining() < 3 or self.error:
            self.error = True
            return 0
        byte1, byte2, byte3 = self.buf[self.ptr:self.ptr + 3]
        val = (byte1 << 16) | (byte2 << 8) | byte3
        self.ptr += 3
        return val

    def write_u24(self, value: int):
        if self.remaining() < 3 or self.error:
            self.error = True
            return b''
        return ((value & 0xff0000) >> 16).to_bytes(1, 'big') + \
            ((value & 0xff00) >> 8).to_bytes(1, 'big') + \
            (value & 0xff).to_bytes(1, 'big')

    def read_u40(self):
        if self.remaining() < 5 or self.error:
            self.error = True
            return 0
        byte1, byte2, byte3, byte4, byte5 = self.buf[self.ptr:self.ptr + 5]
        val = (byte1 << 32) | (byte2 << 24) | (byte3 << 16) | (byte4 << 8) | byte5
        self.ptr += 5
        return val

    def write_u40(self, value: int):
        if self.remaining() < 5 or self.error:
            self.error = True
            return b''
        return ((value & 0xff00000000) >> 32).to_bytes(1, 'big') + \
            ((value & 0x00ff000000) >> 24).to_bytes(1, 'big') + \
            ((value & 0x0000ff0000) >> 16).to_bytes(1, 'big') + \
            ((value & 0x000000ff00) >> 8).to_bytes(1, 'big') + \
            (value & 0x00000000ff).to_bytes(1, 'big')

    def skip(self, size: int):
        if self.ptr + size > self.size or self.error:
            self.error = True
        else:
            self.ptr += size

    def rewind(self, size: int):
        if self.ptr - size < 0 or self.error:
            self.error = True
        else:
            self.ptr -= size

    def work_ptr(self):
        return self.buf[self.ptr:]

    def import_ptr(self, data_size: int) -> bytes:
        if self.ptr + data_size <= self.size and not self.error:
            data = self.buf[self.ptr:self.ptr + data_size]
            return data
        else:
            self.error = True
            return b''

    def export_ptr(self, data, length):
        remaining = len(self.buf) - self.ptr
        copy_len = min(length, remaining)
        if copy_len <= 0:
            return
        self.buf[self.ptr:self.ptr + copy_len] = data[:copy_len]
        self.ptr += copy_len

    def import_bsb(self, size):
        # 从缓冲区b中导入size字节的数据到新的BSB对象
        if self.ptr + size > self.size or self.error:
            self.error = True
            return None

        # 创建新的BSB对象
        new_bsb = type(self)(self.buf[self.ptr:self.ptr + size], size)
        self.ptr += size
        return new_bsb

    def export_sprintf(self, fmt, *args):
        if self.error or self.ptr >= self.size:
            return
        # 格式化字符串
        formatted = fmt % args
        byte_data = formatted.encode('utf-8')
        data_len = len(byte_data)
        if data_len <= self.remaining():
            self.buf[self.ptr:self.ptr + data_len] = byte_data
            self.ptr += data_len
        else:
            self.error = True

    def export_cstr(self, s: str):
        if self.error:
            return
        try:
            byte_data = s.encode('utf-8')
            data_len = len(byte_data)

            # 检查缓冲区空间
            if self.ptr + data_len > self.size:
                self.error = True
                return

            # 写入数据
            self.buf[self.ptr:self.ptr + data_len] = byte_data
            self.ptr += data_len
        except Exception:
            self.error = True

    def export_inet_ntop(self, address_family, packed_ip):
        if self.error:
            return
        try:
            if address_family == socket.AF_INET:
                ip_str = socket.inet_ntop(address_family, packed_ip)
            elif address_family == socket.AF_INET6:
                if packed_ip.startswith(b'\x00' * 10 + b'\xff\xff'):
                    ip_str = socket.inet_ntop(socket.AF_INET, packed_ip[12:])
                else:
                    ip_str = socket.inet_ntop(address_family, packed_ip)
            else:
                self.error = True
                return

            # 计算可用空间
            ip_bytes = ip_str.encode('utf-8')
            ip_len = len(ip_bytes)

            if ip_len > self.remaining():
                self.error = True
                return

            # 写入缓冲区并移动指针
            self.buf[self.ptr:self.ptr + ip_len] = ip_bytes
            self.ptr += ip_len

        except (OSError, ValueError, BufferError):
            self.error = True

    def length(self):
        return self.ptr

    def shrink_remaining(self, rem):
        """调整缓冲区可用空间（等效 C 的 BSB_SHRINK_REMAINING）"""
        if self.end and (self.ptr + rem < self.end):
            self.end = self.ptr + rem

    def get_bytes(self, size: int) -> bytearray:
        """
        获取指定大小的字节，并前进指针
        """
        if self.remaining() < size or self.error:
            self.error = True
            return bytearray()
        
        # 提取数据
        data = self.buf[self.ptr:self.ptr + size]
        self.ptr += size
        return data
