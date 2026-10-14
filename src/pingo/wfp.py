"""Windows Filtering Platform kill switch, installed atomically and retained on crash.

ABI declarations follow the Windows SDK fwpmtypes.h/fwptypes.h. No global
Windows Firewall policy is changed. `pingo unlock` removes only these filter keys.
"""

import ctypes as c
import ipaddress
import logging
import uuid

LOG = logging.getLogger(__name__)
NAMESPACE = uuid.UUID("ef07e6d8-2985-4a9a-b789-fcfa76fe27d6")
KEYS = [uuid.uuid5(NAMESPACE, str(index)) for index in range(3)]


class GUID(c.Structure):
    _fields_ = [
        ("data1", c.c_uint32),
        ("data2", c.c_uint16),
        ("data3", c.c_uint16),
        ("data4", c.c_ubyte * 8),
    ]

    @property
    def data(self):
        return c.string_at(c.byref(self), 16)

    @classmethod
    def of(cls, value):
        return cls.from_buffer_copy(uuid.UUID(str(value)).bytes_le)


class Display(c.Structure):
    _fields_ = [("name", c.c_wchar_p), ("description", c.c_wchar_p)]


class Blob(c.Structure):
    _fields_ = [("size", c.c_uint32), ("data", c.c_void_p)]


class Number(c.Union):
    _fields_ = [
        ("u8", c.c_uint8),
        ("u32", c.c_uint32),
        ("u64", c.POINTER(c.c_uint64)),
        ("pointer", c.c_void_p),
    ]


class Value(c.Structure):
    _fields_ = [("type", c.c_uint32), ("number", Number)]


class Condition(c.Structure):
    _fields_ = [("key", GUID), ("match", c.c_uint32), ("value", Value)]


class Action(c.Structure):
    _fields_ = [("type", c.c_uint32), ("key", GUID)]


class Context(c.Union):
    _fields_ = [("raw", c.c_uint64), ("key", GUID)]


class Filter(c.Structure):
    _fields_ = [
        ("key", GUID),
        ("display", Display),
        ("flags", c.c_uint32),
        ("provider", c.c_void_p),
        ("data", Blob),
        ("layer", GUID),
        ("sublayer", GUID),
        ("weight", Value),
        ("count", c.c_uint32),
        ("conditions", c.POINTER(Condition)),
        ("action", Action),
        ("context", Context),
        ("reserved", c.c_void_p),
        ("id", c.c_uint64),
        ("effective_weight", Value),
    ]


FIELDS = {
    "interface": "4cd62a49-59c3-4969-b7f3-bda5d32890a4",
    "flags": "632ce23b-5167-435c-86d7-e903684aa80c",
    "remote": "b235ae9a-1d64-49b8-a44c-5ff3d9095045",
    "protocol": "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7",
}
V4 = "09e61aea-d214-46e2-9b21-b26b0b2f28c8"
V6 = "e1735bde-013f-4655-b351-a49e15762df0"
SUBLAYER = "eebecc03-ced4-4380-819a-2734397b2b74"


class WindowsKillSwitch:
    def __init__(self, peer, adapter, dll=None):
        self.peer = int(ipaddress.IPv4Address(peer))
        self.adapter = adapter
        self.dll = dll if dll is not None else c.WinDLL("fwpuclnt.dll", use_last_error=True)
        self.handle = c.c_void_p()
        self.active = False
        self._bind()

    def _bind(self):
        handle, ptr, uint = c.c_void_p, c.c_void_p, c.c_uint32
        for name, args in {
            "FwpmEngineOpen0": [c.c_wchar_p, uint, ptr, ptr, c.POINTER(handle)],
            "FwpmEngineClose0": [handle],
            "FwpmTransactionBegin0": [handle, uint],
            "FwpmTransactionCommit0": [handle],
            "FwpmTransactionAbort0": [handle],
            "FwpmFilterAdd0": [handle, c.POINTER(Filter), ptr, c.POINTER(c.c_uint64)],
            "FwpmFilterDeleteByKey0": [handle, c.POINTER(GUID)],
        }.items():
            function = getattr(self.dll, name)
            function.argtypes, function.restype = args, uint

    @staticmethod
    def check(result):
        if result:
            raise OSError(result, f"Windows Filtering Platform error 0x{result:08x}")

    def _open(self):
        self.check(self.dll.FwpmEngineOpen0(None, 10, None, None, c.byref(self.handle)))

    @staticmethod
    def condition(field, match, value, kind=3):
        item = Condition(GUID.of(FIELDS[field]), match, Value())
        item.value.type = kind
        if kind == 4:
            item.value.number.u64 = c.pointer(value)
        elif kind == 1:
            item.value.number.u8 = value
        else:
            item.value.number.u32 = value
        return item

    def __enter__(self):
        self._open()
        transaction = False
        try:
            luid = c.c_uint64()
            function = self.adapter.dll.WintunGetAdapterLUID
            function.argtypes, function.restype = [c.c_void_p, c.POINTER(c.c_uint64)], None
            function(self.adapter.adapter, c.byref(luid))
            outside = self.condition("interface", 10, luid, 4)  # FWP_MATCH_NOT_EQUAL
            nonloopback = self.condition("flags", 8, 1)  # FWP_MATCH_FLAGS_NONE_SET
            specs = [
                (V4, [outside, nonloopback, self.condition("remote", 10, self.peer)]),
                (
                    V4,
                    [
                        outside,
                        nonloopback,
                        self.condition("remote", 0, self.peer),
                        self.condition("protocol", 10, 1, 1),
                    ],
                ),
                (V6, [nonloopback]),
            ]
            self.check(self.dll.FwpmTransactionBegin0(self.handle, 0))
            transaction = True
            for index, (layer, conditions) in enumerate(specs):
                array = (Condition * len(conditions))(*conditions)
                item = Filter()
                item.key = GUID.of(KEYS[index])
                item.display = Display("Pingo kill switch", "Blocks traffic outside Pingo")
                item.flags = 1  # FWPM_FILTER_FLAG_PERSISTENT
                item.layer, item.sublayer = GUID.of(layer), GUID.of(SUBLAYER)
                item.count, item.conditions = len(array), array
                item.action.type = 0x1001  # FWP_ACTION_BLOCK
                self.check(self.dll.FwpmFilterAdd0(self.handle, c.byref(item), None, None))
            self.check(self.dll.FwpmTransactionCommit0(self.handle))
            transaction = False
            self.active = True
            LOG.info("Windows kill switch active; crash recovery: pingo unlock")
            return self
        except BaseException:
            if transaction:
                self.dll.FwpmTransactionAbort0(self.handle)
            self.dll.FwpmEngineClose0(self.handle)
            self.handle = c.c_void_p()
            raise

    def close(self):
        if self.active:
            try:
                self.check(self.dll.FwpmTransactionBegin0(self.handle, 0))
                for key in KEYS:
                    self.check(self.dll.FwpmFilterDeleteByKey0(self.handle, c.byref(GUID.of(key))))
                self.check(self.dll.FwpmTransactionCommit0(self.handle))
                self.active = False
            except BaseException:
                self.dll.FwpmTransactionAbort0(self.handle)
                LOG.error("Kill switch retained; recover with: pingo unlock")
                raise
            finally:
                self.dll.FwpmEngineClose0(self.handle)
                self.handle = c.c_void_p()

    def __exit__(self, exc_type, *_):
        if exc_type is None:
            self.close()
        elif self.handle:
            self.dll.FwpmEngineClose0(self.handle)
            self.handle = c.c_void_p()
            LOG.error("Kill switch retained after failure; recover with: pingo unlock")


def unlock_windows(dll=None):
    guard = WindowsKillSwitch("0.0.0.0", None, dll=dll)
    guard._open()
    try:
        for key in KEYS:
            result = guard.dll.FwpmFilterDeleteByKey0(guard.handle, c.byref(GUID.of(key)))
            if result != 0x80320003:  # FWP_E_FILTER_NOT_FOUND
                guard.check(result)
    finally:
        guard.dll.FwpmEngineClose0(guard.handle)
