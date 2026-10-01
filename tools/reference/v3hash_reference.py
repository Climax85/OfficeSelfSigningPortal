# Independent reference implementation of the MS-OVBA V3 Contents Hash
# (MS-OVBA 2.4.2.5 / 2.4.2.6 / 2.4.2.7), written directly from the specification
# pseudocode with a different parser stack (Python + olefile). Used to cross-validate
# the production C# implementation (VbaContentHasher) during development; the resulting
# digest values are pinned as golden values in tests/OfficeSelfSigningPortal.Tests/Signing.
#
# Usage: python v3hash_reference.py <file.xlsm|vbaProject.bin>
# Prints the SHA-256 hex digest of ContentBuffer = V3ContentNormalizedData || ProjectNormalizedData.

import hashlib
import io
import struct
import sys
import zipfile

import olefile

LF = 0x0A

DEFAULT_ATTRIBUTES = [
    b'Attribute VB_Base = "0{00020820-0000-0000-C000-000000000046}"',
    b'Attribute VB_GlobalNameSpace = False',
    b'Attribute VB_Creatable = False',
    b'Attribute VB_PredeclaredId = True',
    b'Attribute VB_Exposed = True',
    b'Attribute VB_TemplateDerived = False',
    b'Attribute VB_Customizable = True',
]

EXCLUDED_PROPERTIES = {"ID", "Document", "CMG", "DPB", "GC"}


# ---------------------------------------------------------------- MS-OVBA 2.4.1
def rle_decompress(container: bytes) -> bytes:
    if not container or container[0] != 0x01:
        raise ValueError("invalid CompressedContainer signature")
    out = bytearray()
    pos = 1
    while pos < len(container):
        header = container[pos] | (container[pos + 1] << 8)
        chunk_size = (header & 0x0FFF) + 3
        is_compressed = (header & 0x8000) != 0
        if (header & 0x7000) != 0x3000:
            raise ValueError("invalid chunk signature")
        chunk = container[pos + 2: pos + chunk_size]
        if not is_compressed:
            out += chunk[:4096]
        else:
            _rle_decompress_chunk(chunk, out)
        pos += chunk_size
    return bytes(out)


def _copy_token_help(decompressed: int):
    difference = max(decompressed, 1)
    bit_count = 4
    while (1 << bit_count) < difference:
        bit_count += 1
    length_mask = 0xFFFF >> bit_count
    offset_mask = (~length_mask) & 0xFFFF
    return bit_count, length_mask, offset_mask


def _rle_decompress_chunk(chunk: bytes, out: bytearray):
    chunk_start = len(out)
    pos = 0
    while pos < len(chunk):
        flags = chunk[pos]
        pos += 1
        for bit in range(8):
            if pos >= len(chunk):
                break
            if (flags & (1 << bit)) == 0:
                out.append(chunk[pos])
                pos += 1
            else:
                token = chunk[pos] | (chunk[pos + 1] << 8)
                pos += 2
                bit_count, length_mask, offset_mask = _copy_token_help(len(out) - chunk_start)
                length = (token & length_mask) + 3
                offset = ((token & offset_mask) >> (16 - bit_count)) + 1
                source = len(out) - offset
                if source < chunk_start:
                    raise ValueError("copy token outside chunk")
                for _ in range(length):
                    out.append(out[source])
                    source += 1


# ---------------------------------------------------------------- MS-OVBA 2.3.4.2
class DirCursor:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def remaining(self):
        return len(self.data) - self.pos

    def u16(self):
        v = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return v

    def u32(self):
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def peek_u16(self):
        return struct.unpack_from("<H", self.data, self.pos)[0]

    def bytes(self, n):
        v = self.data[self.pos: self.pos + n]
        self.pos += n
        return v

    def skip(self, n):
        self.pos += n


def parse_dir(decompressed: bytes):
    """Minimaler dir-Parser: liefert alle für MS-OVBA 2.4.2.5 benötigten Felder."""
    r = DirCursor(decompressed)
    d = {
        "code_page": 1252, "syskind_size": 0, "lcid": 0, "lcid_invoke": 0,
        "project_name": b"", "docstring_size": 0, "docstring_unicode_size": 0,
        "helpfile1_size": 0, "helpfile2_size": 0, "helpcontext_size": 0,
        "libflags": 0, "version_reserved": 0, "version_major": 0, "version_minor": 0,
        "constants": b"", "constants_unicode": b"", "references": [], "modules": [],
        "terminator_reserved": 0,
    }
    current_name = None
    current_module = None

    def name_record():
        size_of_name = r.u32()
        name = r.bytes(size_of_name)
        reserved = r.u16()
        size_unicode = r.u32()
        name_unicode = r.bytes(size_unicode)
        return {
            "size_of_name": size_of_name, "name": name, "reserved": reserved,
            "size_of_name_unicode": size_unicode, "name_unicode": name_unicode,
        }

    def read_control(target):
        size_twiddled = r.u32()
        target["control_size_of_libid_twiddled"] = size_twiddled
        target["control_libid_twiddled"] = r.bytes(size_twiddled)
        target["control_reserved1"] = r.u32()
        target["control_reserved2"] = r.u16()
        if target["control_reserved2"] == 0x003E:
            if r.u16() != 0x0016:
                raise ValueError("expected repeated REFERENCENAME")
            target["control_name_extended"] = name_record()
        if r.remaining() >= 2 and r.peek_u16() == 0x0030:
            r.u16()
            target["control_has_extended"] = True
            size_extended = r.u32()
            target["control_size_of_libid_extended"] = size_extended
            target["control_libid_extended"] = r.bytes(size_extended)
            target["control_reserved4"] = r.u32()
            target["control_reserved5"] = r.u16()
            target["control_original_typelib"] = r.bytes(16)
            target["control_cookie"] = r.u32()
        else:
            target["control_has_extended"] = False

    while r.remaining() > 0:
        rid = r.u16()
        if rid == 0x0001:
            d["syskind_size"] = r.u32()
            r.skip(d["syskind_size"])
        elif rid == 0x0002:
            r.u32()
            d["lcid"] = r.u32()
        elif rid == 0x0014:
            r.u32()
            d["lcid_invoke"] = r.u32()
        elif rid == 0x0003:
            r.u32()
            d["code_page"] = r.u16()
        elif rid == 0x0004:
            d["project_name"] = r.bytes(r.u32())
        elif rid == 0x0005:
            d["docstring_size"] = r.u32()
            r.skip(d["docstring_size"])
            if r.u16() != 0x0040:
                raise ValueError("PROJECTDOCSTRING without unicode record")
            d["docstring_unicode_size"] = r.u32()
            r.skip(d["docstring_unicode_size"])
        elif rid == 0x0006:
            d["helpfile1_size"] = r.u32()
            r.skip(d["helpfile1_size"])
            if r.u16() != 0x003D:
                raise ValueError("PROJECTHELPFILEPATH without second record")
            d["helpfile2_size"] = r.u32()
            r.skip(d["helpfile2_size"])
        elif rid == 0x0007:
            d["helpcontext_size"] = r.u32()
            r.skip(d["helpcontext_size"])
        elif rid == 0x0008:
            r.u32()
            d["libflags"] = r.u32()
        elif rid == 0x0009:
            d["version_reserved"] = r.u32()
            d["version_major"] = r.u32()
            d["version_minor"] = r.u16()
        elif rid == 0x000C:
            d["constants"] = r.bytes(r.u32())
            if r.u16() != 0x003C:
                raise ValueError("PROJECTCONSTANTS without unicode record")
            d["constants_unicode"] = r.bytes(r.u32())
        elif rid == 0x0016:
            current_name = name_record()
        elif rid == 0x000D:
            # MS-OVBA 2.3.4.2.2.2: Id, Size (deckt SizeOfLibid, Libid, Reserved1 und
            # Reserved2 ab), SizeOfLibid, Libid, Reserved1, Reserved2. Das verschachtelte
            # SizeOfLibid schreibt echtes Office — beide Felder explizit lesen.
            ref = {"record_id": rid, "name_record": current_name}
            record_size = r.u32()
            size = r.u32()
            if record_size != size + 10:
                raise ValueError(f"REFERENCEREGISTERED: Size ({record_size}) passt nicht zu SizeOfLibid ({size})")
            ref["registered_size"] = record_size
            ref["registered_size_of_libid"] = size
            ref["registered_libid"] = r.bytes(size)
            ref["registered_reserved1"] = r.u32()
            ref["registered_reserved2"] = r.u16()
            d["references"].append(ref)
        elif rid == 0x000E:
            # MS-OVBA 2.3.4.2.2.4: Id, Size (deckt beide Libids + Major/Minor ab),
            # dann die Felder selbst. Das äußere Size-Feld schreibt echtes Office.
            ref = {"record_id": rid, "name_record": current_name}
            record_size = r.u32()
            ref["project_size"] = record_size
            ref["project_size_abs"] = r.u32()
            ref["project_libid_abs"] = r.bytes(ref["project_size_abs"])
            ref["project_size_rel"] = r.u32()
            ref["project_libid_rel"] = r.bytes(ref["project_size_rel"])
            ref["project_major"] = r.u32()
            ref["project_minor"] = r.u16()
            if record_size != ref["project_size_abs"] + ref["project_size_rel"] + 14:
                raise ValueError(
                    f"REFERENCEPROJECT: Size ({record_size}) passt nicht zu den Libid-Größen "
                    f"({ref['project_size_abs']}/{ref['project_size_rel']}).")
            d["references"].append(ref)
        elif rid == 0x0033:
            ref = {"record_id": rid, "name_record": current_name}
            size = r.u32()
            ref["original_size_of_libid"] = size
            ref["original_libid"] = r.bytes(size)
            d["references"].append(ref)
        elif rid == 0x002F:
            if (d["references"] and d["references"][-1]["record_id"] == 0x0033
                    and "control_libid_twiddled" not in d["references"][-1]):
                target = d["references"][-1]
            else:
                target = {"record_id": rid, "name_record": current_name}
                d["references"].append(target)
            read_control(target)
        elif rid == 0x0019:
            current_module = {"name": r.bytes(r.u32())}
            d["modules"].append(current_module)
        elif rid == 0x0047:
            current_module["name_unicode"] = r.bytes(r.u32())
        elif rid == 0x001A:
            # MS-OVBA 2.3.4.2.3.2.3: Nach dem MBCS-Namen folgen Reserved(2)
            # (per Spec 0x0032) und der UTF-16-Streamname — beides schreibt echtes Office.
            current_module["stream_name"] = r.bytes(r.u32())
            current_module["stream_name_reserved"] = r.u16()
            current_module["stream_name_unicode"] = r.bytes(r.u32())
        elif rid == 0x001C:
            r.skip(r.u32())
            r.u16()
            r.skip(r.u32())
        elif rid == 0x001E:
            r.skip(r.u32())
        elif rid == 0x002C:
            r.skip(r.u32())
        elif rid == 0x0031:
            r.u32()
            current_module["text_offset"] = r.u32()
        elif rid == 0x0025:
            current_module["readonly_reserved"] = r.u32()
            current_module["readonly"] = True
        elif rid == 0x0028:
            current_module["private_reserved"] = r.u32()
            current_module["private"] = True
        elif rid in (0x0021, 0x0022):
            current_module["type_reserved"] = r.u32()
            current_module["procedural"] = rid == 0x0021
        elif rid == 0x002B:
            current_module["terminator_reserved"] = r.u32()
            current_module = None
        elif rid == 0x004A:
            r.skip(r.u32())
        elif rid == 0x000F:
            r.skip(r.u32())
        elif rid == 0x0013:
            r.skip(r.u32())
        elif rid == 0x0010:
            d["terminator_reserved"] = r.u32() if r.remaining() >= 4 else 0
        else:
            raise ValueError(f"unknown dir record 0x{rid:04X} at {r.pos}")
    return d


# ---------------------------------------------------------------- MS-OVBA 2.4.2.5
def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def starts_with_ignore_case(line: bytes, prefix: bytes) -> bool:
    if len(line) < len(prefix):
        return False
    return line[: len(prefix)].lower() == prefix.lower()


def split_lines(text: bytes):
    # EPPlus-/Office-Semantik (MS Q&A 632599, gegen echte Office-Signaturen verifiziert):
    # Eine Zeile wird NUR angehaengt, wenn das aktuelle Zeichen 0x0A/0x0D ist und das
    # VORHERIGE 0x0D war (d.h. am LF eines CRLF-Paars). Der finale Rest-Puffer wird
    # UNBEDINGT verworfen — reine Attribut-Dokumentmodule tragen daher nichts bei.
    lines = []
    buf = bytearray()
    previous = 0
    for ch in text:
        if ch == 0x0A or ch == 0x0D:
            if previous == 0x0D:
                lines.append(bytes(buf))
                buf = bytearray()
        else:
            buf.append(ch)
        previous = ch
    return lines


def v3_content_normalized_data(d, ole) -> bytes:
    buf = bytearray()
    w = buf.extend

    w(u16(0x0001)); w(u32(d["syskind_size"]))
    w(u16(0x0002)); w(u32(4)); w(u32(d["lcid"]))
    w(u16(0x0014)); w(u32(4)); w(u32(d["lcid_invoke"]))
    w(u16(0x0003)); w(u32(2))
    w(u16(0x0004)); w(u32(len(d["project_name"]))); w(d["project_name"])
    w(u16(0x0005)); w(u32(d["docstring_size"])); w(u16(0x0040)); w(u32(d["docstring_unicode_size"]))
    w(u16(0x0006)); w(u32(d["helpfile1_size"])); w(u16(0x003D)); w(u32(d["helpfile2_size"]))
    w(u16(0x0007)); w(u32(d["helpcontext_size"]))
    w(u16(0x0008)); w(u32(4)); w(u32(d["libflags"]))
    w(u16(0x0009)); w(u32(d["version_reserved"])); w(u32(d["version_major"])); w(u16(d["version_minor"]))
    w(u16(0x000C)); w(u32(len(d["constants"]))); w(d["constants"])
    w(u16(0x003C)); w(u32(len(d["constants_unicode"]))); w(d["constants_unicode"])

    for ref in d["references"]:
        nr = ref["name_record"]
        w(u16(0x0016)); w(u32(nr["size_of_name"])); w(nr["name"]); w(u16(nr["reserved"]))
        w(u32(nr["size_of_name_unicode"])); w(nr["name_unicode"])
        rid = ref["record_id"]
        if rid == 0x002F:
            w(u16(0x002F)); w(u32(ref["control_size_of_libid_twiddled"])); w(ref["control_libid_twiddled"])
            w(u32(ref["control_reserved1"])); w(u16(ref["control_reserved2"]))
            if "control_name_extended" in ref:
                ne = ref["control_name_extended"]
                w(u16(0x0016)); w(u32(ne["size_of_name"])); w(ne["name"]); w(u16(ne["reserved"]))
                w(u32(ne["size_of_name_unicode"])); w(ne["name_unicode"])
            if ref["control_has_extended"]:
                w(u16(0x0030)); w(u32(ref["control_size_of_libid_extended"])); w(ref["control_libid_extended"])
                w(u32(ref["control_reserved4"])); w(u16(ref["control_reserved5"]))
                w(ref["control_original_typelib"]); w(u32(ref["control_cookie"]))
        elif rid == 0x0033:
            w(u16(0x0033)); w(u32(ref["original_size_of_libid"])); w(ref["original_libid"])
        elif rid == 0x000D:
            # Office-Abweichung von der Spec (MS Q&A 632599, EPPlus-Verhalten, an Golden
            # Files verifiziert): Die Libid wird als UTF-16 geschrieben, das Size-Feld
            # traegt die ZEICHENANZAHL (nicht die Byteanzahl). Control/Project-Libids
            # bleiben roh MBCS.
            libid_text = ref["registered_libid"].decode("cp%d" % d["code_page"])
            libid_wide = libid_text.encode("utf-16-le")
            w(u16(0x000D)); w(u32(len(libid_text))); w(libid_wide)
            w(u32(ref["registered_reserved1"])); w(u16(ref["registered_reserved2"]))
        elif rid == 0x000E:
            w(u16(0x000E)); w(u32(ref["project_size_abs"])); w(ref["project_libid_abs"])
            w(u32(ref["project_size_rel"])); w(ref["project_libid_rel"])
            w(u32(ref["project_major"])); w(u16(ref["project_minor"]))
        else:
            raise ValueError(f"unsupported reference record 0x{rid:04X}")

    w(u16(0x000F)); w(u32(2))
    w(u16(0x0013)); w(u32(2))

    for module in d["modules"]:
        if module.get("procedural"):
            w(u16(0x0021)); w(u32(module.get("type_reserved", 0)))
        if module.get("readonly"):
            w(u16(0x0025)); w(u32(module.get("readonly_reserved", 0)))
        if module.get("private"):
            w(u16(0x0028)); w(u32(module.get("private_reserved", 0)))

        stream = ole.openstream(("VBA", module["stream_name"].decode("cp1252"))).read()
        text = rle_decompress(stream[module["text_offset"]:])
        hash_module_name = False
        for line in split_lines(text):
            if not starts_with_ignore_case(line, b"attribute"):
                hash_module_name = True
                w(line); w(bytes([LF]))
            elif starts_with_ignore_case(line, b"Attribute VB_Name = "):
                continue
            elif line not in DEFAULT_ATTRIBUTES:
                hash_module_name = True
                w(line); w(bytes([LF]))
        if hash_module_name:
            if module.get("name_unicode"):
                w(module["name_unicode"])
            else:
                w(module["name"])
            w(bytes([LF]))

    w(u16(0x0010)); w(u32(d["terminator_reserved"]))
    return bytes(buf)


# ---------------------------------------------------------------- MS-OVBA 2.4.2.6 / 2.4.2.2
def list_direct_children(ole, prefix):
    """Direkte Kindelemente (Streams und Storages) eines Storage-Pfads in Verzeichnisreihenfolge."""
    prefix = tuple(prefix)
    seen = set()
    children = []
    for entry in ole.listdir(streams=True, storages=True):
        path = tuple(entry)
        if path[: len(prefix)] == prefix and len(path) == len(prefix) + 1 and path not in seen:
            seen.add(path)
            children.append(entry)
    return children


def normalize_storage(ole, prefix) -> bytes:
    out = bytearray()
    for entry in list_direct_children(ole, prefix):
        path = tuple(entry)
        if ole.get_type(path) == olefile.STGTY_STORAGE:
            out += normalize_storage(ole, path)
        else:
            data = ole.openstream(path).read()
            for offset in range(0, len(data), 1023):
                chunk = data[offset: offset + 1023]
                out += chunk
                out += bytes(1023 - len(chunk))
    return bytes(out)


def project_normalized_data(project_text: str, ole) -> bytes:
    buf = bytearray()
    w = buf.extend
    lines = project_text.replace("\r\n", "\n").replace("\n\r", "\n").split("\n")
    current_category = ""
    host_extenders = []
    saw_host_extender_section = False

    for raw_line in lines:
        line = raw_line
        if line.startswith("[") and line.endswith("]"):
            current_category = line[1:-1]
            if current_category == "Host Extender Info":
                saw_host_extender_section = True
            continue
        if current_category:
            if current_category == "Host Extender Info" and line:
                host_extenders.append(line)
            continue
        if not line or "=" not in line:
            continue
        name, _, value = line.partition("=")
        if name.lower() == "baseclass":
            w(normalize_storage(ole, (value,)))
        if name in EXCLUDED_PROPERTIES:
            continue
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        w(name.encode("cp1252"))
        w(value.encode("cp1252"))

    if saw_host_extender_section and host_extenders:
        w(b"Host Extender Info")
        for extender in host_extenders:
            w(extender.encode("cp1252"))
    return bytes(buf)


# ---------------------------------------------------------------- entry point
def extract_vba_project(document: bytes) -> bytes:
    if document[: 2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(document)) as package:
            name = next(n for n in package.namelist() if n.endswith("/vbaProject.bin"))
            return package.read(name)
    return document


def main() -> int:
    document = open(sys.argv[1], "rb").read()
    vba_project = extract_vba_project(document)
    ole = olefile.OleFileIO(io.BytesIO(vba_project))
    decompressed = rle_decompress(ole.openstream("VBA/dir").read())
    d = parse_dir(decompressed)

    content = v3_content_normalized_data(d, ole)
    project_text = ole.openstream("PROJECT").read().decode("cp1252")
    project = project_normalized_data(project_text, ole)

    digest = hashlib.sha256(content + project).hexdigest()
    print(f"v3-content-sha256: {digest}")
    print(f"transcript-length: {len(content) + len(project)} "
          f"(content={len(content)}, project={len(project)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
