#!/usr/bin/env python3
"""
extYuRis - An extraction and repacking tool for Yu-Ris Script Engine .ybn files.
Ported from Go (https://github.com/lunaswd/extYuRis) to Python.
"""

import argparse
import base64
import io
import json
import os
import re
import struct
import sys
import zlib

# =============================================================================
# Global Variables
# =============================================================================

g_is_output_opcode = False
g_verbose = False

# Codepage constants
CP_932 = 'cp932'
CP_936 = 'gbk'
CP_UTF8_SIG = 'utf-8-sig'
CP_UNKNOWN = 'utf-8'

# =============================================================================
# Utility Functions
# =============================================================================


def logf(fmt_str, *args):
    if g_verbose:
        if args:
            print(fmt_str % args, end='')
        else:
            print(fmt_str, end='')


def logln(*args):
    if g_verbose:
        print(*args)


def index_of(a, s):
    for k, i in enumerate(a):
        if i == s:
            return k
    return 0


def includes(a, v):
    return v in a


def decrypt_block(stm, key):
    """XOR decrypt/encrypt a block with a 4-byte key (in-place)."""
    if len(key) != 4:
        raise ValueError("key length error")
    for i in range(len(stm)):
        stm[i] ^= key[i & 3]


def decode_str(data, codepage):
    """Decode bytes to string using the given codepage."""
    if not data:
        return ""
    try:
        return data.decode(codepage, errors='replace')
    except Exception:
        return data.decode('utf-8', errors='replace')


def encode_str(s, codepage):
    """Encode string to bytes using the given codepage."""
    try:
        return s.encode(codepage, errors='replace')
    except Exception:
        return s.encode('utf-8', errors='replace')


def parse_codepage(s):
    if s == '936':
        return CP_936
    elif s == '932':
        return CP_932
    else:
        return CP_UNKNOWN


def read_ansi_str(reader, codepage):
    """Read a null-terminated ANSI string from a BinaryReader."""
    buf = bytearray()
    while reader.pos < len(reader.data):
        b = reader.data[reader.pos]
        reader.pos += 1
        if b == 0:
            break
        buf.append(b)
    if not buf:
        return ""
    return decode_str(bytes(buf), codepage)


def read_file_to_string(filename, codepage):
    """Read entire file and decode to string with specified codepage."""
    with open(filename, 'rb') as f:
        data = f.read()
    return decode_str(data, codepage)


def read_win32_txt_to_lines(filename):
    """Read a text file (possibly with BOM) and return lines."""
    with open(filename, 'rb') as f:
        raw = f.read()

    # Detect BOM
    if raw[:3] == b'\xef\xbb\xbf':
        text = raw[3:].decode('utf-8')
    elif raw[:2] == b'\xff\xfe':
        text = raw[2:].decode('utf-16-le')
    elif raw[:2] == b'\xfe\xff':
        text = raw[2:].decode('utf-16-be')
    else:
        text = raw.decode('utf-8')

    lines = text.replace('\r\n', '\n').split('\n')
    if lines and lines[-1] == '':
        lines = lines[:-1]
    return lines


def bytes_to_b64(b):
    """Convert bytes to base64 string (matches Go json.Marshal for []byte)."""
    if b:
        return base64.b64encode(b).decode('ascii')
    return None


def make_json_serializable(obj):
    """Recursively convert objects for JSON serialization, encoding bytes as base64."""
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('ascii')
    elif isinstance(obj, bytearray):
        return base64.b64encode(bytes(obj)).decode('ascii')
    elif isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()
                if v is not None}
    elif isinstance(obj, (list, tuple)):
        return [make_json_serializable(item) for item in obj]
    else:
        return obj


# =============================================================================
# Binary Reader Helper
# =============================================================================


class BinaryReader:
    """A simple binary reader that wraps a bytes/bytearray object."""

    def __init__(self, data):
        if isinstance(data, memoryview):
            self.data = bytes(data)
        elif isinstance(data, bytearray):
            self.data = bytes(data)
        else:
            self.data = data
        self.pos = 0

    def seek(self, pos, whence=0):
        if whence == 0:
            self.pos = pos
        elif whence == 1:
            self.pos += pos
        elif whence == 2:
            self.pos = len(self.data) + pos
        return self.pos

    def tell(self):
        return self.pos

    def read(self, n):
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u8(self):
        val = self.data[self.pos]
        self.pos += 1
        return val

    def read_u16(self):
        val = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return val

    def read_u32(self):
        val = struct.unpack_from('<I', self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_u64(self):
        val = struct.unpack_from('<Q', self.data, self.pos)[0]
        self.pos += 8
        return val

    def read_i64(self):
        val = struct.unpack_from('<q', self.data, self.pos)[0]
        self.pos += 8
        return val

    def read_f64(self):
        val = struct.unpack_from('<d', self.data, self.pos)[0]
        self.pos += 8
        return val

    def size(self):
        return len(self.data)


# =============================================================================
# YSCF Format (Project Configuration)
# =============================================================================

YSCF_HEADER_FMT = '<4sIIIIII8s4sIIIIIIIIIH'
YSCF_HEADER_SIZE = struct.calcsize(YSCF_HEADER_FMT)  # 78


def parse_yscf(ori_stm, codepage):
    """Parse YSCF binary data and return script info dict."""
    fields = struct.unpack_from(YSCF_HEADER_FMT, ori_stm, 0)
    header = {
        'magic': fields[0],
        'version': fields[1],
        'padding1': fields[2],
        'compile': fields[3],
        'screen_width': fields[4],
        'screen_height': fields[5],
        'enable': fields[6],
        'image_type_slots': fields[7],
        'sound_type_slots': fields[8],
        'thread': fields[9],
        'debug_mode': fields[10],
        'sound': fields[11],
        'window_resize': fields[12],
        'window_frame': fields[13],
        'fp_dev': fields[14],
        'fp_debug': fields[15],
        'fp_release': fields[16],
        'padding2': fields[17],
        'caption_length': fields[18],
    }
    logln("header:", header)
    if header['magic'] != b'YSCF':
        raise ValueError("not a ybn file")

    caption_bytes = ori_stm[YSCF_HEADER_SIZE:YSCF_HEADER_SIZE + header['caption_length']]
    caption = decode_str(caption_bytes, codepage)
    return {'header': header, 'caption': caption}


def parse_yscf_file(ori_stm, out_json_name, out_instruct_name, codepage):
    """Parse YSCF file and write to JSON and/or instruct format."""
    logln("parsing ybn...")
    try:
        script = parse_yscf(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    header = script['header']
    if out_json_name:
        logln("writing json...")
        json_data = {
            'Header': {
                'Meta': {'Magic': list(header['magic']), 'Version': header['version']},
                'Padding1': header['padding1'],
                'Compile': header['compile'],
                'ScreenWidth': header['screen_width'],
                'ScreenHeight': header['screen_height'],
                'Enable': header['enable'],
                'ImageTypeSlots': list(header['image_type_slots']),
                'SoundTypeSlots': list(header['sound_type_slots']),
                'Thread': header['thread'],
                'DebugMode': header['debug_mode'],
                'Sound': header['sound'],
                'WindowResize': header['window_resize'],
                'WindowFrame': header['window_frame'],
                'FilePriority': {
                    'Dev': header['fp_dev'],
                    'Debug': header['fp_debug'],
                    'Release': header['fp_release'],
                },
                'Padding2': header['padding2'],
                'CaptionLength': header['caption_length'],
            },
            'Caption': script['caption'],
        }
        out = json.dumps(json_data, indent='\t', ensure_ascii=False)
        with open(out_json_name, 'w', encoding='utf-8') as f:
            f.write(out)

    if out_instruct_name:
        logln("writing instructions...")
        img_slots = list(header['image_type_slots'])
        snd_slots = list(header['sound_type_slots'])
        out = ""
        out += "Version=%d\n" % header['version']
        out += "Compile=%d\n" % header['compile']
        out += "ScreenWidth=%d\n" % header['screen_width']
        out += "ScreenHeight=%d\n" % header['screen_height']
        out += "Enable=%d\n" % header['enable']
        out += "ImageTypeSlots=[%s]\n" % ' '.join(str(x) for x in img_slots)
        out += "SoundTypeSlots=[%s]\n" % ' '.join(str(x) for x in snd_slots)
        out += "Thread=%d\n" % header['thread']
        out += "DebugMode=%d\n" % header['debug_mode']
        out += "Sound=%d\n" % header['sound']
        out += "WindowResize=%d\n" % header['window_resize']
        out += "WindowFrame=%d\n" % header['window_frame']
        out += "FilePriorityDev=%d\n" % header['fp_dev']
        out += "FilePriorityDebug=%d\n" % header['fp_debug']
        out += "FilePriorityRelease=%d\n" % header['fp_release']
        out += "Caption=%s\n" % script['caption']
        out = out.rstrip('\n')
        with open(out_instruct_name, 'w', encoding='utf-8') as f:
            f.write(out)

    logln("complete.")
    return True


def pack_yscf_file(ori_stm, out_instruct_name, out_ybn_name, codepage):
    """Repack YSCF file from instruct file."""
    logln("parsing ybn...")
    try:
        script = parse_yscf(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    if out_instruct_name:
        logln("loading files...")
        txt = read_file_to_string(out_instruct_name, codepage)

        logln("encoding text and writing...")
        pattern = (
            r"(?:Version=([0-9]+)\n?)?"
            r"(?:Compile=([0-9]+)\n?)?"
            r"(?:ScreenWidth=([0-9]+)\n?)?"
            r"(?:ScreenHeight=([0-9]+)\n?)?"
            r"(?:Enable=([0-9]+)\n?)?"
            r"(?:ImageTypeSlots=\[((?:[0-9] ?)*)\]\n?)?"
            r"(?:SoundTypeSlots=\[((?:[0-9] ?)*)\]\n?)?"
            r"(?:Thread=([0-9]+)\n?)?"
            r"(?:DebugMode=([0-9]+)\n?)?"
            r"(?:Sound=([0-9]+)\n?)?"
            r"(?:WindowResize=([0-9]+)\n?)?"
            r"(?:WindowFrame=([0-9]+)\n?)?"
            r"(?:FilePriorityDev=([0-9]+)\n?)?"
            r"(?:FilePriorityDebug=([0-9]+)\n?)?"
            r"(?:FilePriorityRelease=([0-9]+)\n?)?"
            r"(?:Caption=(.+)\n?)?"
        )
        m = re.match(pattern, txt)
        if not m:
            print("Failed to parse instruct file")
            return False

        header = script['header']
        for i in range(1, 17):
            val = m.group(i)
            if not val:
                continue
            if i == 1:
                header['version'] = int(val)
            elif i == 2:
                header['compile'] = int(val)
            elif i == 3:
                header['screen_width'] = int(val)
            elif i == 4:
                header['screen_height'] = int(val)
            elif i == 5:
                header['enable'] = int(val)
            elif i == 6:
                parts = val.split(' ')
                img = bytearray(8)
                for j, s in enumerate(parts):
                    img[j] = int(s)
                header['image_type_slots'] = bytes(img)
            elif i == 7:
                parts = val.split(' ')
                snd = bytearray(4)
                for j, s in enumerate(parts):
                    snd[j] = int(s)
                header['sound_type_slots'] = bytes(snd)
            elif i == 8:
                header['thread'] = int(val)
            elif i == 9:
                header['debug_mode'] = int(val)
            elif i == 10:
                header['sound'] = int(val)
            elif i == 11:
                header['window_resize'] = int(val)
            elif i == 12:
                header['window_frame'] = int(val)
            elif i == 13:
                header['fp_dev'] = int(val)
            elif i == 14:
                header['fp_debug'] = int(val)
            elif i == 15:
                header['fp_release'] = int(val)
            elif i == 16:
                header['caption_length'] = len(val)
                script['caption'] = val

        buf = struct.pack(YSCF_HEADER_FMT,
                          header['magic'], header['version'],
                          header['padding1'], header['compile'],
                          header['screen_width'], header['screen_height'],
                          header['enable'], header['image_type_slots'],
                          header['sound_type_slots'], header['thread'],
                          header['debug_mode'], header['sound'],
                          header['window_resize'], header['window_frame'],
                          header['fp_dev'], header['fp_debug'],
                          header['fp_release'], header['padding2'],
                          header['caption_length'])
        buf += encode_str(script['caption'], codepage)
        with open(out_ybn_name, 'wb') as f:
            f.write(buf)

    logln("complete.")
    return True


# =============================================================================
# YSCM Format (Command Definitions)
# =============================================================================

YSCM_HEADER_FMT = '<4sIII'
YSCM_HEADER_SIZE = struct.calcsize(YSCM_HEADER_FMT)  # 16


def parse_yscm(ori_stm, codepage):
    """Parse YSCM binary data."""
    fields = struct.unpack_from(YSCM_HEADER_FMT, ori_stm, 0)
    header = {
        'magic': fields[0],
        'version': fields[1],
        'count': fields[2],
        'padding': fields[3],
    }
    logln("header:", header)
    if header['magic'] != b'YSCM':
        raise ValueError("not a ybn file")

    reader = BinaryReader(ori_stm)
    reader.seek(YSCM_HEADER_SIZE)

    commands = []
    for _ in range(header['count']):
        name = read_ansi_str(reader, codepage)
        action_count = reader.read_u8()
        actions = []
        for _ in range(action_count):
            act_name = read_ansi_str(reader, codepage)
            arg_type = reader.read_u8()
            arg_vaid = reader.read_u8()
            actions.append({
                'Name': act_name,
                'ArgType': arg_type,
                'ArgVaid': arg_vaid,
            })
        commands.append({'Name': name, 'Actions': actions})

    error_offset = reader.tell()
    error_messages = []
    for _ in range(37):
        error_messages.append(read_ansi_str(reader, codepage))

    unk = reader.read(256)

    return {
        'header': header,
        'commands': commands,
        'error_offset': error_offset,
        'error_messages': error_messages,
        'unk': unk,
    }


def parse_yscm_file(ori_stm, out_json_name, out_txt_name, out_instruct_name, codepage):
    """Parse YSCM file and write outputs."""
    logln("parsing ybn...")
    try:
        script = parse_yscm(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    if out_json_name:
        logln("writing json...")
        json_data = make_json_serializable({
            'Header': {
                'Meta': {'Magic': list(script['header']['magic']),
                         'Version': script['header']['version']},
                'Count': script['header']['count'],
                'Padding': script['header']['padding'],
            },
            'Commands': script['commands'],
            'ErrorOffset': script['error_offset'],
            'ErrorMessages': script['error_messages'],
            'Unk': script['unk'],
        })
        out = json.dumps(json_data, indent='\t', ensure_ascii=False)
        with open(out_json_name, 'w', encoding='utf-8') as f:
            f.write(out)

    if out_instruct_name:
        logln("writing instructions...")
        out = ""
        for cmd in script['commands']:
            out += cmd['Name'] + "("
            for act in cmd['Actions']:
                out += act['Name'] + "(" + str(act['ArgType']) + "," + str(act['ArgVaid']) + "),"
            out = out.rstrip(',')
            out += ")\n"
        out = out.rstrip('\n')
        with open(out_instruct_name, 'w', encoding='utf-8') as f:
            f.write(out)

    if out_txt_name:
        logln("extracting text from script...")
        txt = list(script['error_messages'])
        logln("encoding text and writing...")
        out = '\r\n'.join(txt).encode('utf-8-sig')
        with open(out_txt_name, 'wb') as f:
            f.write(out)

    logln("complete.")
    return True


def pack_yscm_file(ori_stm, out_txt_name, out_ybn_name, codepage):
    """Repack YSCM file from txt file."""
    logln("parsing ybn...")
    try:
        script = parse_yscm(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    if out_txt_name:
        logln("loading files...")
        ls = read_win32_txt_to_lines(out_txt_name)

        logln("encoding text and writing...")
        buf = bytearray()
        buf.extend(ori_stm[:script['error_offset']])
        for line in ls:
            buf.extend(encode_str(line, codepage))
            buf.append(0)
        buf.extend(script['unk'])
        with open(out_ybn_name, 'wb') as f:
            f.write(buf)

    logln("complete.")
    return True


# =============================================================================
# YSER Format (Error Messages)
# =============================================================================

YSER_HEADER_FMT = '<4sIII'
YSER_HEADER_SIZE = struct.calcsize(YSER_HEADER_FMT)  # 16


def parse_yser(ori_stm, codepage):
    """Parse YSER binary data."""
    fields = struct.unpack_from(YSER_HEADER_FMT, ori_stm, 0)
    header = {
        'magic': fields[0],
        'version': fields[1],
        'count': fields[2],
        'padding': fields[3],
    }
    logln("header:", header)
    if header['magic'] != b'YSER':
        raise ValueError("not a ybn file")

    reader = BinaryReader(ori_stm)
    reader.seek(YSER_HEADER_SIZE)

    error_messages = []
    for _ in range(header['count']):
        code = reader.read_u32()
        message = read_ansi_str(reader, codepage)
        error_messages.append({'Code': code, 'Message': message})

    return {'header': header, 'error_messages': error_messages}


def parse_yser_file(ori_stm, out_json_name, out_txt_name, codepage):
    """Parse YSER file and write outputs."""
    logln("parsing ybn...")
    try:
        script = parse_yser(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    if out_json_name:
        logln("writing json...")
        json_data = {
            'Header': {
                'Meta': {'Magic': list(script['header']['magic']),
                         'Version': script['header']['version']},
                'Count': script['header']['count'],
                'Padding': script['header']['padding'],
            },
            'ErrorMessages': script['error_messages'],
        }
        out = json.dumps(json_data, indent='\t', ensure_ascii=False)
        with open(out_json_name, 'w', encoding='utf-8') as f:
            f.write(out)

    if out_txt_name:
        logln("writing instructions...")
        out = ""
        for msg in script['error_messages']:
            out += '%d->"%s"\n' % (msg['Code'], msg['Message'])
        out = out.rstrip('\n')
        with open(out_txt_name, 'w', encoding='utf-8') as f:
            f.write(out)

    logln("complete.")
    return True


def pack_yser_file(ori_stm, out_txt_name, out_ybn_name, codepage):
    """Repack YSER file from txt file."""
    logln("parsing ybn...")
    try:
        script = parse_yser(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    if out_txt_name:
        logln("loading files...")
        txt = read_file_to_string(out_txt_name, codepage)

        logln("encoding text and writing...")
        buf = bytearray()
        buf.extend(ori_stm[:YSER_HEADER_SIZE])
        matches = re.findall(r'(?:^|\n)([0-9]+)->"([^"]+)"', txt)
        for match in matches:
            code = int(match[0])
            buf.extend(struct.pack('<I', code))
            buf.extend(encode_str(match[1], codepage))
            logln(code, match[1])
            buf.append(0)
        with open(out_ybn_name, 'wb') as f:
            f.write(buf)

    logln("complete.")
    return True


# =============================================================================
# YSLB Format (Labels)
# =============================================================================

YSLB_HEADER_FMT = '<4sII'
YSLB_HEADER_SIZE = struct.calcsize(YSLB_HEADER_FMT)  # 12


def parse_yslb(ori_stm, codepage):
    """Parse YSLB binary data."""
    fields = struct.unpack_from(YSLB_HEADER_FMT, ori_stm, 0)
    header = {
        'magic': fields[0],
        'version': fields[1],
        'count': fields[2],
    }
    logln("header:", header)
    if header['magic'] != b'YSLB':
        raise ValueError("not a ybn file")

    reader = BinaryReader(ori_stm)
    reader.seek(YSLB_HEADER_SIZE)

    # Read 256 uint32 label range start indexes
    label_range_start_indexes = struct.unpack_from('<256I', ori_stm, reader.tell())
    reader.seek(reader.tell() + 256 * 4)

    labels = []
    for _ in range(header['count']):
        name_length = reader.read_u8()
        encoded_name = reader.read(name_length)
        name = decode_str(encoded_name, codepage)
        label_id = reader.read_u32()
        command_index = reader.read_u32()
        script_id = reader.read_u16()
        padding = reader.read(2)
        labels.append({
            'EncodedName': encoded_name,
            'Name': name,
            'Id': label_id,
            'CommandIndex': command_index,
            'ScriptId': script_id,
            'Padding': padding,
        })

    return {
        'header': header,
        'label_range_start_indexes': list(label_range_start_indexes),
        'labels': labels,
    }


def parse_yslb_file(ori_stm, out_json_name, out_instruct_name, codepage):
    """Parse YSLB file and write outputs."""
    logln("parsing ybn...")
    try:
        script = parse_yslb(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    if out_json_name:
        logln("writing json...")
        json_data = make_json_serializable({
            'Header': {
                'Meta': {'Magic': list(script['header']['magic']),
                         'Version': script['header']['version']},
                'Count': script['header']['count'],
            },
            'labelRangeStartIndexes': script['label_range_start_indexes'],
            'Labels': script['labels'],
        })
        out = json.dumps(json_data, indent='\t', ensure_ascii=False)
        with open(out_json_name, 'w', encoding='utf-8') as f:
            f.write(out)

    if out_instruct_name:
        logln("writing instructions...")
        out = ""
        for label in script['labels']:
            out += '#="%s" =>yst%05d.ybn.instruct:%5d\n' % (
                label['Name'], label['ScriptId'], label['CommandIndex'])
        out = out.rstrip('\n')
        with open(out_instruct_name, 'w', encoding='utf-8') as f:
            f.write(out)

    logln("complete.")
    return True


# =============================================================================
# YSTB Format (Script Bytecode)
# =============================================================================

YSTB_HEADER_FMT = '<4sIIIIIII'
YSTB_HEADER_SIZE = struct.calcsize(YSTB_HEADER_FMT)  # 32

TEXT_FUNCTION_NAMES = [
    '"es.sel.set"',
    '"es.char.name.mark.set"',
    '"es.char.name"',
    '"es.input.str.set"',
    '"es.tips.def.set"',
    '"es.tips.tx.def.set"',
]


def is_long_english_sentence(s):
    """Check if data is a long English sentence (>5 spaces, all ASCII)."""
    space_count = 0
    for c in s:
        if c >= 0x80:
            return False
        elif c == ord(' '):
            space_count += 1
    return space_count > 5


def is_english_msg(arg):
    """Check if argument is an English message."""
    return (arg['value'] == 0 and arg['type'] == 3 and
            arg['res']['res'] and is_long_english_sentence(arg['res']['res']))


def is_jap_or_chn_msg(arg):
    """Check if argument is a Japanese or Chinese message."""
    return (arg['value'] == 0 and arg['type'] == 0 and
            arg['res']['res_raw'] and len(arg['res']['res_raw']) > 0 and
            arg['res']['res_raw'][0] > 0x80)


def is_function_to_extract(name):
    """Check if a function name should have its text extracted."""
    if not name:
        return False
    f = name.decode('ascii', errors='replace').lower() if isinstance(name, bytes) else name.lower()
    for v in TEXT_FUNCTION_NAMES:
        if v == f:
            return True
    return False


def decrypt_ystb(stm, key, header):
    """Decrypt all sections of a YSTB file in-place."""
    p = YSTB_HEADER_SIZE
    decrypt_block(stm[p:p + header['code_size']], key)
    p += header['code_size']
    decrypt_block(stm[p:p + header['arg_size']], key)
    p += header['arg_size']
    decrypt_block(stm[p:p + header['resource_size']], key)
    p += header['resource_size']
    decrypt_block(stm[p:p + header['off_size']], key)


def guess_ystb_op(script, ops):
    """Try to guess msg and call opcodes from script patterns."""
    msg_stat = [0] * 256
    call_stat = [0] * 256
    for inst in script['insts']:
        if 'msg' in ops and 'call' in ops:
            if g_is_output_opcode:
                print("msg\tcall")
                print("%d\t%d" % (index_of(ops, 'msg'), index_of(ops, 'call')))
            return True
        if 'msg' not in ops and len(inst['args']) == 1:
            if is_jap_or_chn_msg(inst['args'][0]) or is_english_msg(inst['args'][0]):
                msg_stat[inst['op']] += 1
                if msg_stat[inst['op']] > 10:
                    ops[inst['op']] = 'msg'
        if 'call' not in ops and len(inst['args']) >= 1:
            arg0 = inst['args'][0]
            if arg0['value'] == 0 and arg0['type'] == 3:
                res = arg0['res']
                if res['res']:
                    s = res['res']
                    if (res['type_'] == 0x4d and len(s) > 4 and
                            s[0:1] == b'"' and s[1:2] == b'e' and s[-1:] == b'"'):
                        call_stat[inst['op']] += 1
                        if call_stat[inst['op']] > 5:
                            ops[inst['op']] = 'call'
    return False


def parse_ystb(ori_stm, key, decrypt_name):
    """Parse YSTB binary data."""
    stm = bytearray(ori_stm)
    fields = struct.unpack_from(YSTB_HEADER_FMT, stm, 0)
    header = {
        'magic': fields[0],
        'version': fields[1],
        'inst_cnt': fields[2],
        'code_size': fields[3],
        'arg_size': fields[4],
        'resource_size': fields[5],
        'off_size': fields[6],
        'resv': fields[7],
    }
    logln("header:", header)

    if header['magic'] != b'YSTB' or header['code_size'] != header['inst_cnt'] * 4:
        raise ValueError("not a ybn file or file format error")

    file_size = len(stm)
    expected_size = YSTB_HEADER_SIZE + header['code_size'] + header['arg_size'] + \
                    header['resource_size'] + header['off_size']
    if expected_size != file_size:
        raise ValueError("file size error")

    if header['resv'] != 0:
        print("reserved is not 0, maybe can't extract all the info")

    # Decrypt
    if key != b'\x00\x00\x00\x00' and key != bytes(4):
        logf("decrypting, key is:0x%02X%02X%02X%02X\n", key[3], key[2], key[1], key[0])
        decrypt_ystb(stm, key, header)

    if decrypt_name:
        logln("write decrypted file...")
        with open(decrypt_name, 'wb') as f:
            f.write(stm)

    logln("reading sections...")
    reader = BinaryReader(bytes(stm))
    reader.seek(YSTB_HEADER_SIZE)

    # Read instructions
    raw_insts = []
    for _ in range(header['inst_cnt']):
        op = reader.read_u8()
        arg_cnt = reader.read_u8()
        label_id = reader.read_u16()
        raw_insts.append({'op': op, 'arg_cnt': arg_cnt, 'label_id': label_id})

    # Read arguments
    num_args = header['arg_size'] // 12
    rargs = []
    for _ in range(num_args):
        value = reader.read_u16()
        type_ = reader.read_u16()
        res_size = reader.read_u32()
        res_offset = reader.read_u32()
        rargs.append({'value': value, 'type': type_,
                      'res_size': res_size, 'res_offset': res_offset})

    res_start_off = reader.tell()

    # Parse instructions with resources
    logln("parsing instructions...")
    insts = []
    rarg_idx = 0
    for rinst in raw_insts:
        inst = {
            'op': rinst['op'],
            'label_id': rinst['label_id'],
            'args': [],
        }
        for _ in range(rinst['arg_cnt']):
            if rarg_idx >= len(rargs):
                raise ValueError("count of arguments exceed limit")
            rarg = rargs[rarg_idx]
            rarg_idx += 1

            arg = {
                'value': rarg['value'],
                'type': rarg['type'],
                'res': {'type_': 0, 'res': None, 'res_raw': None, 'res_str': None},
                'res_info': 0,
                'res_offset': 0,
            }

            if rarg['type'] == 0 and rinst['arg_cnt'] != 1:
                arg['res_info'] = rarg['res_size']
                arg['res_offset'] = rarg['res_offset']
            else:
                reader.seek(res_start_off + rarg['res_offset'])
                if rarg['type'] == 3:
                    # Type 3: ResInfo header + data
                    res_type = reader.read_u8()
                    res_len = reader.read_u16()
                    res_data = reader.read(res_len)
                    arg['res']['type_'] = res_type
                    arg['res']['res'] = res_data
                else:
                    if rarg['res_size'] > 3:
                        save_pos = reader.tell()
                        res_type = reader.read_u8()
                        res_len = reader.read_u16()
                        if res_len + 3 == rarg['res_size']:
                            res_data = reader.read(res_len)
                            arg['res']['type_'] = res_type
                            arg['res']['res'] = res_data
                        else:
                            reader.seek(save_pos)
                            arg['res']['res_raw'] = reader.read(rarg['res_size'])
                    else:
                        arg['res']['res_raw'] = reader.read(rarg['res_size'])

            inst['args'].append(arg)
        insts.append(inst)

    # Read offset table
    off_tbl_offset = YSTB_HEADER_SIZE + header['code_size'] + header['arg_size'] + header['resource_size']
    reader.seek(off_tbl_offset)
    offs = []
    for _ in range(header['inst_cnt']):
        offs.append(reader.read_u32())

    return {'header': header, 'insts': insts, 'offs': offs}


def decode_script_string(script, ops, codepage):
    """Decode string resources in the script for verbose JSON output."""
    for inst in script['insts']:
        for arg in inst['args']:
            res = arg['res']
            if res['res'] and res['type_'] == 77:
                res['res_str'] = decode_str(res['res'], codepage)
            elif ops[inst['op']] == 'msg' and res['res_raw']:
                res['res_str'] = decode_str(res['res_raw'], codepage)


def res_str(res, codepage):
    """Get string representation of a resource entry."""
    if res.get('res_str'):
        return res['res_str']
    elif res.get('res'):
        return decode_str(res['res'], codepage)
    elif res.get('res_raw'):
        return decode_str(res['res_raw'], codepage)
    return ""


def ext_txt_from_ybn(script, ops, codepage):
    """Extract translatable text from YSTB script."""
    txt = []
    for inst in script['insts']:
        if ops[inst['op']] == 'msg':
            if len(inst['args']) != 1:
                raise ValueError("the message op:0x%X has not only 1 argument" % inst['op'])
            arg = inst['args'][0]
            if arg['type'] == 3:
                raw_str = arg['res']['res']
            else:
                raw_str = arg['res']['res_raw']
            txt.append(decode_str(raw_str, codepage))
        elif ops[inst['op']] == 'call':
            if len(inst['args']) < 1:
                raise ValueError("call op:0x%X argument less than 1" % inst['op'])
            if is_function_to_extract(inst['args'][0]['res']['res']):
                for arg in inst['args'][1:]:
                    if (arg['type'] == 3 and
                            arg['res']['res'] != b'""' and
                            arg['res']['res'] != b"''"):
                        txt.append(decode_str(arg['res']['res'], codepage))
    return txt


def pack_line_to_ystb_resource(arg, line, codepage):
    """Encode a text line to YSTB resource format."""
    ns = encode_str(line, codepage)
    if arg['type'] == 3:
        buf = bytearray()
        buf.append(arg['res']['type_'])
        buf.extend(struct.pack('<H', len(ns)))
        buf.extend(ns)
        return bytes(buf)
    return ns


def pack_txt_to_ystb(script, stm, txt, ops, codepage, key):
    """Repack text into YSTB binary data."""
    header = script['header']
    arg_off_start = YSTB_HEADER_SIZE + header['code_size']
    arg_data = bytearray(stm[arg_off_start:arg_off_start + header['arg_size']])

    res_tail = bytearray()
    res_new_offset = header['resource_size']
    arg_idx = 0
    txt_idx = 0

    for inst in script['insts']:
        if ops[inst['op']] == 'msg':
            ns = pack_line_to_ystb_resource(inst['args'][0], txt[txt_idx], codepage)
            txt_idx += 1
            res_tail.extend(ns)
            offset = arg_idx * 12 + 4
            struct.pack_into('<I', arg_data, offset, len(ns))
            struct.pack_into('<I', arg_data, offset + 4, res_new_offset)
            res_new_offset += len(ns)
        elif ops[inst['op']] == 'call':
            if is_function_to_extract(inst['args'][0]['res']['res']):
                for i, arg in enumerate(inst['args'][1:]):
                    if (arg['type'] == 3 and
                            arg['res']['res'] != b'""' and
                            arg['res']['res'] != b"''"):
                        ns = pack_line_to_ystb_resource(arg, txt[txt_idx], codepage)
                        txt_idx += 1
                        res_tail.extend(ns)
                        offset = (arg_idx + 1 + i) * 12 + 4
                        struct.pack_into('<I', arg_data, offset, len(ns))
                        struct.pack_into('<I', arg_data, offset + 4, res_new_offset)
                        res_new_offset += len(ns)
        arg_idx += len(inst['args'])

    # Build new YBN
    new_resource_size = header['resource_size'] + len(res_tail)
    new_header = struct.pack(YSTB_HEADER_FMT,
                             header['magic'], header['version'],
                             header['inst_cnt'], header['code_size'],
                             header['arg_size'], new_resource_size,
                             header['off_size'], header['resv'])

    new_ybn = bytearray()
    new_ybn.extend(new_header)
    code_start = YSTB_HEADER_SIZE
    new_ybn.extend(stm[code_start:code_start + header['code_size']])
    new_ybn.extend(arg_data)
    res_start = arg_off_start + header['arg_size']
    new_ybn.extend(stm[res_start:res_start + header['resource_size']])
    new_ybn.extend(res_tail)
    off_start = res_start + header['resource_size']
    new_ybn.extend(stm[off_start:off_start + header['off_size']])

    # Re-encrypt if key is not zero
    if key != b'\x00\x00\x00\x00' and key != bytes(4):
        new_header_dict = dict(header)
        new_header_dict['resource_size'] = new_resource_size
        decrypt_ystb(new_ybn, key, new_header_dict)

    return bytes(new_ybn)


def parse_ystb_file(ori_stm, out_json_name, out_txt_name, out_decrypt_name,
                    out_instruct_name, key, ops, codepage):
    """Parse YSTB file and write outputs."""
    logln("parsing ybn...")
    try:
        script = parse_ystb(ori_stm, key, out_decrypt_name)
    except ValueError as e:
        print("parse error:", e)
        return False

    logln("guessing opcode if not provided...")
    if not guess_ystb_op(script, ops):
        print("Guess opcodes failed, msg op:0x%X, call op:0x%X" % (
            index_of(ops, 'msg'), index_of(ops, 'call')))

    if out_json_name:
        logln("writing json...")
        if g_verbose:
            logln("decode some string in json...")
            decode_script_string(script, ops, codepage)

        # Build JSON-serializable structure
        json_insts = []
        for inst in script['insts']:
            json_args = []
            for arg in inst['args']:
                json_arg = {
                    'Value': arg['value'],
                    'Type': arg['type'],
                    'Res': {},
                }
                res = arg['res']
                json_arg['Res']['Type'] = res['type_']
                if res['res']:
                    json_arg['Res']['Res'] = bytes_to_b64(res['res'])
                if res['res_raw']:
                    json_arg['Res']['ResRaw'] = bytes_to_b64(res['res_raw'])
                if res.get('res_str'):
                    json_arg['Res']['ResStr'] = res['res_str']
                if arg.get('res_info'):
                    json_arg['ResInfo'] = arg['res_info']
                if arg.get('res_offset'):
                    json_arg['ResOffset'] = arg['res_offset']
                json_args.append(json_arg)
            json_insts.append({
                'Op': inst['op'],
                'LabelId': inst['label_id'],
                'Args': json_args,
            })

        json_data = {
            'Header': {
                'Meta': {'Magic': list(script['header']['magic']),
                         'Version': script['header']['version']},
                'InstCnt': script['header']['inst_cnt'],
                'CodeSize': script['header']['code_size'],
                'ArgSize': script['header']['arg_size'],
                'ResourceSize': script['header']['resource_size'],
                'OffSize': script['header']['off_size'],
                'Resv': script['header']['resv'],
            },
            'Insts': json_insts,
            'Offs': script['offs'],
        }
        out = json.dumps(json_data, indent='\t', ensure_ascii=False)
        with open(out_json_name, 'w', encoding='utf-8') as f:
            f.write(out)

    if out_instruct_name:
        res_types = {77: 'str'}
        logln("writing instructions...")
        out = ""
        for inst in script['insts']:
            op = ops[inst['op']]
            if not op:
                op = str(inst['op'])

            if op == 'msg':
                out += res_str(inst['args'][0]['res'], codepage).replace('"', '') + "\n"
            elif op == 'msg-meta':
                out += "msg-data(" + str(inst['args'][0]['value'])
                if inst['args'][0]['res']['res_raw']:
                    out += ", " + base64.b64encode(inst['args'][0]['res']['res_raw']).decode('ascii')
                out += ")\n"
            elif op == 'call':
                out += "\\" + res_str(inst['args'][0]['res'], codepage).replace('"', '')
                out += "("
                for i in range(1, len(inst['args'])):
                    arg = inst['args'][i]
                    out += "%d: %d ->" % (arg['value'], arg['type'])
                    write_type = True
                    res_type_val = res_types.get(arg['res']['type_'])
                    if res_type_val is None:
                        res_type_val = str(arg['res']['type_'])
                    if res_type_val == 'str':
                        write_type = False
                        rs = res_str(arg['res'], codepage)
                        if rs != "''":
                            out += rs
                        else:
                            out += "null"
                    else:
                        if arg['res']['res_raw']:
                            out += base64.b64encode(arg['res']['res_raw']).decode('ascii')
                        elif arg['res']['res']:
                            out += base64.b64encode(arg['res']['res']).decode('ascii')
                        elif arg.get('res_offset') and arg.get('res_info'):
                            out += "res::(%s--%s)" % (arg['res_info'], arg['res_offset'])
                        else:
                            out += "~"
                    if write_type:
                        out += ":" + res_type_val
                    if i + 1 < len(inst['args']):
                        out += ", "
                out += ")\n"
            else:
                out += "\\" + op + "("
                for i in range(len(inst['args'])):
                    arg = inst['args'][i]
                    out += "%d: %d ->" % (arg['value'], arg['type'])
                    write_type = True
                    res_type_val = res_types.get(arg['res']['type_'])
                    if res_type_val is None:
                        res_type_val = str(arg['res']['type_'])
                    if res_type_val == 'str':
                        write_type = False
                        rs = res_str(arg['res'], codepage)
                        if rs != "''":
                            out += rs
                        else:
                            out += "null"
                    else:
                        if arg['res']['res_raw']:
                            out += base64.b64encode(arg['res']['res_raw']).decode('ascii')
                        elif arg['res']['res']:
                            out += base64.b64encode(arg['res']['res']).decode('ascii')
                        elif arg.get('res_offset') and arg.get('res_info'):
                            out += "res::(%s--%s)" % (arg['res_info'], arg['res_offset'])
                        else:
                            out += "~"
                    if write_type:
                        out += ":" + res_type_val
                    if i + 1 < len(inst['args']):
                        out += ", "
                out += ")\n"

        with open(out_instruct_name, 'w', encoding='utf-8') as f:
            f.write(out)

    if out_txt_name:
        logln("extracting text from script...")
        try:
            txt = ext_txt_from_ybn(script, ops, codepage)
        except ValueError as e:
            print("error when extracting txt:", e)
            return False
        if txt:
            logln("encoding text and writing...")
            out = '\r\n'.join(txt).encode('utf-8-sig')
            with open(out_txt_name, 'wb') as f:
                f.write(out)
        else:
            logln("no extracted text...")

    logln("complete.")
    return True


def pack_ystb_file(ori_stm, txt_name, out_ybn_name, key, ops, codepage):
    """Repack YSTB file from txt file."""
    logln("parsing ybn...")
    try:
        script = parse_ystb(ori_stm, key, "")
    except ValueError as e:
        print("parse error:", e)
        return False

    logln("guessing opcode if not provided...")
    if not guess_ystb_op(script, ops):
        print("Can't guess the opcode")
        return False

    logln("reading text:", txt_name)
    ls = read_win32_txt_to_lines(txt_name)
    logf("reading text finished, %d lines\n", len(ls))

    logln("packing text to ybn...")
    try:
        new_stm = pack_txt_to_ystb(script, ori_stm, ls, ops, codepage, key)
    except Exception as e:
        print(e)
        return False

    logln("writing ybn:", out_ybn_name)
    with open(out_ybn_name, 'wb') as f:
        f.write(new_stm)

    logln("complete.")
    return True


# =============================================================================
# YSTD Format (Script Data Definitions)
# =============================================================================

YSTD_HEADER_FMT = '<4sIII'
YSTD_HEADER_SIZE = struct.calcsize(YSTD_HEADER_FMT)  # 16


def parse_ystd(ori_stm, codepage):
    """Parse YSTD binary data."""
    fields = struct.unpack_from(YSTD_HEADER_FMT, ori_stm, 0)
    header = {
        'magic': fields[0],
        'version': fields[1],
        'var_count': fields[2],
        'text_count': fields[3],
    }
    logln("header:", header)
    if header['magic'] != b'YSTD':
        raise ValueError("not a ybn file")
    return {'header': header}


def parse_ystd_file(ori_stm, out_json_name, out_instruct_name, codepage):
    """Parse YSTD file and write outputs."""
    logln("parsing ybn...")
    try:
        script = parse_ystd(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    if out_json_name:
        logln("writing json...")
        json_data = {
            'Header': {
                'Meta': {'Magic': list(script['header']['magic']),
                         'Version': script['header']['version']},
                'VarCount': script['header']['var_count'],
                'TextCount': script['header']['text_count'],
            },
        }
        out = json.dumps(json_data, indent='\t', ensure_ascii=False)
        with open(out_json_name, 'w', encoding='utf-8') as f:
            f.write(out)

    if out_instruct_name:
        logln("writing instructions...")
        out = "YSTD v%d\n%d\n%d" % (
            script['header']['version'],
            script['header']['var_count'],
            script['header']['text_count'])
        with open(out_instruct_name, 'w', encoding='utf-8') as f:
            f.write(out)

    logln("complete.")
    return True


# =============================================================================
# YSTL Format (Script List)
# =============================================================================

YSTL_HEADER_FMT = '<4sII'
YSTL_HEADER_SIZE = struct.calcsize(YSTL_HEADER_FMT)  # 12


def parse_ystl(ori_stm, codepage):
    """Parse YSTL binary data."""
    fields = struct.unpack_from(YSTL_HEADER_FMT, ori_stm, 0)
    header = {
        'magic': fields[0],
        'version': fields[1],
        'count': fields[2],
    }
    logln("header:", header)
    if header['magic'] != b'YSTL':
        raise ValueError("not a ybn file")

    reader = BinaryReader(ori_stm)
    reader.seek(YSTL_HEADER_SIZE)

    scripts = []
    for _ in range(header['count']):
        scr_id = reader.read_u32()
        source_length = reader.read_u32()
        encoded_name = reader.read(source_length)
        source = decode_str(encoded_name, codepage)
        mod_time = reader.read_u64()
        var_count = reader.read_u32()
        lbl_count = reader.read_u32()
        txt_count = reader.read_u32()
        scripts.append({
            'Id': scr_id,
            'SourceLength': source_length,
            'Source': source,
            'ModificationTime': mod_time,
            'VarCount': var_count,
            'LblCount': lbl_count,
            'TxtCount': txt_count,
        })

    return {'header': header, 'scripts': scripts}


def parse_ystl_file(ori_stm, out_json_name, out_instruct_name, codepage):
    """Parse YSTL file and write outputs."""
    logln("parsing ybn...")
    try:
        script = parse_ystl(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    if out_json_name:
        logln("writing json...")
        json_data = {
            'Header': {
                'Meta': {'Magic': list(script['header']['magic']),
                         'Version': script['header']['version']},
                'Count': script['header']['count'],
            },
            'Scripts': script['scripts'],
        }
        out = json.dumps(json_data, indent='\t', ensure_ascii=False)
        with open(out_json_name, 'w', encoding='utf-8') as f:
            f.write(out)

    if out_instruct_name:
        logln("writing instructions...")
        out = ""
        for scr in script['scripts']:
            out += "yst%05d.ybn => %s  (%d,%d,%d,%d)\n" % (
                scr['Id'], scr['Source'], scr['ModificationTime'],
                scr['VarCount'], scr['LblCount'], scr['TxtCount'])
        out = out.rstrip('\n')
        with open(out_instruct_name, 'w', encoding='utf-8') as f:
            f.write(out)

    logln("complete.")
    return True


# =============================================================================
# YSVR Format (Script Variables)
# =============================================================================

YSVR_HEADER_FMT = '<4sIH'
YSVR_HEADER_SIZE = struct.calcsize(YSVR_HEADER_FMT)  # 10

YSVR_VAR_HEADER_FMT = '<BHHBB'
YSVR_VAR_HEADER_SIZE = struct.calcsize(YSVR_VAR_HEADER_FMT)  # 7


def parse_ysvr(ori_stm, codepage):
    """Parse YSVR binary data."""
    fields = struct.unpack_from(YSVR_HEADER_FMT, ori_stm, 0)
    header = {
        'magic': fields[0],
        'version': fields[1],
        'count': fields[2],
    }
    logln("header:", header)
    if header['magic'] != b'YSVR':
        raise ValueError("not a ybn file")

    reader = BinaryReader(ori_stm)
    reader.seek(YSVR_HEADER_SIZE)

    data = []
    for _ in range(header['count']):
        var_fields = struct.unpack_from(YSVR_VAR_HEADER_FMT, reader.data, reader.pos)
        reader.pos += YSVR_VAR_HEADER_SIZE
        var_header = {
            'Scope': var_fields[0],
            'ScriptId': var_fields[1],
            'VarIndex': var_fields[2],
            'Type': var_fields[3],
            'DimCount': var_fields[4],
        }

        dim_size = []
        for _ in range(var_header['DimCount']):
            dim_size.append(reader.read_u32())

        var_data = None
        if var_header['Type'] == 0:
            pass
        elif var_header['Type'] == 1:
            var_data = reader.read_i64()
        elif var_header['Type'] == 2:
            var_data = reader.read_f64()
        elif var_header['Type'] == 3:
            str_len = reader.read_u16()
            b = reader.read(str_len)
            var_data = decode_str(b, codepage)

        data.append({
            'Header': var_header,
            'DimSize': dim_size,
            'Data': var_data,
        })

    return {'header': header, 'data': data}


def parse_ysvr_file(ori_stm, out_json_name, codepage):
    """Parse YSVR file and write outputs."""
    logln("parsing ybn...")
    try:
        script = parse_ysvr(ori_stm, codepage)
    except ValueError as e:
        print("parse error:", e)
        return False

    if out_json_name:
        logln("writing json...")
        json_data = {
            'Header': {
                'Meta': {'Magic': list(script['header']['magic']),
                         'Version': script['header']['version']},
                'Count': script['header']['count'],
            },
            'Data': script['data'],
        }
        out = json.dumps(json_data, indent='\t', ensure_ascii=False)
        with open(out_json_name, 'w', encoding='utf-8') as f:
            f.write(out)

    logln("complete.")
    return True


# =============================================================================
# YPF Format (Archive)
# =============================================================================

YPF_HEADER_FMT = '<4sIII16s'
YPF_HEADER_SIZE = struct.calcsize(YPF_HEADER_FMT)  # 32


def murmur_hash2(data, seed=0):
    """MurmurHash2 implementation matching the Go aviddiviner/go-murmur library."""
    m = 0x5BD1E995
    r = 24
    length = len(data)
    h = (seed ^ length) & 0xFFFFFFFF

    i = 0
    while length >= 4:
        k = struct.unpack_from('<I', data, i)[0]
        k = (k * m) & 0xFFFFFFFF
        k ^= (k >> r)
        k = (k * m) & 0xFFFFFFFF
        h = (h * m) & 0xFFFFFFFF
        h ^= k
        i += 4
        length -= 4

    if length >= 3:
        h ^= (data[i + 2] << 16) & 0xFFFFFFFF
    if length >= 2:
        h ^= (data[i + 1] << 8) & 0xFFFFFFFF
    if length >= 1:
        h ^= data[i]
        h = (h * m) & 0xFFFFFFFF

    h ^= (h >> 13)
    h = (h * m) & 0xFFFFFFFF
    h ^= (h >> 15)

    return h


def get_length_swapping_table(version):
    """Get the filename length swapping table for the YPF version."""
    if version >= 500:
        return [0, 1, 2, 10, 4, 5, 53, 7, 8, 11, 3, 9, 16, 19, 14, 15, 12, 24, 18, 13, 46, 27, 22, 23, 17, 25, 26, 21, 30, 29, 28, 31, 35, 33, 34, 32, 36, 37, 41, 39, 40, 38, 42, 43, 47, 45, 20, 44, 48, 49, 50, 51, 52, 6, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]
    return [0, 1, 2, 72, 4, 5, 53, 7, 8, 11, 10, 9, 16, 19, 14, 15, 12, 25, 18, 13, 20, 27, 22, 23, 24, 17, 26, 21, 30, 29, 28, 31, 35, 33, 34, 32, 36, 37, 41, 39, 40, 38, 42, 43, 47, 45, 50, 44, 48, 49, 46, 51, 52, 6, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 3, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]


def get_filename_encryption_key(version):
    """Get the filename encryption key for the YPF version."""
    if version == 290:
        return 64
    if version > 500:
        return 54
    return 0


def checksum_by_version(data, version, is_name):
    """Calculate checksum based on YPF version."""
    if version < 479:
        if is_name:
            return zlib.crc32(data) & 0xFFFFFFFF
        else:
            return zlib.adler32(data) & 0xFFFFFFFF
    else:
        return murmur_hash2(data, 0)


def parse_ypf(ori_stm, codepage):
    """Parse YPF archive header and file entries."""
    fields = struct.unpack_from(YPF_HEADER_FMT, ori_stm, 0)
    header = {
        'magic': fields[0],
        'version': fields[1],
        'file_count': fields[2],
        'archived_files_header_size': fields[3],
        'unk': fields[4],
    }
    logln("header:", header)
    if header['magic'] != b'YPF\x00':
        raise ValueError("not a ypf file")

    reader = BinaryReader(ori_stm)
    reader.seek(YPF_HEADER_SIZE)

    length_swapping_table = get_length_swapping_table(header['version'])
    filename_encryption_key = get_filename_encryption_key(header['version'])

    entries = []
    for _ in range(header['file_count']):
        name_checksum = reader.read_u32()
        b = reader.read_u8()
        b = (~b) & 0xFF
        b2 = length_swapping_table[b]
        array = bytearray(reader.read(b2))
        for j in range(b2):
            array[j] = ((~array[j]) & 0xFF) ^ filename_encryption_key
        filename = decode_str(bytes(array), codepage)

        if name_checksum != checksum_by_version(bytes(array), header['version'], True):
            raise ValueError("name check failed for %s" % filename)

        file_type = reader.read_u8()
        is_compressed = reader.read_u8()
        raw_file_size = reader.read_u32()
        compressed_file_size = reader.read_u32()
        if header['version'] < 479:
            offset = reader.read_u32()
        else:
            offset = reader.read_u64()
        data_checksum = reader.read_u32()

        entries.append({
            'name_checksum': name_checksum,
            'filename': filename,
            'type': file_type,
            'is_compressed': is_compressed,
            'raw_file_size': raw_file_size,
            'compressed_file_size': compressed_file_size,
            'offset': offset,
            'data_checksum': data_checksum,
        })

    entries.sort(key=lambda e: e['offset'])
    return {'header': header, 'entries': entries}


def extract_file_from_ypf(ori_stm, entry, version):
    """Extract a single file from a YPF archive."""
    offset = entry['offset']
    size = entry['compressed_file_size']
    data = ori_stm[offset:offset + size]

    if entry['data_checksum'] != checksum_by_version(data, version, False):
        raise ValueError("data check failed for %s" % entry['filename'])

    if entry['is_compressed'] != 1:
        return data

    # Decompress
    return zlib.decompress(data)


def extract_ypf(ori_stm, output_dir, codepage):
    """Extract all files from a YPF archive."""
    try:
        ypf = parse_ypf(ori_stm, codepage)
    except ValueError:
        return False

    for entry in ypf['entries']:
        try:
            file_bytes = extract_file_from_ypf(ori_stm, entry, ypf['header']['version'])
        except ValueError:
            return False
        out_path = os.path.join(output_dir, entry['filename'])
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(file_bytes)

    return True


def index_of_byte(arr, candidate):
    """Find the index of a byte value in an array."""
    for i, c in enumerate(arr):
        if c == candidate:
            return i
    return 0


def pack_ypf(output_ypf, input_dir, version, codepage):
    """Pack files from a directory into a YPF archive."""
    input_abs = os.path.abspath(input_dir)
    files = []
    for root, _, filenames in os.walk(input_abs):
        for fn in filenames:
            full_path = os.path.join(root, fn)
            rel_path = os.path.relpath(full_path, input_abs)
            files.append(rel_path)

    header = {
        'version': version,
        'file_count': len(files),
        'archived_files_header_size': 32,
    }

    type_map = {
        'txt': 0, 'bmp': 1, 'png': 2, 'jpg': 3, 'gif': 4,
        'wav': 5, 'ogg': 6, 'psd': 7, 'ycg': 8, 'psb': 9,
    }

    entries = []
    for file in files:
        entry = {'filename': file}
        file_ext = os.path.splitext(file)[1].lstrip('.')
        if file_ext == 'ycg':
            entry['filename'] = file[:-4]
        if not entry['filename']:
            print("Filename can't be empty")
            return False

        for e in entries:
            if e['filename'] == entry['filename']:
                print("Filenames can't be duplicates")
                return False

        encoded_name = entry['filename'].encode(codepage, errors='replace')
        entry['name_checksum'] = checksum_by_version(encoded_name, version, True)
        entry['type'] = type_map.get(file_ext, 0)
        header['archived_files_header_size'] += 23 + len(encoded_name)
        if version >= 479:
            header['archived_files_header_size'] += 4
        entries.append(entry)

    entries.sort(key=lambda e: e['name_checksum'])

    out_buf = bytearray()
    for entry in entries:
        print("Adding %s" % entry['filename'])
        file_path = os.path.join(input_dir, entry['filename'])
        if entry['type'] == type_map.get('ycg', 8):
            file_path += '.ycg'
        with open(file_path, 'rb') as f:
            file_bytes = f.read()

        if len(file_bytes) > 0xFFFFFFFF:
            print("File too large")
            return False
        if len(file_bytes) == 0:
            print("File empty")
            return False

        entry['offset'] = len(out_buf) + header['archived_files_header_size']
        entry['raw_file_size'] = len(file_bytes)

        compressed = zlib.compress(file_bytes)

        if len(compressed) < len(file_bytes):
            entry['data_checksum'] = checksum_by_version(compressed, version, False)
            # Check for duplicates
            found_dup = False
            for e in entries:
                if (e.get('data_checksum') == entry['data_checksum'] and
                        e.get('raw_file_size') == entry['raw_file_size'] and
                        e is not entry):
                    entry['offset'] = e['offset']
                    found_dup = True
                    break
            if not found_dup:
                out_buf.extend(compressed)
            entry['compressed_file_size'] = len(compressed)
            entry['is_compressed'] = 1
        else:
            entry['data_checksum'] = checksum_by_version(file_bytes, version, False)
            found_dup = False
            for e in entries:
                if (e.get('data_checksum') == entry['data_checksum'] and
                        e.get('raw_file_size') == entry['raw_file_size'] and
                        e is not entry):
                    entry['offset'] = e['offset']
                    found_dup = True
                    break
            if not found_dup:
                out_buf.extend(file_bytes)
            entry['compressed_file_size'] = entry['raw_file_size']
            entry['is_compressed'] = 0

        if version < 479 and len(out_buf) > 0xFFFFFFFF:
            print("Output file too long")
            return False

    # Build the full output
    full_buf = bytearray()
    full_buf.extend(struct.pack(YPF_HEADER_FMT,
                                b'YPF\x00', version, len(entries),
                                header['archived_files_header_size'],
                                b'\x00' * 16))

    for entry in entries:
        full_buf.extend(struct.pack('<I', entry['name_checksum']))
        encoded_name = entry['filename'].encode(codepage, errors='replace')
        if len(encoded_name) > 0xFF:
            print("Filename can only be one byte")
            return False
        length_encoded = index_of_byte(
            get_length_swapping_table(version), len(encoded_name))
        full_buf.append((~length_encoded) & 0xFF)
        enc_name = bytearray(encoded_name)
        key = get_filename_encryption_key(version)
        for i in range(len(enc_name)):
            enc_name[i] = (~(enc_name[i] ^ key)) & 0xFF
        full_buf.extend(enc_name)
        full_buf.append(entry['type'])
        full_buf.append(entry.get('is_compressed', 0))
        full_buf.extend(struct.pack('<I', entry.get('raw_file_size', 0)))
        full_buf.extend(struct.pack('<I', entry.get('compressed_file_size', 0)))
        if version < 479:
            full_buf.extend(struct.pack('<I', entry.get('offset', 0)))
        else:
            full_buf.extend(struct.pack('<Q', entry.get('offset', 0)))
        full_buf.extend(struct.pack('<I', entry.get('data_checksum', 0)))

    if len(full_buf) != header['archived_files_header_size']:
        print("Oversized Header")
        return False

    full_buf.extend(out_buf)
    with open(output_ypf, 'wb') as f:
        f.write(full_buf)

    return True


# =============================================================================
# Main Dispatch Functions
# =============================================================================


def extract_ybn_file(ybn_name, out_json_name, out_txt_name, out_instruct_name,
                     out_decrypt_name, key, guess_key, ops, codepage):
    """Extract a YBN file based on its magic bytes."""
    logln("reading file:", ybn_name)
    try:
        with open(ybn_name, 'rb') as f:
            ori_stm = f.read()
    except IOError as e:
        print(e)
        return False

    if len(ori_stm) < 4:
        print("File too small")
        return False

    magic = ori_stm[:4].upper()

    if magic == b'YSTB':
        # Parse header to get code_size for key guessing
        if guess_key:
            fields = struct.unpack_from(YSTB_HEADER_FMT, ori_stm, 0)
            code_size = fields[3]
            idx = YSTB_HEADER_SIZE + code_size - 4
            guessed_key = bytearray(ori_stm[idx:idx + 4])
            decrypt_block(guessed_key, bytearray([12, 0, 0, 0]))
            return parse_ystb_file(ori_stm, out_json_name, out_txt_name,
                                   out_decrypt_name, out_instruct_name,
                                   bytes(guessed_key), ops, codepage)
        return parse_ystb_file(ori_stm, out_json_name, out_txt_name,
                               out_decrypt_name, out_instruct_name,
                               key, ops, codepage)
    elif magic == b'YSLB':
        return parse_yslb_file(ori_stm, out_json_name, out_instruct_name, codepage)
    elif magic == b'YSCF':
        return parse_yscf_file(ori_stm, out_json_name, out_instruct_name, codepage)
    elif magic == b'YSCM':
        return parse_yscm_file(ori_stm, out_json_name, out_txt_name, out_instruct_name, codepage)
    elif magic == b'YSER':
        return parse_yser_file(ori_stm, out_json_name, out_txt_name, codepage)
    elif magic == b'YSTD':
        return parse_ystd_file(ori_stm, out_json_name, out_instruct_name, codepage)
    elif magic == b'YSTL':
        return parse_ystl_file(ori_stm, out_json_name, out_instruct_name, codepage)
    elif magic == b'YSVR':
        return parse_ysvr_file(ori_stm, out_json_name, codepage)
    else:
        print("Unknown MAGIC-bytes")
        return False


def pack_ybn_file(ybn_name, out_txt_name, out_instruct_name, out_ybn_name,
                  key, ops, codepage):
    """Pack/repack a YBN file based on its magic bytes."""
    logln("reading file:", ybn_name)
    try:
        with open(ybn_name, 'rb') as f:
            ori_stm = f.read()
    except IOError as e:
        print(e)
        return False

    if len(ori_stm) < 4:
        print("File too small")
        return False

    magic = ori_stm[:4].upper()

    if magic == b'YSTB':
        return pack_ystb_file(ori_stm, out_txt_name, out_ybn_name, key, ops, codepage)
    elif magic == b'YSCF':
        return pack_yscf_file(ori_stm, out_instruct_name, out_ybn_name, codepage)
    elif magic == b'YSCM':
        return pack_yscm_file(ori_stm, out_txt_name, out_ybn_name, codepage)
    elif magic == b'YSER':
        return pack_yser_file(ori_stm, out_txt_name, out_ybn_name, codepage)
    else:
        print("Unknown MAGIC-bytes or packing not supported")
        return False


# =============================================================================
# CLI Entry Point
# =============================================================================


def parse_cmd_ops(cds):
    """Parse opcode specifications like '90:msg,29:call'."""
    ops = [''] * 256
    parts = cds.split(',')
    for part in parts:
        spl = part.split(':')
        if len(spl) != 2:
            raise ValueError("malformatted Op-Codes")
        opcode = int(spl[0])
        if opcode > 255:
            raise ValueError("malformatted Op-Codes")
        ops[opcode] = spl[1]
    return ops


def print_usage():
    exe_name = os.path.basename(sys.argv[0])
    print("YBN extractor v3.0 (Python)")
    print("Usage: %s -e -input <ybn> [-json <json>] [-txt <txt>] [options]" % exe_name)
    print("Usage: %s -p -input <ybn> -txt <txt> -new-ybn <new_ybn> [options]" % exe_name)
    print("""
About the extraction to different formats:
  Repacking is only possible from a txt file generated from a ystXXXXX.ybn,
  ysc.ybn or yse.ybn file and from an instruct file generated from yscfg.ybn.
  Some ybn variants may only support specific file formats:
      YSCF: json,\tinstruct
      YSCM:\tjson,\tinstruct,\ttxt
      YSER:\tjson,\t\t\ttxt
      YSLB:\tjson,\tinstruct,\ttxt
      YSTB:\tjson,\tinstruct,\ttxt,\tdecrypt
      YSTD:\tjson,\tinstruct
      YSTL:\tjson,\tinstruct
      YSVR:\tjson

  Different formats may contain different data depending on the variant.
  Which formats are supported is decided based on usefulness. In
  General one can say that (1) json files should contain as much as
  possible (if possible 1:1 binary reconstruction), (2) instruct files
  should aim to imitate source code files, (3) txt files should be used for
  translation purposes and therefore only contain strings and (4) decrypt
  files should be exactly only the original files without encryption.


About the key:
  The files use a 4-byte key XOR-Cipher. The Program can try to break it based
  on assumptions about the content. This should work with any standard
  compiled scripts. If it fails, try to use the default key or use these:
  0x6cfddadb or 0x30731B78. The Program may CRASH or PANIC if not given the
  correct key. If nothing works, try https://wiremask.eu/tools/xor-cracker/

About the opcode:
  This program can guess the opcode-msg and opcode-call which is needed, but
  you need to give it a .ybn which has some msg texts to do it. Generally, you
  can give it yst0XXXX.ybn where the XXXX is the maximum number among all the
  ybn file names.
  You can use:

  %s -e -input yst0XXXX.ybn -output-opcode

  to output the opcodes, and then use them in all the .ybn files of this game.
  You can also Specify other Op-Codes to translate them in instruct files.
""" % exe_name)


def main():
    global g_is_output_opcode, g_verbose

    parser = argparse.ArgumentParser(
        description='YBN extractor v3.0 (Python) - Extract/pack Yu-Ris Script Engine .ybn files',
        add_help=True)

    parser.add_argument('-e', action='store_true', help='extract a file')
    parser.add_argument('-p', action='store_true', help='pack a ybn')
    parser.add_argument('-input', dest='input_file', default='',
                        help='input ybn file or directory name')
    parser.add_argument('-json', dest='json_file', default='',
                        help='output json file name')
    parser.add_argument('-instruct', dest='instruct_file', default='',
                        help='output instruct file name')
    parser.add_argument('-txt', dest='txt_file', default='',
                        help='output txt file name')
    parser.add_argument('-decrypt', dest='decrypt_file', default='',
                        help='output decrypted file name')
    parser.add_argument('-new-ybn', dest='new_ybn', default='',
                        help='output ybn file name')
    parser.add_argument('-key', type=lambda x: int(x, 0), default=0x96ac6fd3,
                        help='decode key (default: 0x96ac6fd3)')
    parser.add_argument('-guess-key', action='store_true',
                        help='try to guess the encryption key')
    parser.add_argument('-cp', default='932',
                        help='specify code page (default: 932)')
    parser.add_argument('-output-opcode', action='store_true',
                        help='output the opcode guessed')
    parser.add_argument('-ops', default='',
                        help='specify op-code names like 90:msg,29:call')
    parser.add_argument('-v', action='store_true', help='verbose output')

    args = parser.parse_args()

    # Convert key integer to 4-byte little-endian array
    key_int = args.key & 0xFFFFFFFF
    key = bytes([
        key_int & 0xFF,
        (key_int >> 8) & 0xFF,
        (key_int >> 16) & 0xFF,
        (key_int >> 24) & 0xFF,
    ])

    ops = [''] * 256
    if args.ops:
        try:
            ops = parse_cmd_ops(args.ops)
        except ValueError:
            print_usage()
            return

    g_is_output_opcode = args.output_opcode
    g_verbose = args.v

    is_extract = args.e
    is_pack = args.p
    input_name = args.input_file

    if (is_extract and is_pack) or (not is_extract and not is_pack):
        print_usage()
        return

    if (is_pack or is_extract) and not input_name:
        print_usage()
        return

    if is_pack and (not args.new_ybn or (not args.txt_file and not args.instruct_file)):
        print_usage()
        return

    codepage = parse_codepage(args.cp)

    if is_extract:
        extract_ybn_file(input_name, args.json_file, args.txt_file,
                         args.instruct_file, args.decrypt_file,
                         key, args.guess_key, ops, codepage)
    elif is_pack:
        pack_ybn_file(input_name, args.txt_file, args.instruct_file,
                      args.new_ybn, key, ops, codepage)
    else:
        print_usage()


if __name__ == '__main__':
    main()
