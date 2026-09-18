# ตัวช่วยเทียบ IP กับรายการที่เป็นได้ทั้ง "IP เดี่ยว" และ "ช่วง subnet (CIDR)"
# ใช้ร่วมกันระหว่าง routes (ตรวจ/normalize ตอนเพิ่ม) กับ detector (เทียบตอนจะ block)
#
# คอลัมน์ ip_white_list.ip_address เป็น VARCHAR ไม่ใช่ inet ของ postgres จึงเทียบ subnet
# ด้วย SQL ตรง ๆ ไม่ได้ — ต้องสแกนฝั่ง python (whitelist มีไม่กี่สิบแถว ไม่คุ้มจะย้ายชนิดคอลัมน์)

import ipaddress


# วงที่ prefix สั้นกว่านี้กินข้าม /8 หลายก้อนรวมอินเทอร์เน็ตสาธารณะ — ไม่ใช่ "วงที่เชื่อถือได้"
# อีกต่อไป และ 0.0.0.0/0 คือทุก IP บนโลก ใส่ลง whitelist = ปิดการบล็อกทั้งระบบเงียบ ๆ
# (/8 ยังเพิ่มได้ เพราะ 10.0.0.0/8 เป็นวงส่วนตัวที่มีคนใช้ทั้งก้อนจริง)
MIN_WHITELIST_PREFIXLEN = 8


def parse_entry(value):
    # คืน ip_network ของรายการหนึ่งแถว — รับทั้ง "1.2.3.4" และ "192.168.1.0/24"
    # strict=False = ยอมให้ติด host bit มา (192.168.1.5/24 -> 192.168.1.0/24) ไม่ใช่ error
    if not value:
        return None

    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


def is_valid_entry(value) -> bool:
    return parse_entry(value) is not None


def is_subnet(value) -> bool:
    # True เฉพาะรายการที่ครอบมากกว่า 1 address — IP เดี่ยว (และ /32) คืน False
    net = parse_entry(value)
    return bool(net and net.num_addresses > 1)


def normalize_entry(value):
    # รูปที่จะเก็บลง DB:
    #   subnet   -> network address เสมอ (192.168.1.5/24 -> 192.168.1.0/24) กันเก็บซ้ำคนละหน้าตา
    #   IP เดี่ยว -> IP เปล่า ๆ ไม่เติม /32 เพื่อให้แถวเดิมกับหน้าเว็บอ่านเหมือนเดิมทุกอย่าง
    net = parse_entry(value)

    if net is None:
        return None

    if net.num_addresses == 1:
        return str(net.network_address)

    return str(net)


def entry_contains(entry, ip) -> bool:
    # ip อยู่ในรายการนี้ไหม (ตรงตัว หรืออยู่ในวง)
    net = parse_entry(entry)

    if net is None:
        return False

    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except (ValueError, TypeError):
        return False

    return addr in net


def is_too_broad(value) -> bool:
    # วงกว้างเกินกว่าจะถือเป็น whitelist ได้ — ให้ route ปฏิเสธไปพร้อมเหตุผล
    net = parse_entry(value)

    if net is None:
        return False

    return net.prefixlen < MIN_WHITELIST_PREFIXLEN


def entry_covers(outer, inner) -> bool:
    # outer ครอบ inner "ทั้งวง" ไหม — ใช้ได้ทั้งตอน inner เป็น IP เดี่ยวและเป็น subnet
    # (วงหนึ่งเป็น subnet ของตัวเองเสมอ ค่านี้จึงครอบเคส "ซ้ำตรงตัว" ไปในตัว)
    a = parse_entry(outer)
    b = parse_entry(inner)

    if a is None or b is None or a.version != b.version:
        return False

    return b.subnet_of(a)


def entry_host_count(value) -> int:
    # จำนวนเครื่องที่ใช้งานได้จริงในรายการนั้น — /24 = 254 (หัก network + broadcast)
    # /31 กับ /32 ไม่มี network/broadcast ให้หัก (RFC 3021) จึงคืน num_addresses ตรง ๆ
    net = parse_entry(value)

    if net is None:
        return 0

    if net.version == 4 and net.prefixlen <= 30:
        return net.num_addresses - 2

    return net.num_addresses


def describe_entry(value) -> str:
    # ข้อความสั้น ๆ ไว้ต่อท้ายข้อความตอบกลับ เช่น "192.168.1.0/24 (254 IP)"
    if not is_subnet(value):
        return str(value)

    return f"{value} ({entry_host_count(value)} IP)"
