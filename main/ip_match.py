


import ipaddress


MIN_WHITELIST_PREFIXLEN = 8


def parse_entry(value):


    if not value:
        return None

    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


def is_valid_entry(value) -> bool:
    return parse_entry(value) is not None


def is_subnet(value) -> bool:

    net = parse_entry(value)
    return bool(net and net.num_addresses > 1)


def normalize_entry(value):


    net = parse_entry(value)

    if net is None:
        return None

    if net.num_addresses == 1:
        return str(net.network_address)

    return str(net)


def entry_contains(entry, ip) -> bool:

    net = parse_entry(entry)

    if net is None:
        return False

    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except (ValueError, TypeError):
        return False

    return addr in net


def is_too_broad(value) -> bool:

    net = parse_entry(value)

    if net is None:
        return False

    return net.prefixlen < MIN_WHITELIST_PREFIXLEN


def entry_covers(outer, inner) -> bool:


    a = parse_entry(outer)
    b = parse_entry(inner)

    if a is None or b is None or a.version != b.version:
        return False

    return b.subnet_of(a)


def entry_host_count(value) -> int:


    net = parse_entry(value)

    if net is None:
        return 0

    if net.version == 4 and net.prefixlen <= 30:
        return net.num_addresses - 2

    return net.num_addresses


def describe_entry(value) -> str:

    if not is_subnet(value):
        return str(value)

    return f"{value} ({entry_host_count(value)} IP)"
