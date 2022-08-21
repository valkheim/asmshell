from asmshell import config, utils


def read_memory_chunks(cmd: str, chunk_length: int) -> bytearray:
    """cmd is a user input formatted as follows:"""
    cmd = utils.clean_str(cmd)
    options = cmd.split()
    start = utils.parse_pointer(utils.seq_get(options, 1)) or 0
    amount = int(utils.parse_value(utils.seq_get(options, 2)) or 1)
    end = start + chunk_length * amount
    mem = config.config.mu.mem_read(start, end - start)
    utils.hexdump(mem, base=start)
    return mem


def write_memory_chunks(cmd: str) -> bytes:
    cmd = utils.clean_str(cmd)
    options = cmd.split()
    va = utils.parse_pointer(utils.seq_get(options, 1))
    data = utils.get_bytes_sequence(options[2:])
    config.config.mu.mem_write(va, data)
    return data
