from collections import defaultdict


class Deformatter:
    def __init__(self) -> None:
        self.trace_id: int = 0x0

    def deformat(self, trace_data: bytes) -> dict[int, bytearray]:
        packet_streams: dict[int, bytearray] = defaultdict(bytearray)

        # Iterate on 128-bit (16-byte) frames
        for data_idx in range(0, len(trace_data), 16):
            frame = trace_data[data_idx : data_idx + 16]
            if len(frame) < 16:
                break  # TODO: Exception incomplete frame

            # Last byte holds bits for all other bytes
            auxiliary_byte: int = frame[15]

            for byte_nb in range(0, 15, 2):
                byte: int = frame[byte_nb]
                auxiliary_bit: int = (auxiliary_byte >> (byte_nb // 2)) & 1

                # ID or Data (offsets 0, 2, 4, 6, 8, 10, 12, 14)
                # Last bit of the byte indicates 1 -> ID, 0 -> Data

                # ID packet
                if byte & 1:
                    new_trace_id: int = byte >> 1
                    # In case of an ID, 0 -> byte 1 is the new ID, 1 -> byte 1 is the old ID
                    if auxiliary_bit == 0:
                        self.trace_id = new_trace_id

                # Data packet
                else:
                    # The auxiliary bit is data[0]
                    packet_streams[self.trace_id].append(byte | auxiliary_bit)

                # Data (offsets 1, 3, 5, 7, 9, 11, 13)
                next_idx = byte_nb + 1
                if next_idx < 15:
                    packet_streams[self.trace_id].append(frame[next_idx])

                # New trace id takes effect now (if not already down with auxiliary bit 0 in previous byte)
                self.trace_id = new_trace_id

        return dict(packet_streams)
