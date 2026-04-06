#include <iostream>
#include <cstdint>
#include <cstddef>

namespace DataBeam {
    const int SR_SACK_BITMAP_CHUNKS = 64;
}

struct ACKPacket {
  uint32_t ack_num; 
  uint64_t bitmap[DataBeam::SR_SACK_BITMAP_CHUNKS]; 
  uint8_t type;                                     
  uint64_t connection_id; 
  uint32_t crc32; 
};

int main() {
    std::cout << "sizeof(ACKPacket): " << sizeof(ACKPacket) << std::endl;
    std::cout << "offsetof(ack_num): " << offsetof(ACKPacket, ack_num) << std::endl;
    std::cout << "offsetof(bitmap): " << offsetof(ACKPacket, bitmap) << std::endl;
    std::cout << "offsetof(type): " << offsetof(ACKPacket, type) << std::endl;
    std::cout << "offsetof(connection_id): " << offsetof(ACKPacket, connection_id) << std::endl;
    std::cout << "offsetof(crc32): " << offsetof(ACKPacket, crc32) << std::endl;
    return 0;
}
