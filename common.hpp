#pragma once
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <cstdlib>
#include <cmath>
#include <algorithm>

static constexpr uint32_t MAGIC   = 0x53534854; // 'SSHT'
static constexpr uint16_t VERSION = 1;

static constexpr size_t MAX_PAYLOAD = 1024 * 1024; // 1MB

enum class FrameType : uint16_t {
  HELLO     = 1,
  HELLO_ACK = 2,
  DATA      = 3,
  ACK       = 4,
  FIN       = 5
};

enum class ContentType : uint16_t {
  TEXT = 1,
  JSON = 2,
  BIN  = 3
};

#pragma pack(push,1)
struct FrameHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint16_t content_type;
  uint16_t reserved;
  uint32_t seq;
  uint32_t payload_len;
  uint32_t checksum;
};
#pragma pack(pop)

inline void log_line(const std::string& tag, const std::string& msg){
  std::cerr << "[" << tag << "] " << msg << "\n";
}

inline uint32_t checksum_simple(const uint8_t* data, size_t n){
  uint32_t s = 0;
  for (size_t i = 0; i < n; i++) s = (s * 131u) + data[i];
  return s;
}

inline void header_to_network(FrameHeader& h){
  h.magic        = htonl(h.magic);
  h.version      = htons(h.version);
  h.type         = htons(h.type);
  h.content_type = htons(h.content_type);
  h.reserved     = htons(h.reserved);
  h.seq          = htonl(h.seq);
  h.payload_len  = htonl(h.payload_len);
  h.checksum     = htonl(h.checksum);
}
inline void header_to_host(FrameHeader& h){
  h.magic        = ntohl(h.magic);
  h.version      = ntohs(h.version);
  h.type         = ntohs(h.type);
  h.content_type = ntohs(h.content_type);
  h.reserved     = ntohs(h.reserved);
  h.seq          = ntohl(h.seq);
  h.payload_len  = ntohl(h.payload_len);
  h.checksum     = ntohl(h.checksum);
}

inline bool send_all(int fd, const uint8_t* buf, size_t n){
  size_t off = 0;
  while (off < n){
    ssize_t w = ::send(fd, buf + off, n - off, 0);
    if (w < 0){
      if (errno == EINTR) continue;
      return false;
    }
    if (w == 0) return false;
    off += (size_t)w;
  }
  return true;
}

inline bool recv_all(int fd, uint8_t* buf, size_t n){
  size_t off = 0;
  while (off < n){
    ssize_t r = ::recv(fd, buf + off, n - off, 0);
    if (r < 0){
      if (errno == EINTR) continue;
      return false;
    }
    if (r == 0) return false;
    off += (size_t)r;
  }
  return true;
}

inline void xor_crypt_inplace(std::vector<uint8_t>& data, const std::vector<uint8_t>& key){
  if (key.empty()) return;
  for (size_t i = 0; i < data.size(); i++){
    data[i] ^= key[i % key.size()];
  }
}

inline std::vector<uint8_t> derive_session_key(uint32_t client_nonce, uint32_t server_nonce, const std::string& psk){
  uint8_t mix[12];
  std::memcpy(mix + 0, &client_nonce, 4);
  std::memcpy(mix + 4, &server_nonce, 4);
  uint32_t p = checksum_simple(reinterpret_cast<const uint8_t*>(psk.data()), psk.size());
  std::memcpy(mix + 8, &p, 4);

  uint32_t seed = checksum_simple(mix, sizeof(mix));
  std::vector<uint8_t> key(32);
  for (size_t i = 0; i < key.size(); i++){
    seed = seed * 1664525u + 1013904223u;
    key[i] = (uint8_t)((seed >> 24) & 0xFF);
  }
  return key;
}

inline bool send_frame_raw(int fd, FrameType type, ContentType ctype, uint32_t seq,
                           const std::vector<uint8_t>& payload, uint32_t plaintext_checksum){
  if (payload.size() > MAX_PAYLOAD) return false;

  FrameHeader h{};
  h.magic = MAGIC;
  h.version = VERSION;
  h.type = (uint16_t)type;
  h.content_type = (uint16_t)ctype;
  h.reserved = 0;
  h.seq = seq;
  h.payload_len = (uint32_t)payload.size();
  h.checksum = plaintext_checksum;

  FrameHeader net = h;
  header_to_network(net);

  if (!send_all(fd, reinterpret_cast<const uint8_t*>(&net), sizeof(net))) return false;
  if (!payload.empty() && !send_all(fd, payload.data(), payload.size())) return false;
  return true;
}

inline bool recv_frame_raw(int fd, FrameHeader& out_h, std::vector<uint8_t>& out_payload){
  FrameHeader net{};
  if (!recv_all(fd, reinterpret_cast<uint8_t*>(&net), sizeof(net))) return false;

  FrameHeader h = net;
  header_to_host(h);

  if (h.magic != MAGIC || h.version != VERSION) return false;
  if (h.payload_len > MAX_PAYLOAD) return false;

  out_payload.assign(h.payload_len, 0);
  if (h.payload_len > 0){
    if (!recv_all(fd, out_payload.data(), out_payload.size())) return false;
  }

  out_h = h;
  return true;
}

inline std::string hex_preview(const std::vector<uint8_t>& v, size_t max_bytes = 32){
  static const char* hexd = "0123456789abcdef";
  std::string s;
  size_t n = std::min(v.size(), max_bytes);
  s.reserve(n * 3);
  for (size_t i = 0; i < n; i++){
    uint8_t b = v[i];
    s.push_back(hexd[(b >> 4) & 0xF]);
    s.push_back(hexd[b & 0xF]);
    if (i + 1 < n) s.push_back(' ');
  }
  if (v.size() > n) s += " ...";
  return s;
}

// ---------------- NOISE / SNR SIM ----------------
inline uint32_t lcg_next(uint32_t& st){
  st = st * 1664525u + 1013904223u;
  return st;
}

inline bool noise_enabled(){
  const char* e = std::getenv("NOISE_SNR_DB");
  return (e && std::strlen(e) > 0);
}

inline double snr_db(){
  const char* e = std::getenv("NOISE_SNR_DB");
  if (!e) return 0.0;
  return std::atof(e);
}

inline uint32_t noise_seed(){
  const char* e = std::getenv("NOISE_SEED");
  if (!e) return 12345u;
  return (uint32_t)std::strtoul(e, nullptr, 10);
}

/*
  Daha "kademeli" mapping:
  - 30 dB => ~1e-7
  - 20 dB => ~1e-6
  - 10 dB => ~1e-5
  - 0  dB => ~1e-4
  Bu sayede 10 dB'de %100 yerine daha makul FER görürsün.
*/
inline double snr_to_bitflip_prob(double db){
  double p = std::pow(10.0, -((db + 40.0) / 10.0));
  return std::clamp(p, 0.0, 0.01);
}

inline void apply_noise_inplace(std::vector<uint8_t>& data, uint32_t frame_seq){
  if (!noise_enabled()) return;
  if (data.empty()) return;

  double db = snr_db();
  double p_bit = snr_to_bitflip_prob(db);

  uint32_t st = noise_seed() ^ (frame_seq * 2654435761u);

  // byte seviyesine çevirelim ama daha yumuşak:
  // p_byte ≈ 1 - (1 - p_bit)^8 ≈ 8*p_bit (küçük p için)
  double p_byte = std::clamp(8.0 * p_bit, 0.0, 0.02);

  for (size_t i = 0; i < data.size(); i++){
    uint32_t r = lcg_next(st);
    double u = (double)(r & 0xFFFFFF) / (double)0x1000000;
    if (u < p_byte){
      // Tek bit flip yeterli (çok agresif olmasın)
      uint32_t r2 = lcg_next(st);
      uint8_t mask = (uint8_t)(1u << (r2 % 8));
      data[i] ^= mask;
    }
  }
}
