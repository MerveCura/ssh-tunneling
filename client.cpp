#include "common.hpp"
#include <netinet/in.h>
#include <sys/socket.h>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstdlib>
#include <algorithm>

static constexpr const char* SERVER_IP = "127.0.0.1";
static constexpr int PORT = 5050;
static const std::string PRE_SHARED_KEY = "demo_key_123";

static std::vector<uint8_t> parse_hex(const std::string& hex){
  std::vector<uint8_t> out;
  if (hex.size() % 2 != 0) return out;

  auto hexval = [](char c)->int{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
  };

  out.reserve(hex.size()/2);
  for (size_t i = 0; i < hex.size(); i += 2){
    int a = hexval(hex[i]);
    int b = hexval(hex[i+1]);
    if (a < 0 || b < 0){ out.clear(); return out; }
    out.push_back((uint8_t)((a << 4) | b));
  }
  return out;
}

static bool has_env(const char* k){
  const char* v = std::getenv(k);
  return (v && std::strlen(v) > 0);
}

static double get_env_double(const char* k, double defv){
  const char* v = std::getenv(k);
  if (!v) return defv;
  return std::atof(v);
}

static uint32_t get_env_u32(const char* k, uint32_t defv){
  const char* v = std::getenv(k);
  if (!v) return defv;
  return (uint32_t)std::strtoul(v, nullptr, 10);
}

int main(int argc, char** argv){
  int cfd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (cfd < 0){ perror("socket"); return 1; }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  if (inet_pton(AF_INET, SERVER_IP, &addr.sin_addr) != 1){
    log_line("CLIENT", "bad ip");
    return 1;
  }
  if (connect(cfd, (sockaddr*)&addr, sizeof(addr)) < 0){
    perror("connect");
    return 1;
  }
  log_line("CLIENT", "connected to " + std::string(SERVER_IP) + ":" + std::to_string(PORT));

  // 1) Handshake HELLO(client_nonce [+ snr_x100 + seed])
  uint32_t client_nonce = (uint32_t)time(nullptr) ^ (uint32_t)getpid();

  std::vector<uint8_t> helloPayload;

  bool noise_on = has_env("NOISE_SNR_DB");
  if (noise_on){
    double snr = get_env_double("NOISE_SNR_DB", 0.0);
    uint32_t seed = get_env_u32("NOISE_SEED", 12345u);

    int32_t snr_x100 = (int32_t)std::lround(snr * 100.0);

    helloPayload.resize(12);
    std::memcpy(helloPayload.data() + 0, &client_nonce, 4);
    std::memcpy(helloPayload.data() + 4, &snr_x100, 4);
    std::memcpy(helloPayload.data() + 8, &seed, 4);

    log_line("CLIENT", "noise enabled: SNR(dB)=" + std::to_string(snr) + " seed=" + std::to_string(seed));
  } else {
    helloPayload.resize(4);
    std::memcpy(helloPayload.data(), &client_nonce, 4);
  }

  uint32_t helloCs = checksum_simple(helloPayload.data(), helloPayload.size());
  if (!send_frame_raw(cfd, FrameType::HELLO, ContentType::BIN, 1, helloPayload, helloCs)){
    log_line("CLIENT", "send HELLO failed");
    return 1;
  }

  FrameHeader h{};
  std::vector<uint8_t> payload;
  if (!recv_frame_raw(cfd, h, payload) ||
      (FrameType)h.type != FrameType::HELLO_ACK ||
      payload.size() != 4){
    log_line("CLIENT", "bad HELLO_ACK");
    return 1;
  }

  uint32_t server_nonce = 0;
  std::memcpy(&server_nonce, payload.data(), 4);
  log_line("HANDSHAKE", "server_nonce=" + std::to_string(server_nonce));

  auto session_key = derive_session_key(client_nonce, server_nonce, PRE_SHARED_KEY);
  log_line("HANDSHAKE", "session_key derived (len=" + std::to_string(session_key.size()) + ")");

  uint32_t seq = 10;

  // FILE MODE: ./client file <path>
  if (argc >= 3 && std::string(argv[1]) == "file"){
    std::string path = argv[2];
    std::ifstream f(path, std::ios::binary);
    if (!f){
      log_line("CLIENT", "cannot open file: " + path);
      return 1;
    }

    log_line("CLIENT", "sending file: " + path);

    std::vector<uint8_t> buf(4096);
    while (f){
      f.read(reinterpret_cast<char*>(buf.data()), buf.size());
      std::streamsize n = f.gcount();
      if (n <= 0) break;

      std::vector<uint8_t> plain(buf.begin(), buf.begin() + n);
      uint32_t cs = checksum_simple(plain.data(), plain.size());

      std::vector<uint8_t> enc = plain;
      xor_crypt_inplace(enc, session_key);

      // noise, encryption'dan SONRA uygulanır (kanal bozuyor gibi)
      apply_noise_inplace(enc, seq);

      if (!send_frame_raw(cfd, FrameType::DATA, ContentType::BIN, seq++, enc, cs)){
        log_line("CLIENT", "send DATA failed");
        break;
      }
    }

    send_frame_raw(cfd, FrameType::FIN, ContentType::BIN, seq++, {}, 0);
    log_line("CLIENT", "SENT FIN (file done)");

    ::shutdown(cfd, SHUT_RDWR);
    ::close(cfd);
    return 0;
  }

  // INTERACTIVE MODE
  log_line("CLIENT", "Type lines. Prefixes: text: / json: / binhex: . Ctrl+D to exit.");
  log_line("CLIENT", "Examples: text:hello | json:{\"a\":1} | binhex:48656c6c6f");

  std::string line;
  while (std::getline(std::cin, line)){
    ContentType ctype = ContentType::TEXT;
    std::vector<uint8_t> plain;

    if (line.rfind("json:", 0) == 0){
      ctype = ContentType::JSON;
      std::string s = line.substr(5);
      plain.assign(s.begin(), s.end());
    } else if (line.rfind("binhex:", 0) == 0){
      ctype = ContentType::BIN;
      std::string hx = line.substr(7);
      plain = parse_hex(hx);
      if (plain.empty()){
        log_line("CLIENT", "binhex parse failed");
        continue;
      }
    } else if (line.rfind("text:", 0) == 0){
      ctype = ContentType::TEXT;
      std::string s = line.substr(5);
      plain.assign(s.begin(), s.end());
    } else {
      ctype = ContentType::TEXT;
      plain.assign(line.begin(), line.end());
    }

    uint32_t cs = checksum_simple(plain.data(), plain.size());

    std::vector<uint8_t> enc = plain;
    xor_crypt_inplace(enc, session_key);

    apply_noise_inplace(enc, seq);

    if (!send_frame_raw(cfd, FrameType::DATA, ctype, seq++, enc, cs)){
      log_line("CLIENT", "send DATA failed");
      break;
    }
  }

  send_frame_raw(cfd, FrameType::FIN, ContentType::BIN, seq++, {}, 0);
  log_line("CLIENT", "SENT FIN");

  ::shutdown(cfd, SHUT_RDWR);
  ::close(cfd);
  return 0;
}
