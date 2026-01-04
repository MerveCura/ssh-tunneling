#include "common.hpp"
#include "ring_buffer.hpp"

#include <thread>
#include <atomic>
#include <fstream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <ctime>

static constexpr int PORT = 5050;
static constexpr size_t BUFFER_SIZE = 65536;
static const std::string PRE_SHARED_KEY = "demo_key_123"; // simülasyon için ortak sır

static void handle_client(int cfd, std::string tag){
  log_line("SERVER", "accept " + tag);

  // 1) Handshake: HELLO (client_nonce) -> HELLO_ACK (server_nonce)
  FrameHeader h{};
  std::vector<uint8_t> payload;

  if (!recv_frame_raw(cfd, h, payload) ||
      (FrameType)h.type != FrameType::HELLO ||
      payload.size() != 4) {
    log_line("SERVER", tag + " handshake: bad HELLO");
    ::close(cfd);
    return;
  }

  uint32_t client_nonce = 0;
  std::memcpy(&client_nonce, payload.data(), 4);
  log_line("HANDSHAKE", tag + " client_nonce=" + std::to_string(client_nonce));

  uint32_t server_nonce = (uint32_t)time(nullptr) ^ (uint32_t)getpid();
  std::vector<uint8_t> ackPayload(4);
  std::memcpy(ackPayload.data(), &server_nonce, 4);

  uint32_t ackCs = checksum_simple(ackPayload.data(), ackPayload.size());
  if (!send_frame_raw(cfd, FrameType::HELLO_ACK, ContentType::BIN, 1, ackPayload, ackCs)){
    log_line("SERVER", tag + " handshake: send HELLO_ACK failed");
    ::close(cfd);
    return;
  }

  auto session_key = derive_session_key(client_nonce, server_nonce, PRE_SHARED_KEY);
  log_line("HANDSHAKE", tag + " session_key derived (len=" + std::to_string(session_key.size()) + ")");

  // 2) FIFO Ring Buffer demo: TEXT/JSON ekrana yavaş basılsın (upload hızlı/consume yavaş)
  RingBuffer rb(BUFFER_SIZE);
  std::atomic<bool> running{true};

  std::thread consumer([&](){
    while (running.load()){
      uint8_t b = 0;
      rb.pop_bytes(&b, 1);
      std::cout << (char)b << std::flush;
      std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
  });

  // 3) File receive state (BIN -> dosyaya yaz)
  std::ofstream outFile;
  bool fileMode = false;
  std::string outName;

  // 4) Main recv loop
  while (true){
    FrameHeader fh{};
    std::vector<uint8_t> enc;

    if (!recv_frame_raw(cfd, fh, enc)){
      log_line("SERVER", tag + " closed or recv error");
      break;
    }

    FrameType t = (FrameType)fh.type;

    if (t == FrameType::FIN){
      log_line("SERVER", tag + " FIN seq=" + std::to_string(fh.seq));
      // Dosya modundaysak kapat
      if (fileMode && outFile.is_open()){
        outFile.close();
        log_line("SERVER", tag + " file saved -> " + outName);
      }
      break;
    }

    if (t != FrameType::DATA){
      log_line("SERVER", tag + " unexpected frame type=" + std::to_string((int)fh.type));
      continue;
    }

    // decrypt
    std::vector<uint8_t> plain = enc;
    xor_crypt_inplace(plain, session_key);

    // verify checksum over plaintext
    uint32_t cs = checksum_simple(plain.data(), plain.size());
    if (cs != fh.checksum){
      log_line("SERVER", tag + " CHECKSUM MISMATCH seq=" + std::to_string(fh.seq));
      continue;
    }

    ContentType ct = (ContentType)fh.content_type;

    log_line("SERVER",
      tag + " DATA seq=" + std::to_string(fh.seq) +
      " len=" + std::to_string(plain.size()) +
      " ctype=" + std::to_string((int)fh.content_type)
    );

    if (ct == ContentType::BIN){
      // İlk BIN paketi gelince dosyayı aç
      if (!fileMode){
        outName = "received_" + tag + ".bin";
        // ':' gibi karakterler dosya adında sorun çıkarabilir; sadeleştirelim
        for (char& ch : outName){
          if (ch == ':' || ch == '/') ch = '_';
        }

        outFile.open(outName, std::ios::binary);
        if (!outFile){
          log_line("SERVER", tag + " cannot open output file: " + outName);
          continue;
        }
        fileMode = true;
        log_line("SERVER", tag + " file receive started -> " + outName);
      }

      if (!plain.empty()){
        outFile.write(reinterpret_cast<const char*>(plain.data()), (std::streamsize)plain.size());
      }
    } else {
      // TEXT/JSON -> ring buffer'a yaz (ekrana yavaş basılacak)
      if (!plain.empty()){
        rb.push_bytes(plain.data(), plain.size());
        uint8_t nl = '\n';
        rb.push_bytes(&nl, 1);
      }
    }
  }

  running.store(false);
  ::shutdown(cfd, SHUT_RDWR);
  ::close(cfd);

  // consumer thread rb.pop'ta bekliyor olabilir; demo için detach
  consumer.detach();

  log_line("SERVER", "client end " + tag);
}

int main(){
  signal(SIGPIPE, SIG_IGN);

  int sfd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (sfd < 0){ perror("socket"); return 1; }

  int opt = 1;
  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(PORT);

  if (bind(sfd, (sockaddr*)&addr, sizeof(addr)) < 0){ perror("bind"); return 1; }
  if (listen(sfd, 16) < 0){ perror("listen"); return 1; }

  log_line("SERVER", "listening on :" + std::to_string(PORT));

  while (true){
    sockaddr_in caddr{};
    socklen_t clen = sizeof(caddr);
    int cfd = accept(sfd, (sockaddr*)&caddr, &clen);
    if (cfd < 0){ perror("accept"); continue; }

    char ipbuf[64];
    inet_ntop(AF_INET, &caddr.sin_addr, ipbuf, sizeof(ipbuf));
    std::string tag = std::string(ipbuf) + ":" + std::to_string(ntohs(caddr.sin_port));

    std::thread(handle_client, cfd, tag).detach();
  }

  ::close(sfd);
  return 0;
}
